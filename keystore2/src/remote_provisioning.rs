// Copyright 2020, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! This is the implementation for the remote provisioning AIDL interface between
//! the network providers for remote provisioning and the system. This interface
//! allows the caller to prompt the Remote Provisioning HAL to generate keys and
//! CBOR blobs that can be ferried to a provisioning server that will return
//! certificate chains signed by some root authority and stored in a keystore SQLite
//! DB.

use std::collections::HashMap;

use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    Algorithm::Algorithm, AttestationKey::AttestationKey, Certificate::Certificate,
    DeviceInfo::DeviceInfo, IRemotelyProvisionedComponent::IRemotelyProvisionedComponent,
    KeyParameter::KeyParameter, KeyParameterValue::KeyParameterValue,
    MacedPublicKey::MacedPublicKey, ProtectedData::ProtectedData, SecurityLevel::SecurityLevel,
    Tag::Tag,
};
use android_security_remoteprovisioning::aidl::android::security::remoteprovisioning::{
    AttestationPoolStatus::AttestationPoolStatus, IRemoteProvisioning::BnRemoteProvisioning,
    IRemoteProvisioning::IRemoteProvisioning, ImplInfo::ImplInfo,
};
use android_security_remoteprovisioning::binder::{BinderFeatures, Strong};
use android_system_keystore2::aidl::android::system::keystore2::{
    Domain::Domain, KeyDescriptor::KeyDescriptor,
};
use anyhow::{Context, Result};
use keystore2_crypto::parse_subject_from_certificate;
use serde_cbor::Value;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::database::{CertificateChain, KeystoreDB, Uuid};
use crate::error::{self, map_or_log_err, map_rem_prov_error, Error};
use crate::globals::{get_keymint_device, get_remotely_provisioned_component, DB};
use crate::metrics_store::log_rkp_error_stats;
use crate::utils::watchdog as wd;
use android_security_metrics::aidl::android::security::metrics::RkpError::RkpError as MetricsRkpError;

/// Contains helper functions to check if remote provisioning is enabled on the system and, if so,
/// to assign and retrieve attestation keys and certificate chains.
#[derive(Default)]
pub struct RemProvState {
    security_level: SecurityLevel,
    km_uuid: Uuid,
    is_hal_present: AtomicBool,
}

static COSE_KEY_XCOORD: Value = Value::Integer(-2);
static COSE_KEY_YCOORD: Value = Value::Integer(-3);
static COSE_MAC0_LEN: usize = 4;
static COSE_MAC0_PAYLOAD: usize = 2;

impl RemProvState {
    /// Creates a RemProvState struct.
    pub fn new(security_level: SecurityLevel, km_uuid: Uuid) -> Self {
        Self { security_level, km_uuid, is_hal_present: AtomicBool::new(true) }
    }

    /// Checks if remote provisioning is enabled and partially caches the result. On a hybrid system
    /// remote provisioning can flip from being disabled to enabled depending on responses from the
    /// server, so unfortunately caching the presence or absence of the HAL is not enough to fully
    /// make decisions about the state of remote provisioning during runtime.
    fn check_rem_prov_enabled(&self, db: &mut KeystoreDB) -> Result<bool> {
        if !self.is_hal_present.load(Ordering::Relaxed)
            || get_remotely_provisioned_component(&self.security_level).is_err()
        {
            self.is_hal_present.store(false, Ordering::Relaxed);
            return Ok(false);
        }
        // To check if remote provisioning is enabled on a system that supports both remote
        // provisioning and factory provisioned keys, we only need to check if there are any
        // keys at all generated to indicate if the app has gotten the signal to begin filling
        // the key pool from the server.
        let pool_status = db
            .get_attestation_pool_status(0 /* date */, &self.km_uuid)
            .context("In check_rem_prov_enabled: failed to get attestation pool status.")?;
        Ok(pool_status.total != 0)
    }

    /// Fetches a remote provisioning attestation key and certificate chain inside of the
    /// returned `CertificateChain` struct if one exists for the given caller_uid. If one has not
    /// been assigned, this function will assign it. If there are no signed attestation keys
    /// available to be assigned, it will return the ResponseCode `OUT_OF_KEYS`
    fn get_rem_prov_attest_key(
        &self,
        key: &KeyDescriptor,
        caller_uid: u32,
        db: &mut KeystoreDB,
    ) -> Result<Option<CertificateChain>> {
        match key.domain {
            Domain::APP => {
                // Attempt to get an Attestation Key once. If it fails, then the app doesn't
                // have a valid chain assigned to it. The helper function will return None after
                // attempting to assign a key. An error will be thrown if the pool is simply out
                // of usable keys. Then another attempt to fetch the just-assigned key will be
                // made. If this fails too, something is very wrong.
                self.get_rem_prov_attest_key_helper(key, caller_uid, db)
                    .context("In get_rem_prov_attest_key: Failed to get a key")?
                    .map_or_else(
                        || self.get_rem_prov_attest_key_helper(key, caller_uid, db),
                        |v| Ok(Some(v)),
                    )
                    .context(concat!(
                        "In get_rem_prov_attest_key: Failed to get a key after",
                        "attempting to assign one."
                    ))?
                    .map_or_else(
                        || {
                            Err(Error::sys()).context(concat!(
                                "In get_rem_prov_attest_key: Attempted to assign a ",
                                "key and failed silently. Something is very wrong."
                            ))
                        },
                        |cert_chain| Ok(Some(cert_chain)),
                    )
            }
            _ => Ok(None),
        }
    }

    /// Returns None if an AttestationKey fails to be assigned. Errors if no keys are available.
    fn get_rem_prov_attest_key_helper(
        &self,
        key: &KeyDescriptor,
        caller_uid: u32,
        db: &mut KeystoreDB,
    ) -> Result<Option<CertificateChain>> {
        let cert_chain = db
            .retrieve_attestation_key_and_cert_chain(key.domain, caller_uid as i64, &self.km_uuid)
            .context("In get_rem_prov_attest_key_helper: Failed to retrieve a key + cert chain")?;
        match cert_chain {
            Some(cert_chain) => Ok(Some(cert_chain)),
            // Either this app needs to be assigned a key, or the pool is empty. An error will
            // be thrown if there is no key available to assign. This will indicate that the app
            // should be nudged to provision more keys so keystore can retry.
            None => {
                db.assign_attestation_key(key.domain, caller_uid as i64, &self.km_uuid)
                    .context("In get_rem_prov_attest_key_helper: Failed to assign a key")?;
                Ok(None)
            }
        }
    }

    fn is_asymmetric_key(&self, params: &[KeyParameter]) -> bool {
        params.iter().any(|kp| {
            matches!(
                kp,
                KeyParameter {
                    tag: Tag::ALGORITHM,
                    value: KeyParameterValue::Algorithm(Algorithm::RSA)
                } | KeyParameter {
                    tag: Tag::ALGORITHM,
                    value: KeyParameterValue::Algorithm(Algorithm::EC)
                }
            )
        })
    }

    /// Checks to see (1) if the key in question should be attested to based on the algorithm and
    /// (2) if remote provisioning is present and enabled on the system. If these conditions are
    /// met, it makes an attempt to fetch the attestation key assigned to the `caller_uid`.
    ///
    /// It returns the ResponseCode `OUT_OF_KEYS` if there is not one key currently assigned to the
    /// `caller_uid` and there are none available to assign.
    pub fn get_remotely_provisioned_attestation_key_and_certs(
        &self,
        key: &KeyDescriptor,
        caller_uid: u32,
        params: &[KeyParameter],
        db: &mut KeystoreDB,
    ) -> Result<Option<(AttestationKey, Certificate)>> {
        if !self.is_asymmetric_key(params) || !self.check_rem_prov_enabled(db)? {
            // There is no remote provisioning component for this security level on the
            // device. Return None so the underlying KM instance knows to use its
            // factory provisioned key instead. Alternatively, it's not an asymmetric key
            // and therefore will not be attested.
            Ok(None)
        } else {
            match self.get_rem_prov_attest_key(key, caller_uid, db) {
                Err(e) => {
                    log::error!(
                        concat!(
                            "In get_remote_provisioning_key_and_certs: Failed to get ",
                            "attestation key. {:?}"
                        ),
                        e
                    );
                    log_rkp_error_stats(MetricsRkpError::FALL_BACK_DURING_HYBRID);
                    Ok(None)
                }
                Ok(v) => match v {
                    Some(cert_chain) => Ok(Some((
                        AttestationKey {
                            keyBlob: cert_chain.private_key.to_vec(),
                            attestKeyParams: vec![],
                            issuerSubjectName: parse_subject_from_certificate(
                                &cert_chain.batch_cert,
                            )
                            .context(concat!(
                                "In get_remote_provisioning_key_and_certs: Failed to ",
                                "parse subject."
                            ))?,
                        },
                        Certificate { encodedCertificate: cert_chain.cert_chain },
                    ))),
                    None => Ok(None),
                },
            }
        }
    }
}
/// Implementation of the IRemoteProvisioning service.
#[derive(Default)]
pub struct RemoteProvisioningService {
    device_by_sec_level: HashMap<SecurityLevel, Strong<dyn IRemotelyProvisionedComponent>>,
    curve_by_sec_level: HashMap<SecurityLevel, i32>,
}

impl RemoteProvisioningService {
    fn get_dev_by_sec_level(
        &self,
        sec_level: &SecurityLevel,
    ) -> Result<Strong<dyn IRemotelyProvisionedComponent>> {
        if let Some(dev) = self.device_by_sec_level.get(sec_level) {
            Ok(dev.clone())
        } else {
            Err(error::Error::sys()).context(concat!(
                "In get_dev_by_sec_level: Remote instance for requested security level",
                " not found."
            ))
        }
    }

    /// Creates a new instance of the remote provisioning service
    pub fn new_native_binder() -> Result<Strong<dyn IRemoteProvisioning>> {
        let mut result: Self = Default::default();
        let dev = get_remotely_provisioned_component(&SecurityLevel::TRUSTED_ENVIRONMENT)
            .context("In new_native_binder: Failed to get TEE Remote Provisioner instance.")?;
        result.curve_by_sec_level.insert(
            SecurityLevel::TRUSTED_ENVIRONMENT,
            dev.getHardwareInfo()
                .context("In new_native_binder: Failed to get hardware info for the TEE.")?
                .supportedEekCurve,
        );
        result.device_by_sec_level.insert(SecurityLevel::TRUSTED_ENVIRONMENT, dev);
        if let Ok(dev) = get_remotely_provisioned_component(&SecurityLevel::STRONGBOX) {
            result.curve_by_sec_level.insert(
                SecurityLevel::STRONGBOX,
                dev.getHardwareInfo()
                    .context("In new_native_binder: Failed to get hardware info for StrongBox.")?
                    .supportedEekCurve,
            );
            result.device_by_sec_level.insert(SecurityLevel::STRONGBOX, dev);
        }
        Ok(BnRemoteProvisioning::new_binder(result, BinderFeatures::default()))
    }

    fn extract_payload_from_cose_mac(data: &[u8]) -> Result<Value> {
        let cose_mac0: Vec<Value> = serde_cbor::from_slice(data).context(
            "In extract_payload_from_cose_mac: COSE_Mac0 returned from IRPC cannot be parsed",
        )?;
        if cose_mac0.len() != COSE_MAC0_LEN {
            return Err(error::Error::sys()).context(format!(
                "In extract_payload_from_cose_mac: COSE_Mac0 has improper length. \
                    Expected: {}, Actual: {}",
                COSE_MAC0_LEN,
                cose_mac0.len(),
            ));
        }
        match &cose_mac0[COSE_MAC0_PAYLOAD] {
            Value::Bytes(key) => Ok(serde_cbor::from_slice(key)
                .context("In extract_payload_from_cose_mac: COSE_Mac0 payload is malformed.")?),
            _ => Err(error::Error::sys()).context(
                "In extract_payload_from_cose_mac: COSE_Mac0 payload is the wrong type.",
            )?,
        }
    }

    /// Generates a CBOR blob which will be assembled by the calling code into a larger
    /// CBOR blob intended for delivery to a provisioning serever. This blob will contain
    /// `num_csr` certificate signing requests for attestation keys generated in the TEE,
    /// along with a server provided `eek` and `challenge`. The endpoint encryption key will
    /// be used to encrypt the sensitive contents being transmitted to the server, and the
    /// challenge will ensure freshness. A `test_mode` flag will instruct the remote provisioning
    /// HAL if it is okay to accept EEKs that aren't signed by something that chains back to the
    /// baked in root of trust in the underlying IRemotelyProvisionedComponent instance.
    #[allow(clippy::too_many_arguments)]
    pub fn generate_csr(
        &self,
        test_mode: bool,
        num_csr: i32,
        eek: &[u8],
        challenge: &[u8],
        sec_level: SecurityLevel,
        protected_data: &mut ProtectedData,
        device_info: &mut DeviceInfo,
    ) -> Result<Vec<u8>> {
        let dev = self.get_dev_by_sec_level(&sec_level)?;
        let (_, _, uuid) = get_keymint_device(&sec_level)?;
        let keys_to_sign = DB.with::<_, Result<Vec<MacedPublicKey>>>(|db| {
            let mut db = db.borrow_mut();
            Ok(db
                .fetch_unsigned_attestation_keys(num_csr, &uuid)?
                .iter()
                .map(|key| MacedPublicKey { macedKey: key.to_vec() })
                .collect())
        })?;
        let mac = map_rem_prov_error(dev.generateCertificateRequest(
            test_mode,
            &keys_to_sign,
            eek,
            challenge,
            device_info,
            protected_data,
        ))
        .context("In generate_csr: Failed to generate csr")?;
        let mut mac_and_keys: Vec<Value> = vec![Value::from(mac)];
        for maced_public_key in keys_to_sign {
            mac_and_keys.push(
                Self::extract_payload_from_cose_mac(&maced_public_key.macedKey)
                    .context("In generate_csr: Failed to get the payload from the COSE_Mac0")?,
            )
        }
        let cbor_array: Value = Value::Array(mac_and_keys);
        serde_cbor::to_vec(&cbor_array)
            .context("In generate_csr: Failed to serialize the mac and keys array")
    }

    /// Provisions a certificate chain for a key whose CSR was included in generate_csr. The
    /// `public_key` is used to index into the SQL database in order to insert the `certs` blob
    /// which represents a PEM encoded X.509 certificate chain. The `expiration_date` is provided
    /// as a convenience from the caller to avoid having to parse the certificates semantically
    /// here.
    pub fn provision_cert_chain(
        &self,
        public_key: &[u8],
        batch_cert: &[u8],
        certs: &[u8],
        expiration_date: i64,
        sec_level: SecurityLevel,
    ) -> Result<()> {
        DB.with::<_, Result<()>>(|db| {
            let mut db = db.borrow_mut();
            let (_, _, uuid) = get_keymint_device(&sec_level)?;
            db.store_signed_attestation_certificate_chain(
                public_key,
                batch_cert,
                certs, /* DER encoded certificate chain */
                expiration_date,
                &uuid,
            )
        })
    }

    fn parse_cose_mac0_for_coords(data: &[u8]) -> Result<Vec<u8>> {
        let cose_mac0: Vec<Value> = serde_cbor::from_slice(data).context(
            "In parse_cose_mac0_for_coords: COSE_Mac0 returned from IRPC cannot be parsed",
        )?;
        if cose_mac0.len() != COSE_MAC0_LEN {
            return Err(error::Error::sys()).context(format!(
                "In parse_cose_mac0_for_coords: COSE_Mac0 has improper length. \
                    Expected: {}, Actual: {}",
                COSE_MAC0_LEN,
                cose_mac0.len(),
            ));
        }
        let cose_key: BTreeMap<Value, Value> = match &cose_mac0[COSE_MAC0_PAYLOAD] {
            Value::Bytes(key) => serde_cbor::from_slice(key)
                .context("In parse_cose_mac0_for_coords: COSE_Key is malformed.")?,
            _ => Err(error::Error::sys())
                .context("In parse_cose_mac0_for_coords: COSE_Mac0 payload is the wrong type.")?,
        };
        if !cose_key.contains_key(&COSE_KEY_XCOORD) || !cose_key.contains_key(&COSE_KEY_YCOORD) {
            return Err(error::Error::sys()).context(
                "In parse_cose_mac0_for_coords: \
                COSE_Key returned from IRPC is lacking required fields",
            );
        }
        let mut raw_key: Vec<u8> = vec![0; 64];
        match &cose_key[&COSE_KEY_XCOORD] {
            Value::Bytes(x_coord) if x_coord.len() == 32 => {
                raw_key[0..32].clone_from_slice(x_coord)
            }
            Value::Bytes(x_coord) => {
                return Err(error::Error::sys()).context(format!(
                "In parse_cose_mac0_for_coords: COSE_Key X-coordinate is not the right length. \
                Expected: 32; Actual: {}",
                    x_coord.len()
                ))
            }
            _ => {
                return Err(error::Error::sys())
                    .context("In parse_cose_mac0_for_coords: COSE_Key X-coordinate is not a bstr")
            }
        }
        match &cose_key[&COSE_KEY_YCOORD] {
            Value::Bytes(y_coord) if y_coord.len() == 32 => {
                raw_key[32..64].clone_from_slice(y_coord)
            }
            Value::Bytes(y_coord) => {
                return Err(error::Error::sys()).context(format!(
                "In parse_cose_mac0_for_coords: COSE_Key Y-coordinate is not the right length. \
                Expected: 32; Actual: {}",
                    y_coord.len()
                ))
            }
            _ => {
                return Err(error::Error::sys())
                    .context("In parse_cose_mac0_for_coords: COSE_Key Y-coordinate is not a bstr")
            }
        }
        Ok(raw_key)
    }

    /// Submits a request to the Remote Provisioner HAL to generate a signing key pair.
    /// `is_test_mode` indicates whether or not the returned public key should be marked as being
    /// for testing in order to differentiate them from private keys. If the call is successful,
    /// the key pair is then added to the database.
    pub fn generate_key_pair(&self, is_test_mode: bool, sec_level: SecurityLevel) -> Result<()> {
        let (_, _, uuid) = get_keymint_device(&sec_level)?;
        let dev = self.get_dev_by_sec_level(&sec_level)?;
        let mut maced_key = MacedPublicKey { macedKey: Vec::new() };
        let priv_key =
            map_rem_prov_error(dev.generateEcdsaP256KeyPair(is_test_mode, &mut maced_key))
                .context("In generate_key_pair: Failed to generated ECDSA keypair.")?;
        let raw_key = Self::parse_cose_mac0_for_coords(&maced_key.macedKey)
            .context("In generate_key_pair: Failed to parse raw key")?;
        DB.with::<_, Result<()>>(|db| {
            let mut db = db.borrow_mut();
            db.create_attestation_key_entry(&maced_key.macedKey, &raw_key, &priv_key, &uuid)
        })
    }

    /// Checks the security level of each available IRemotelyProvisionedComponent hal and returns
    /// all levels in an array to the caller.
    pub fn get_implementation_info(&self) -> Result<Vec<ImplInfo>> {
        Ok(self
            .curve_by_sec_level
            .iter()
            .map(|(sec_level, curve)| ImplInfo { secLevel: *sec_level, supportedCurve: *curve })
            .collect())
    }

    /// Deletes all attestation keys generated by the IRemotelyProvisionedComponent from the device,
    /// regardless of what state of the attestation key lifecycle they were in.
    pub fn delete_all_keys(&self) -> Result<i64> {
        DB.with::<_, Result<i64>>(|db| {
            let mut db = db.borrow_mut();
            db.delete_all_attestation_keys()
        })
    }
}

/// Populates the AttestationPoolStatus parcelable with information about how many
/// certs will be expiring by the date provided in `expired_by` along with how many
/// keys have not yet been assigned.
pub fn get_pool_status(expired_by: i64, sec_level: SecurityLevel) -> Result<AttestationPoolStatus> {
    let (_, _, uuid) = get_keymint_device(&sec_level)?;
    DB.with::<_, Result<AttestationPoolStatus>>(|db| {
        let mut db = db.borrow_mut();
        // delete_expired_attestation_keys is always safe to call, and will remove anything
        // older than the date at the time of calling. No work should be done on the
        // attestation keys unless the pool status is checked first, so this call should be
        // enough to routinely clean out expired keys.
        db.delete_expired_attestation_keys()?;
        db.get_attestation_pool_status(expired_by, &uuid)
    })
}

impl binder::Interface for RemoteProvisioningService {}

// Implementation of IRemoteProvisioning. See AIDL spec at
// :aidl/android/security/remoteprovisioning/IRemoteProvisioning.aidl
impl IRemoteProvisioning for RemoteProvisioningService {
    fn getPoolStatus(
        &self,
        expired_by: i64,
        sec_level: SecurityLevel,
    ) -> binder::public_api::Result<AttestationPoolStatus> {
        let _wp = wd::watch_millis("IRemoteProvisioning::getPoolStatus", 500);
        map_or_log_err(get_pool_status(expired_by, sec_level), Ok)
    }

    fn generateCsr(
        &self,
        test_mode: bool,
        num_csr: i32,
        eek: &[u8],
        challenge: &[u8],
        sec_level: SecurityLevel,
        protected_data: &mut ProtectedData,
        device_info: &mut DeviceInfo,
    ) -> binder::public_api::Result<Vec<u8>> {
        let _wp = wd::watch_millis("IRemoteProvisioning::generateCsr", 500);
        map_or_log_err(
            self.generate_csr(
                test_mode,
                num_csr,
                eek,
                challenge,
                sec_level,
                protected_data,
                device_info,
            ),
            Ok,
        )
    }

    fn provisionCertChain(
        &self,
        public_key: &[u8],
        batch_cert: &[u8],
        certs: &[u8],
        expiration_date: i64,
        sec_level: SecurityLevel,
    ) -> binder::public_api::Result<()> {
        let _wp = wd::watch_millis("IRemoteProvisioning::provisionCertChain", 500);
        map_or_log_err(
            self.provision_cert_chain(public_key, batch_cert, certs, expiration_date, sec_level),
            Ok,
        )
    }

    fn generateKeyPair(
        &self,
        is_test_mode: bool,
        sec_level: SecurityLevel,
    ) -> binder::public_api::Result<()> {
        let _wp = wd::watch_millis("IRemoteProvisioning::generateKeyPair", 500);
        map_or_log_err(self.generate_key_pair(is_test_mode, sec_level), Ok)
    }

    fn getImplementationInfo(&self) -> binder::public_api::Result<Vec<ImplInfo>> {
        let _wp = wd::watch_millis("IRemoteProvisioning::getSecurityLevels", 500);
        map_or_log_err(self.get_implementation_info(), Ok)
    }

    fn deleteAllKeys(&self) -> binder::public_api::Result<i64> {
        let _wp = wd::watch_millis("IRemoteProvisioning::deleteAllKeys", 500);
        map_or_log_err(self.delete_all_keys(), Ok)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_cbor::Value;
    use std::collections::BTreeMap;

    #[test]
    fn test_parse_cose_mac0_for_coords_raw_bytes() -> Result<()> {
        let cose_mac0: Vec<u8> = vec![
            0x84, 0x01, 0x02, 0x58, 0x4D, 0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58,
            0x20, 0x1A, 0xFB, 0xB2, 0xD9, 0x9D, 0xF6, 0x2D, 0xF0, 0xC3, 0xA8, 0xFC, 0x7E, 0xC9,
            0x21, 0x26, 0xED, 0xB5, 0x4A, 0x98, 0x9B, 0xF3, 0x0D, 0x91, 0x3F, 0xC6, 0x42, 0x5C,
            0x43, 0x22, 0xC8, 0xEE, 0x03, 0x22, 0x58, 0x20, 0x40, 0xB3, 0x9B, 0xFC, 0x47, 0x95,
            0x90, 0xA7, 0x5C, 0x5A, 0x16, 0x31, 0x34, 0xAF, 0x0C, 0x5B, 0xF2, 0xB2, 0xD8, 0x2A,
            0xA3, 0xB3, 0x1A, 0xB4, 0x4C, 0xA6, 0x3B, 0xE7, 0x22, 0xEC, 0x41, 0xDC, 0x03,
        ];
        let raw_key = RemoteProvisioningService::parse_cose_mac0_for_coords(&cose_mac0)?;
        assert_eq!(
            raw_key,
            vec![
                0x1A, 0xFB, 0xB2, 0xD9, 0x9D, 0xF6, 0x2D, 0xF0, 0xC3, 0xA8, 0xFC, 0x7E, 0xC9, 0x21,
                0x26, 0xED, 0xB5, 0x4A, 0x98, 0x9B, 0xF3, 0x0D, 0x91, 0x3F, 0xC6, 0x42, 0x5C, 0x43,
                0x22, 0xC8, 0xEE, 0x03, 0x40, 0xB3, 0x9B, 0xFC, 0x47, 0x95, 0x90, 0xA7, 0x5C, 0x5A,
                0x16, 0x31, 0x34, 0xAF, 0x0C, 0x5B, 0xF2, 0xB2, 0xD8, 0x2A, 0xA3, 0xB3, 0x1A, 0xB4,
                0x4C, 0xA6, 0x3B, 0xE7, 0x22, 0xEC, 0x41, 0xDC,
            ]
        );
        Ok(())
    }

    #[test]
    fn test_parse_cose_mac0_for_coords_constructed_mac() -> Result<()> {
        let x_coord: Vec<u8> = vec![0; 32];
        let y_coord: Vec<u8> = vec![1; 32];
        let mut expected_key: Vec<u8> = Vec::new();
        expected_key.extend(&x_coord);
        expected_key.extend(&y_coord);
        let key_map: BTreeMap<Value, Value> = BTreeMap::from([
            (Value::Integer(1), Value::Integer(2)),
            (Value::Integer(3), Value::Integer(-7)),
            (Value::Integer(-1), Value::Integer(1)),
            (Value::Integer(-2), Value::Bytes(x_coord)),
            (Value::Integer(-3), Value::Bytes(y_coord)),
        ]);
        let cose_mac0: Vec<Value> = vec![
            Value::Integer(0),
            Value::Integer(1),
            Value::from(serde_cbor::to_vec(&key_map)?),
            Value::Integer(2),
        ];
        let raw_key = RemoteProvisioningService::parse_cose_mac0_for_coords(&serde_cbor::to_vec(
            &Value::from(cose_mac0),
        )?)?;
        assert_eq!(expected_key, raw_key);
        Ok(())
    }

    #[test]
    fn test_extract_payload_from_cose_mac() -> Result<()> {
        let key_map = Value::Map(BTreeMap::from([(Value::Integer(1), Value::Integer(2))]));
        let payload = Value::Bytes(serde_cbor::to_vec(&key_map)?);
        let cose_mac0 =
            Value::Array(vec![Value::Integer(0), Value::Integer(1), payload, Value::Integer(3)]);
        let extracted_map = RemoteProvisioningService::extract_payload_from_cose_mac(
            &serde_cbor::to_vec(&cose_mac0)?,
        )?;
        assert_eq!(key_map, extracted_map);
        Ok(())
    }

    #[test]
    fn test_extract_payload_from_cose_mac_fails_malformed_payload() -> Result<()> {
        let payload = Value::Bytes(vec![5; 10]);
        let cose_mac0 =
            Value::Array(vec![Value::Integer(0), Value::Integer(1), payload, Value::Integer(3)]);
        let extracted_payload = RemoteProvisioningService::extract_payload_from_cose_mac(
            &serde_cbor::to_vec(&cose_mac0)?,
        );
        assert!(extracted_payload.is_err());
        Ok(())
    }

    #[test]
    fn test_extract_payload_from_cose_mac_fails_type() -> Result<()> {
        let payload = Value::Integer(1);
        let cose_mac0 =
            Value::Array(vec![Value::Integer(0), Value::Integer(1), payload, Value::Integer(3)]);
        let extracted_payload = RemoteProvisioningService::extract_payload_from_cose_mac(
            &serde_cbor::to_vec(&cose_mac0)?,
        );
        assert!(extracted_payload.is_err());
        Ok(())
    }

    #[test]
    fn test_extract_payload_from_cose_mac_fails_length() -> Result<()> {
        let cose_mac0 = Value::Array(vec![Value::Integer(0), Value::Integer(1)]);
        let extracted_payload = RemoteProvisioningService::extract_payload_from_cose_mac(
            &serde_cbor::to_vec(&cose_mac0)?,
        );
        assert!(extracted_payload.is_err());
        Ok(())
    }
}
