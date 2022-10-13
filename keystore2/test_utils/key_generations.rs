// Copyright 2022, The Android Open Source Project
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

//! This module implements test utils to generate various types of keys.

use anyhow::Result;

use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    Algorithm::Algorithm, BlockMode::BlockMode, Digest::Digest, EcCurve::EcCurve,
    ErrorCode::ErrorCode, KeyPurpose::KeyPurpose, PaddingMode::PaddingMode,
};
use android_system_keystore2::aidl::android::system::keystore2::{
    Domain::Domain, IKeystoreSecurityLevel::IKeystoreSecurityLevel, KeyDescriptor::KeyDescriptor,
    KeyMetadata::KeyMetadata, ResponseCode::ResponseCode,
};

use crate::authorizations::AuthSetBuilder;
use android_system_keystore2::binder::{ExceptionCode, Result as BinderResult};

/// Shell namespace.
pub const SELINUX_SHELL_NAMESPACE: i64 = 1;
/// Vold namespace.
pub const SELINUX_VOLD_NAMESPACE: i64 = 100;

/// SU context.
pub const TARGET_SU_CTX: &str = "u:r:su:s0";

/// Vold context
pub const TARGET_VOLD_CTX: &str = "u:r:vold:s0";

/// Key parameters to generate a key.
pub struct KeyParams {
    /// Key Size.
    pub key_size: i32,
    /// Key Purposes.
    pub purpose: Vec<KeyPurpose>,
    /// Padding Mode.
    pub padding: Option<PaddingMode>,
    /// Digest.
    pub digest: Option<Digest>,
    /// MFG Digest.
    pub mgf_digest: Option<Digest>,
    /// Block Mode.
    pub block_mode: Option<BlockMode>,
    /// Attestation challenge.
    pub att_challenge: Option<Vec<u8>>,
    /// Attestation app id.
    pub att_app_id: Option<Vec<u8>>,
}

/// To map Keystore errors.
#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub enum Error {
    /// Keystore2 error code
    #[error("ResponseCode {0:?}")]
    Rc(ResponseCode),
    /// Keymint error code
    #[error("ErrorCode {0:?}")]
    Km(ErrorCode),
    /// Exception
    #[error("Binder exception {0:?}")]
    Binder(ExceptionCode),
}

/// Keystore2 error mapping.
pub fn map_ks_error<T>(r: BinderResult<T>) -> Result<T, Error> {
    r.map_err(|s| {
        match s.exception_code() {
            ExceptionCode::SERVICE_SPECIFIC => {
                match s.service_specific_error() {
                    se if se < 0 => {
                        // Negative service specific errors are KM error codes.
                        Error::Km(ErrorCode(se))
                    }
                    se => {
                        // Positive service specific errors are KS response codes.
                        Error::Rc(ResponseCode(se))
                    }
                }
            }
            // We create `Error::Binder` to preserve the exception code
            // for logging.
            e_code => Error::Binder(e_code),
        }
    })
}

/// Generate EC Key using given security level and domain with below key parameters and
/// optionally allow the generated key to be attested with factory provisioned attest key using
/// given challenge and application id -
///     Purposes: SIGN and VERIFY
///     Digest: SHA_2_256
///     Curve: P_256
pub fn generate_ec_p256_signing_key(
    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
    domain: Domain,
    nspace: i64,
    alias: Option<String>,
    att_challenge: Option<&[u8]>,
    att_app_id: Option<&[u8]>,
) -> binder::Result<KeyMetadata> {
    let mut key_attest = false;
    let mut gen_params = AuthSetBuilder::new()
        .no_auth_required()
        .algorithm(Algorithm::EC)
        .purpose(KeyPurpose::SIGN)
        .purpose(KeyPurpose::VERIFY)
        .digest(Digest::SHA_2_256)
        .ec_curve(EcCurve::P_256);

    if let Some(challenge) = att_challenge {
        key_attest = true;
        gen_params = gen_params.clone().attestation_challenge(challenge.to_vec());
    }

    if let Some(app_id) = att_app_id {
        key_attest = true;
        gen_params = gen_params.clone().attestation_app_id(app_id.to_vec());
    }

    match sec_level.generateKey(
        &KeyDescriptor { domain, nspace, alias, blob: None },
        None,
        &gen_params,
        0,
        b"entropy",
    ) {
        Ok(key_metadata) => {
            assert!(key_metadata.certificate.is_some());
            if key_attest {
                assert!(key_metadata.certificateChain.is_some());
            }
            if domain == Domain::BLOB {
                assert!(key_metadata.key.blob.is_some());
            }

            Ok(key_metadata)
        }
        Err(e) => Err(e),
    }
}

/// Generate EC signing key.
pub fn generate_ec_key(
    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
    domain: Domain,
    nspace: i64,
    alias: Option<String>,
    ec_curve: EcCurve,
    digest: Digest,
) -> binder::Result<KeyMetadata> {
    let gen_params = AuthSetBuilder::new()
        .no_auth_required()
        .algorithm(Algorithm::EC)
        .purpose(KeyPurpose::SIGN)
        .purpose(KeyPurpose::VERIFY)
        .digest(digest)
        .ec_curve(ec_curve);

    let key_metadata = sec_level.generateKey(
        &KeyDescriptor { domain, nspace, alias, blob: None },
        None,
        &gen_params,
        0,
        b"entropy",
    )?;

    // Must have a public key.
    assert!(key_metadata.certificate.is_some());

    // Should not have an attestation record.
    assert!(key_metadata.certificateChain.is_none());

    if domain == Domain::BLOB {
        assert!(key_metadata.key.blob.is_some());
    } else {
        assert!(key_metadata.key.blob.is_none());
    }
    Ok(key_metadata)
}

/// Generate a RSA key with the given key parameters, alias, domain and namespace.
pub fn generate_rsa_key(
    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
    domain: Domain,
    nspace: i64,
    alias: Option<String>,
    key_params: &KeyParams,
    attest_key: Option<&KeyDescriptor>,
) -> binder::Result<KeyMetadata> {
    let mut gen_params = AuthSetBuilder::new()
        .no_auth_required()
        .algorithm(Algorithm::RSA)
        .rsa_public_exponent(65537)
        .key_size(key_params.key_size);

    for purpose in &key_params.purpose {
        gen_params = gen_params.purpose(*purpose);
    }
    if let Some(value) = key_params.digest {
        gen_params = gen_params.digest(value)
    }
    if let Some(value) = key_params.padding {
        gen_params = gen_params.padding_mode(value);
    }
    if let Some(value) = key_params.mgf_digest {
        gen_params = gen_params.mgf_digest(value);
    }
    if let Some(value) = key_params.block_mode {
        gen_params = gen_params.block_mode(value)
    }
    if let Some(value) = &key_params.att_challenge {
        gen_params = gen_params.attestation_challenge(value.to_vec())
    }
    if let Some(value) = &key_params.att_app_id {
        gen_params = gen_params.attestation_app_id(value.to_vec())
    }

    let key_metadata = sec_level.generateKey(
        &KeyDescriptor { domain, nspace, alias, blob: None },
        attest_key,
        &gen_params,
        0,
        b"entropy",
    )?;

    // Must have a public key.
    assert!(key_metadata.certificate.is_some());

    if attest_key.is_none() && key_params.att_challenge.is_some() && key_params.att_app_id.is_some()
    {
        // Should have an attestation record.
        assert!(key_metadata.certificateChain.is_some());
    } else {
        // Should not have an attestation record.
        assert!(key_metadata.certificateChain.is_none());
    }

    assert!(
        (domain == Domain::BLOB && key_metadata.key.blob.is_some())
            || key_metadata.key.blob.is_none()
    );

    Ok(key_metadata)
}

/// Generate AES/3DES key.
pub fn generate_sym_key(
    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
    algorithm: Algorithm,
    size: i32,
    alias: &str,
    padding_mode: &PaddingMode,
    block_mode: &BlockMode,
    min_mac_len: Option<i32>,
) -> binder::Result<KeyMetadata> {
    let mut gen_params = AuthSetBuilder::new()
        .no_auth_required()
        .algorithm(algorithm)
        .purpose(KeyPurpose::ENCRYPT)
        .purpose(KeyPurpose::DECRYPT)
        .key_size(size)
        .padding_mode(*padding_mode)
        .block_mode(*block_mode);

    if let Some(val) = min_mac_len {
        gen_params = gen_params.min_mac_length(val);
    }

    let key_metadata = sec_level.generateKey(
        &KeyDescriptor {
            domain: Domain::APP,
            nspace: -1,
            alias: Some(alias.to_string()),
            blob: None,
        },
        None,
        &gen_params,
        0,
        b"entropy",
    )?;

    // Should not have public certificate.
    assert!(key_metadata.certificate.is_none());

    // Should not have an attestation record.
    assert!(key_metadata.certificateChain.is_none());
    Ok(key_metadata)
}

/// Generate HMAC key.
pub fn generate_hmac_key(
    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
    alias: &str,
    key_size: i32,
    min_mac_len: i32,
    digest: Digest,
) -> binder::Result<KeyMetadata> {
    let gen_params = AuthSetBuilder::new()
        .no_auth_required()
        .algorithm(Algorithm::HMAC)
        .purpose(KeyPurpose::SIGN)
        .purpose(KeyPurpose::VERIFY)
        .key_size(key_size)
        .min_mac_length(min_mac_len)
        .digest(digest);

    let key_metadata = sec_level.generateKey(
        &KeyDescriptor {
            domain: Domain::APP,
            nspace: -1,
            alias: Some(alias.to_string()),
            blob: None,
        },
        None,
        &gen_params,
        0,
        b"entropy",
    )?;

    // Should not have public certificate.
    assert!(key_metadata.certificate.is_none());

    // Should not have an attestation record.
    assert!(key_metadata.certificateChain.is_none());

    Ok(key_metadata)
}
