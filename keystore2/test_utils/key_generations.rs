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
    Algorithm::Algorithm, Digest::Digest, EcCurve::EcCurve, ErrorCode::ErrorCode,
    KeyPurpose::KeyPurpose,
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
pub fn generate_ec_key<S: IKeystoreSecurityLevel + ?Sized>(
    sec_level: &S,
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
