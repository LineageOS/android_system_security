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

use nix::unistd::getuid;

use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    BlockMode::BlockMode, Digest::Digest, ErrorCode::ErrorCode, KeyPurpose::KeyPurpose,
    PaddingMode::PaddingMode, SecurityLevel::SecurityLevel,
};
use android_system_keystore2::aidl::android::system::keystore2::{
    CreateOperationResponse::CreateOperationResponse, Domain::Domain,
    IKeystoreSecurityLevel::IKeystoreSecurityLevel,
};

use keystore2_test_utils::{
    authorizations, get_keystore_service, key_generations, key_generations::Error,
};

use crate::keystore2_client_test_utils::{perform_sample_sign_operation, ForcedOp};

/// Generate a RSA key and create an operation using the generated key.
fn create_rsa_key_and_operation(
    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
    domain: Domain,
    nspace: i64,
    alias: Option<String>,
    key_params: &key_generations::KeyParams,
    op_purpose: KeyPurpose,
    forced_op: ForcedOp,
) -> binder::Result<CreateOperationResponse> {
    let key_metadata =
        key_generations::generate_rsa_key(sec_level, domain, nspace, alias, key_params, None)?;

    let mut op_params = authorizations::AuthSetBuilder::new().purpose(op_purpose);

    if let Some(value) = key_params.digest {
        op_params = op_params.digest(value)
    }
    if let Some(value) = key_params.padding {
        op_params = op_params.padding_mode(value);
    }
    if let Some(value) = key_params.mgf_digest {
        op_params = op_params.mgf_digest(value);
    }
    if let Some(value) = key_params.block_mode {
        op_params = op_params.block_mode(value)
    }

    sec_level.createOperation(&key_metadata.key, &op_params, forced_op.0)
}

/// Generate RSA signing keys with -
///     Padding mode: RSA_PKCS1_1_5_SIGN
///     Digest modes: `NONE, MD5, SHA1, SHA-2 224, SHA-2 256, SHA-2 384 and SHA-2 512`
/// Create operations with these generated keys. Test should create operations successfully.
#[test]
fn keystore2_rsa_generate_signing_key_padding_pkcs1_1_5() {
    let keystore2 = get_keystore_service();
    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();

    let digests = [
        Digest::NONE,
        Digest::MD5,
        Digest::SHA1,
        Digest::SHA_2_224,
        Digest::SHA_2_256,
        Digest::SHA_2_384,
        Digest::SHA_2_512,
    ];

    let key_sizes = [2048, 3072, 4096];

    for key_size in key_sizes {
        for digest in digests {
            let alias = format!("ks_rsa_key_test_{}{}{}", getuid(), key_size, digest.0);
            let op_response = create_rsa_key_and_operation(
                &sec_level,
                Domain::APP,
                -1,
                Some(alias.to_string()),
                &key_generations::KeyParams {
                    key_size,
                    purpose: vec![KeyPurpose::SIGN, KeyPurpose::VERIFY],
                    padding: Some(PaddingMode::RSA_PKCS1_1_5_SIGN),
                    digest: Some(digest),
                    mgf_digest: None,
                    block_mode: None,
                    att_challenge: None,
                    att_app_id: None,
                },
                KeyPurpose::SIGN,
                ForcedOp(false),
            )
            .unwrap();

            assert!(op_response.iOperation.is_some());
            assert_eq!(
                Ok(()),
                key_generations::map_ks_error(perform_sample_sign_operation(
                    &op_response.iOperation.unwrap()
                ))
            );
        } // End of digests.
    } // End of key-sizes.
}

/// Generate RSA signing keys with -
///     Padding mode: RSA_PSS
///     Digest modes: `MD5, SHA1, SHA-2 224, SHA-2 256, SHA-2 384 and SHA-2 512`
/// Create operations with these generated keys. Test should create operations successfully.
#[test]
fn keystore2_rsa_generate_signing_key_padding_pss_success() {
    let keystore2 = get_keystore_service();
    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();

    let digests = [
        Digest::MD5,
        Digest::SHA1,
        Digest::SHA_2_224,
        Digest::SHA_2_256,
        Digest::SHA_2_384,
        Digest::SHA_2_512,
    ];

    let key_sizes = [2048, 3072, 4096];

    for key_size in key_sizes {
        for digest in digests {
            let alias = format!("ks_rsa_key_test_{}{}{}", getuid(), key_size, digest.0);
            let op_response = create_rsa_key_and_operation(
                &sec_level,
                Domain::APP,
                -1,
                Some(alias.to_string()),
                &key_generations::KeyParams {
                    key_size,
                    purpose: vec![KeyPurpose::SIGN, KeyPurpose::VERIFY],
                    padding: Some(PaddingMode::RSA_PSS),
                    digest: Some(digest),
                    mgf_digest: None,
                    block_mode: None,
                    att_challenge: None,
                    att_app_id: None,
                },
                KeyPurpose::SIGN,
                ForcedOp(false),
            )
            .unwrap();

            assert!(op_response.iOperation.is_some());
            assert_eq!(
                Ok(()),
                key_generations::map_ks_error(perform_sample_sign_operation(
                    &op_response.iOperation.unwrap()
                ))
            );
        } // End of digests.
    } // End of key-sizes.
}

/// Generate RSA signing key with -
///     Padding mode: RSA_PSS
///     Digest mode: `NONE`.
/// Try to create an operation with this generated key. Test should fail to create an operation with
/// `INCOMPATIBLE_DIGEST` error code.
#[test]
fn keystore2_rsa_generate_signing_key_padding_pss_fail() {
    let keystore2 = get_keystore_service();
    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();

    let key_sizes = [2048, 3072, 4096];

    for key_size in key_sizes {
        let alias = format!("ks_rsa_pss_none_key_test_{}{}", getuid(), key_size);
        let result = key_generations::map_ks_error(create_rsa_key_and_operation(
            &sec_level,
            Domain::APP,
            -1,
            Some(alias.to_string()),
            &key_generations::KeyParams {
                key_size,
                purpose: vec![KeyPurpose::SIGN, KeyPurpose::VERIFY],
                padding: Some(PaddingMode::RSA_PSS),
                digest: Some(Digest::NONE),
                mgf_digest: None,
                block_mode: None,
                att_challenge: None,
                att_app_id: None,
            },
            KeyPurpose::SIGN,
            ForcedOp(false),
        ));
        assert!(result.is_err());
        assert_eq!(Error::Km(ErrorCode::INCOMPATIBLE_DIGEST), result.unwrap_err());
    }
}

/// Generate RSA signing key with -
///     Padding mode: `NONE`
///     Digest mode `NONE`
/// Try to create an operation with this generated key. Test should create an operation successfully.
#[test]
fn keystore2_rsa_generate_signing_key_padding_none_success() {
    let keystore2 = get_keystore_service();
    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();

    let key_sizes = [2048, 3072, 4096];

    for key_size in key_sizes {
        let alias = format!("ks_rsa_pad_none_key_test_{}{}", getuid(), key_size);
        let op_response = create_rsa_key_and_operation(
            &sec_level,
            Domain::APP,
            -1,
            Some(alias.to_string()),
            &key_generations::KeyParams {
                key_size,
                purpose: vec![KeyPurpose::SIGN, KeyPurpose::VERIFY],
                padding: Some(PaddingMode::NONE),
                digest: Some(Digest::NONE),
                mgf_digest: None,
                block_mode: None,
                att_challenge: None,
                att_app_id: None,
            },
            KeyPurpose::SIGN,
            ForcedOp(false),
        )
        .unwrap();

        assert!(op_response.iOperation.is_some());
        assert_eq!(
            Ok(()),
            key_generations::map_ks_error(perform_sample_sign_operation(
                &op_response.iOperation.unwrap()
            ))
        );
    }
}

/// Generate RSA signing keys with -
///     Padding mode: `NONE`
///     Digest modes: `MD5, SHA1, SHA-2 224, SHA-2 256, SHA-2 384 and SHA-2 512`
/// Create operations with these generated keys. Test should fail to create operations with
/// an error code `UNKNOWN_ERROR`.
#[test]
fn keystore2_rsa_generate_signing_key_padding_none_fail() {
    let keystore2 = get_keystore_service();
    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();

    let digests = [
        Digest::MD5,
        Digest::SHA1,
        Digest::SHA_2_224,
        Digest::SHA_2_256,
        Digest::SHA_2_384,
        Digest::SHA_2_512,
    ];

    let key_sizes = [2048, 3072, 4096];

    for key_size in key_sizes {
        for digest in digests {
            let alias = format!("ks_rsa_key_test_{}{}{}", getuid(), key_size, digest.0);
            let result = key_generations::map_ks_error(create_rsa_key_and_operation(
                &sec_level,
                Domain::APP,
                -1,
                Some(alias.to_string()),
                &key_generations::KeyParams {
                    key_size,
                    purpose: vec![KeyPurpose::SIGN, KeyPurpose::VERIFY],
                    padding: Some(PaddingMode::NONE),
                    digest: Some(digest),
                    mgf_digest: None,
                    block_mode: None,
                    att_challenge: None,
                    att_app_id: None,
                },
                KeyPurpose::SIGN,
                ForcedOp(false),
            ));
            assert!(result.is_err());
            assert_eq!(Error::Km(ErrorCode::UNKNOWN_ERROR), result.unwrap_err());
        }
    }
}

/// Generate RSA keys with -
///     Padding Mode: `RSA_OAEP`
///     Digest modes: `MD5, SHA1, SHA-2 224, SHA-2 256, SHA-2 384 and SHA-2 512`
///     mgf-digests: `MD5, SHA1, SHA-2 224, SHA-2 256, SHA-2 384 and SHA-2 512`
/// Create a decrypt operations using generated keys. Test should create operations successfully.
#[test]
fn keystore2_rsa_generate_key_with_oaep_padding_success() {
    let keystore2 = get_keystore_service();
    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();

    let digests = [
        Digest::MD5,
        Digest::SHA1,
        Digest::SHA_2_224,
        Digest::SHA_2_256,
        Digest::SHA_2_384,
        Digest::SHA_2_512,
    ];

    let mgf_digests = [
        Digest::MD5,
        Digest::SHA1,
        Digest::SHA_2_224,
        Digest::SHA_2_256,
        Digest::SHA_2_384,
        Digest::SHA_2_512,
    ];

    let key_sizes = [2048, 3072, 4096];

    for key_size in key_sizes {
        for digest in digests {
            for mgf_digest in mgf_digests {
                let alias =
                    format!("ks_rsa_key_pair_oaep_test_{}{}{}", getuid(), key_size, digest.0);
                let result = create_rsa_key_and_operation(
                    &sec_level,
                    Domain::APP,
                    -1,
                    Some(alias.to_string()),
                    &key_generations::KeyParams {
                        key_size,
                        purpose: vec![KeyPurpose::ENCRYPT, KeyPurpose::DECRYPT],
                        padding: Some(PaddingMode::RSA_OAEP),
                        digest: Some(digest),
                        mgf_digest: Some(mgf_digest),
                        block_mode: Some(BlockMode::ECB),
                        att_challenge: None,
                        att_app_id: None,
                    },
                    KeyPurpose::DECRYPT,
                    ForcedOp(false),
                );
                assert!(result.is_ok());
            } // End of mgf-digests.
        } // End of digests.
    } // End of key-sizes.
}

/// Generate RSA keys with -
///     Padding mode: `RSA_OAEP`
///     Digest modes: `MD5, SHA1, SHA-2 224, SHA-2 256, SHA-2 384 and SHA-2 512`
/// Create a decrypt operations using generated keys. Test should create operations successfully.
#[test]
fn keystore2_rsa_generate_key_with_oaep_padding_and_digests_success() {
    let keystore2 = get_keystore_service();
    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();

    let digests = [
        Digest::MD5,
        Digest::SHA1,
        Digest::SHA_2_224,
        Digest::SHA_2_256,
        Digest::SHA_2_384,
        Digest::SHA_2_512,
    ];

    let key_sizes = [2048, 3072, 4096];

    for key_size in key_sizes {
        for digest in digests {
            let alias = format!("ks_rsa_key_pair_oaep_test_{}{}{}", getuid(), key_size, digest.0);
            let result = create_rsa_key_and_operation(
                &sec_level,
                Domain::APP,
                -1,
                Some(alias.to_string()),
                &key_generations::KeyParams {
                    key_size,
                    purpose: vec![KeyPurpose::ENCRYPT, KeyPurpose::DECRYPT],
                    padding: Some(PaddingMode::RSA_OAEP),
                    digest: Some(digest),
                    mgf_digest: None,
                    block_mode: Some(BlockMode::ECB),
                    att_challenge: None,
                    att_app_id: None,
                },
                KeyPurpose::DECRYPT,
                ForcedOp(false),
            );
            assert!(result.is_ok());
        } // End of digests.
    } // End of key-sizes.
}

/// Generate RSA encryption key with -
///     Digest mode: `NONE`
///     Padding mode: `RSA_OAEP`
/// Try to create an operation using generated key. Test should fail to create an operation
/// with an error code `INCOMPATIBLE_DIGEST`.
#[test]
fn keystore2_rsa_generate_key_with_oaep_padding_fail() {
    let keystore2 = get_keystore_service();
    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();

    let key_sizes = [2048, 3072, 4096];

    for key_size in key_sizes {
        let alias = format!("ks_rsa_key_padding_{}{}", getuid(), key_size);
        let result = key_generations::map_ks_error(create_rsa_key_and_operation(
            &sec_level,
            Domain::APP,
            -1,
            Some(alias.to_string()),
            &key_generations::KeyParams {
                key_size,
                purpose: vec![KeyPurpose::ENCRYPT, KeyPurpose::DECRYPT],
                padding: Some(PaddingMode::RSA_OAEP),
                digest: Some(Digest::NONE),
                mgf_digest: None,
                block_mode: None,
                att_challenge: None,
                att_app_id: None,
            },
            KeyPurpose::DECRYPT,
            ForcedOp(false),
        ));

        assert!(result.is_err());
        assert_eq!(Error::Km(ErrorCode::INCOMPATIBLE_DIGEST), result.unwrap_err());
    }
}

/// Generate RSA encryption keys with various digest mode and padding mode combinations.
///     Digest modes: `MD5, SHA1, SHA-2 224, SHA-2 256, SHA-2 384 and SHA-2 512`
///     Padding modes: `NONE, RSA_PKCS1_1_5_ENCRYPT`
/// Try to create operations using generated keys, test should create operations successfully.
#[test]
fn keystore2_rsa_generate_keys_with_digest_paddings() {
    let keystore2 = get_keystore_service();
    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();

    let digests = [
        Digest::NONE,
        Digest::MD5,
        Digest::SHA1,
        Digest::SHA_2_224,
        Digest::SHA_2_256,
        Digest::SHA_2_384,
        Digest::SHA_2_512,
    ];

    let paddings = [PaddingMode::NONE, PaddingMode::RSA_PKCS1_1_5_ENCRYPT];

    let key_sizes = [2048, 3072, 4096];

    for key_size in key_sizes {
        for digest in digests {
            for padding in paddings {
                let alias = format!("ks_rsa_key_padding_{}{}{}", getuid(), key_size, digest.0);
                let result = key_generations::map_ks_error(create_rsa_key_and_operation(
                    &sec_level,
                    Domain::APP,
                    -1,
                    Some(alias.to_string()),
                    &key_generations::KeyParams {
                        key_size,
                        purpose: vec![KeyPurpose::ENCRYPT, KeyPurpose::DECRYPT],
                        padding: Some(padding),
                        digest: Some(digest),
                        mgf_digest: None,
                        block_mode: None,
                        att_challenge: None,
                        att_app_id: None,
                    },
                    KeyPurpose::DECRYPT,
                    ForcedOp(false),
                ));

                assert!(result.is_ok());
            } // End of paddings.
        } // End of digests.
    } // End of key-sizes.
}

/// Generate RSA encryption keys with only padding modes.
///     Padding modes: `NONE, RSA_PKCS1_1_5_ENCRYPT`
/// Try to create operations using generated keys, test should create operations successfully.
#[test]
fn keystore2_rsa_generate_keys_with_paddings() {
    let keystore2 = get_keystore_service();
    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();

    let paddings = [PaddingMode::NONE, PaddingMode::RSA_PKCS1_1_5_ENCRYPT];

    let key_sizes = [2048, 3072, 4096];

    for key_size in key_sizes {
        for padding in paddings {
            let alias = format!("ks_rsa_key_padding_{}{}", getuid(), key_size);
            let result = create_rsa_key_and_operation(
                &sec_level,
                Domain::APP,
                -1,
                Some(alias.to_string()),
                &key_generations::KeyParams {
                    key_size,
                    purpose: vec![KeyPurpose::ENCRYPT, KeyPurpose::DECRYPT],
                    padding: Some(padding),
                    digest: None,
                    mgf_digest: None,
                    block_mode: None,
                    att_challenge: None,
                    att_app_id: None,
                },
                KeyPurpose::DECRYPT,
                ForcedOp(false),
            );
            assert!(result.is_ok());
        } // End of paddings.
    } // End of key-sizes.
}

/// Generate RSA keys without padding and digest modes. Try to create decrypt operation without
/// digest and padding. Creation of an operation should fail with an error code
/// `UNSUPPORTED_PADDING_MODE`.
#[test]
fn keystore2_rsa_generate_keys() {
    let keystore2 = get_keystore_service();
    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();

    let key_sizes = [2048, 3072, 4096];

    for key_size in key_sizes {
        let alias = format!("ks_rsa_key_test_{}{}", getuid(), key_size);
        let result = key_generations::map_ks_error(create_rsa_key_and_operation(
            &sec_level,
            Domain::APP,
            -1,
            Some(alias.to_string()),
            &key_generations::KeyParams {
                key_size,
                purpose: vec![KeyPurpose::ENCRYPT, KeyPurpose::DECRYPT],
                padding: None,
                digest: None,
                mgf_digest: None,
                block_mode: None,
                att_challenge: None,
                att_app_id: None,
            },
            KeyPurpose::DECRYPT,
            ForcedOp(false),
        ));
        assert!(result.is_err());
        assert_eq!(Error::Km(ErrorCode::UNSUPPORTED_PADDING_MODE), result.unwrap_err());
    }
}

/// Generate a RSA encryption key. Try to create a signing operation with it, an error
/// `INCOMPATIBLE_PURPOSE` is expected as the generated key doesn't support sign operation.
#[test]
fn keystore2_rsa_encrypt_key_op_invalid_purpose() {
    let keystore2 = get_keystore_service();
    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();

    let alias = "ks_rsa_test_key_1";
    let result = key_generations::map_ks_error(create_rsa_key_and_operation(
        &sec_level,
        Domain::APP,
        -1,
        Some(alias.to_string()),
        &key_generations::KeyParams {
            key_size: 2048,
            purpose: vec![KeyPurpose::ENCRYPT, KeyPurpose::DECRYPT],
            padding: Some(PaddingMode::RSA_PKCS1_1_5_ENCRYPT),
            digest: Some(Digest::SHA_2_256),
            mgf_digest: None,
            block_mode: None,
            att_challenge: None,
            att_app_id: None,
        },
        KeyPurpose::SIGN,
        ForcedOp(false),
    ));
    assert!(result.is_err());
    assert_eq!(Error::Km(ErrorCode::INCOMPATIBLE_PURPOSE), result.unwrap_err());
}

/// Generate a RSA signing key. Try to create a decrypt operation with it, an error
/// `INCOMPATIBLE_PURPOSE` is expected as the generated key doesn't support decrypt operation.
#[test]
fn keystore2_rsa_sign_key_op_invalid_purpose() {
    let keystore2 = get_keystore_service();
    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();

    let alias = "ks_rsa_test_key_2";
    let result = key_generations::map_ks_error(create_rsa_key_and_operation(
        &sec_level,
        Domain::APP,
        -1,
        Some(alias.to_string()),
        &key_generations::KeyParams {
            key_size: 2048,
            purpose: vec![KeyPurpose::SIGN, KeyPurpose::VERIFY],
            padding: Some(PaddingMode::RSA_PKCS1_1_5_SIGN),
            digest: Some(Digest::SHA_2_256),
            mgf_digest: None,
            block_mode: None,
            att_challenge: None,
            att_app_id: None,
        },
        KeyPurpose::DECRYPT,
        ForcedOp(false),
    ));
    assert!(result.is_err());
    assert_eq!(Error::Km(ErrorCode::INCOMPATIBLE_PURPOSE), result.unwrap_err());
}

/// Generate a RSA key with SIGN and AGREE_KEY purposes. Try to perform an operation using the
/// generated key, an error `UNSUPPORTED_PURPOSE` is expected as RSA doesn't support AGREE_KEY.
#[test]
fn keystore2_rsa_key_unsupported_purpose() {
    let keystore2 = get_keystore_service();
    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();

    let alias = "ks_rsa_key_test_3";
    let result = key_generations::map_ks_error(create_rsa_key_and_operation(
        &sec_level,
        Domain::APP,
        -1,
        Some(alias.to_string()),
        &key_generations::KeyParams {
            key_size: 2048,
            purpose: vec![KeyPurpose::AGREE_KEY],
            padding: Some(PaddingMode::RSA_PKCS1_1_5_SIGN),
            digest: Some(Digest::SHA_2_256),
            mgf_digest: None,
            block_mode: None,
            att_challenge: None,
            att_app_id: None,
        },
        KeyPurpose::AGREE_KEY,
        ForcedOp(false),
    ));
    assert!(result.is_err());
    assert_eq!(Error::Km(ErrorCode::UNSUPPORTED_PURPOSE), result.unwrap_err());
}

/// Generate a RSA encrypt key with padding mode supported for signing. Try to create an operation
/// using generated key, an error `UNSUPPORTED_PADDING_MODE` is expected with unsupported padding
/// mode.
#[test]
fn keystore2_rsa_encrypt_key_unsupported_padding() {
    let keystore2 = get_keystore_service();
    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
    let paddings = [PaddingMode::RSA_PKCS1_1_5_SIGN, PaddingMode::RSA_PSS];

    for padding in paddings {
        let alias = format!("ks_rsa_key_test_4_{}{}", getuid(), padding.0);
        let result = key_generations::map_ks_error(create_rsa_key_and_operation(
            &sec_level,
            Domain::APP,
            -1,
            Some(alias.to_string()),
            &key_generations::KeyParams {
                key_size: 2048,
                purpose: vec![KeyPurpose::ENCRYPT, KeyPurpose::DECRYPT],
                padding: Some(padding),
                digest: Some(Digest::SHA_2_256),
                mgf_digest: None,
                block_mode: None,
                att_challenge: None,
                att_app_id: None,
            },
            KeyPurpose::DECRYPT,
            ForcedOp(false),
        ));
        assert!(result.is_err());
        assert_eq!(Error::Km(ErrorCode::UNSUPPORTED_PADDING_MODE), result.unwrap_err());
    }
}

/// Generate a RSA signing key with padding mode supported for encryption. Try to create an
/// operation using generated key, an error `UNSUPPORTED_PADDING_MODE` is expected with
/// unsupported padding mode.
#[test]
fn keystore2_rsa_signing_key_unsupported_padding() {
    let keystore2 = get_keystore_service();
    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
    let paddings = [PaddingMode::RSA_PKCS1_1_5_ENCRYPT, PaddingMode::RSA_OAEP];

    for padding in paddings {
        let alias = format!("ks_rsa_key_test_4_{}{}", getuid(), padding.0);
        let result = key_generations::map_ks_error(create_rsa_key_and_operation(
            &sec_level,
            Domain::APP,
            -1,
            Some(alias.to_string()),
            &key_generations::KeyParams {
                key_size: 2048,
                purpose: vec![KeyPurpose::SIGN, KeyPurpose::VERIFY],
                padding: Some(padding),
                digest: Some(Digest::SHA_2_256),
                mgf_digest: None,
                block_mode: None,
                att_challenge: None,
                att_app_id: None,
            },
            KeyPurpose::SIGN,
            ForcedOp(false),
        ));
        assert!(result.is_err());
        assert_eq!(Error::Km(ErrorCode::UNSUPPORTED_PADDING_MODE), result.unwrap_err());
    }
}

/// Generate a RSA encryption key. Try to perform encrypt operation using the generated
/// key, an error `UNSUPPORTED_PURPOSE` is expected as encrypt operation is not supported
/// with RSA key.
#[test]
fn keystore2_rsa_key_unsupported_op() {
    let keystore2 = get_keystore_service();
    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();

    let alias = "ks_rsa_key_test_5";
    let result = key_generations::map_ks_error(create_rsa_key_and_operation(
        &sec_level,
        Domain::APP,
        -1,
        Some(alias.to_string()),
        &key_generations::KeyParams {
            key_size: 2048,
            purpose: vec![KeyPurpose::ENCRYPT, KeyPurpose::DECRYPT],
            padding: Some(PaddingMode::RSA_PKCS1_1_5_ENCRYPT),
            digest: Some(Digest::SHA_2_256),
            mgf_digest: None,
            block_mode: None,
            att_challenge: None,
            att_app_id: None,
        },
        KeyPurpose::ENCRYPT,
        ForcedOp(false),
    ));

    assert!(result.is_err());
    assert_eq!(Error::Km(ErrorCode::UNSUPPORTED_PURPOSE), result.unwrap_err());
}

/// Generate a RSA key with encrypt, sign and verify purpose. Try to perform decrypt operation
/// using the generated key, an error `INCOMPATIBLE_PURPOSE` is expected as the key is not
/// generated with decrypt purpose.
#[test]
fn keystore2_rsa_key_missing_purpose() {
    let keystore2 = get_keystore_service();
    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();

    let alias = "ks_rsa_key_test_6";
    let result = key_generations::map_ks_error(create_rsa_key_and_operation(
        &sec_level,
        Domain::APP,
        -1,
        Some(alias.to_string()),
        &key_generations::KeyParams {
            key_size: 2048,
            purpose: vec![KeyPurpose::ENCRYPT, KeyPurpose::SIGN, KeyPurpose::VERIFY],
            padding: Some(PaddingMode::RSA_PKCS1_1_5_ENCRYPT),
            digest: Some(Digest::SHA_2_256),
            mgf_digest: None,
            block_mode: None,
            att_challenge: None,
            att_app_id: None,
        },
        KeyPurpose::DECRYPT,
        ForcedOp(false),
    ));

    assert!(result.is_err());
    assert_eq!(Error::Km(ErrorCode::INCOMPATIBLE_PURPOSE), result.unwrap_err());
}

/// Generate RSA encryption keys with OAEP padding mode and without digest mode. Try to create an
/// operation with generated key, unsupported digest error is expected.
#[test]
fn keystore2_rsa_gen_keys_with_oaep_paddings_without_digest() {
    let keystore2 = get_keystore_service();
    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();

    let alias = "ks_rsa_key_padding_fail";
    let result = key_generations::map_ks_error(create_rsa_key_and_operation(
        &sec_level,
        Domain::APP,
        -1,
        Some(alias.to_string()),
        &key_generations::KeyParams {
            key_size: 2048,
            purpose: vec![KeyPurpose::ENCRYPT, KeyPurpose::DECRYPT],
            padding: Some(PaddingMode::RSA_OAEP),
            digest: None,
            mgf_digest: None,
            block_mode: None,
            att_challenge: None,
            att_app_id: None,
        },
        KeyPurpose::DECRYPT,
        ForcedOp(false),
    ));

    assert!(result.is_err());
    assert_eq!(Error::Km(ErrorCode::UNSUPPORTED_DIGEST), result.unwrap_err());
}

/// Generate RSA keys with unsupported key size, an error `UNSUPPORTED_KEY_SIZE` is expected.
#[test]
fn keystore2_rsa_gen_keys_unsupported_size() {
    let keystore2 = get_keystore_service();
    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();

    let alias = "ks_rsa_key_padding_fail";
    let result = key_generations::map_ks_error(key_generations::generate_rsa_key(
        &sec_level,
        Domain::APP,
        -1,
        Some(alias.to_string()),
        &key_generations::KeyParams {
            key_size: 5120,
            purpose: vec![KeyPurpose::ENCRYPT, KeyPurpose::SIGN, KeyPurpose::VERIFY],
            padding: Some(PaddingMode::RSA_PKCS1_1_5_ENCRYPT),
            digest: Some(Digest::SHA_2_256),
            mgf_digest: None,
            block_mode: None,
            att_challenge: None,
            att_app_id: None,
        },
        None,
    ));

    assert!(result.is_err());
    assert_eq!(Error::Km(ErrorCode::UNSUPPORTED_KEY_SIZE), result.unwrap_err());
}
