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
    Algorithm::Algorithm, BlockMode::BlockMode, Digest::Digest, EcCurve::EcCurve,
    ErrorCode::ErrorCode, KeyPurpose::KeyPurpose, PaddingMode::PaddingMode,
    SecurityLevel::SecurityLevel,
};
use android_system_keystore2::aidl::android::system::keystore2::{
    Domain::Domain, IKeystoreSecurityLevel::IKeystoreSecurityLevel, KeyDescriptor::KeyDescriptor,
};

use keystore2_test_utils::{
    authorizations, get_keystore_service, key_generations, key_generations::Error,
};

use crate::keystore2_client_test_utils::{
    has_trusty_keymint, perform_sample_asym_sign_verify_op, perform_sample_hmac_sign_verify_op,
    perform_sample_sym_key_decrypt_op, perform_sample_sym_key_encrypt_op, SAMPLE_PLAIN_TEXT,
};

pub fn import_rsa_sign_key_and_perform_sample_operation(
    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
    domain: Domain,
    nspace: i64,
    alias: Option<String>,
    import_params: authorizations::AuthSetBuilder,
) {
    let key_metadata =
        key_generations::import_rsa_2048_key(sec_level, domain, nspace, alias, import_params)
            .unwrap();

    perform_sample_asym_sign_verify_op(
        sec_level,
        &key_metadata,
        Some(PaddingMode::RSA_PSS),
        Some(Digest::SHA_2_256),
    );
}

/// Import RSA key and verify imported key parameters. Try to create an operation using the
/// imported key. Test should be able to create an operation successfully.
#[test]
fn keystore2_rsa_import_key_success() {
    let keystore2 = get_keystore_service();
    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();

    let alias = format!("ks_rsa_key_test_import_1_{}{}", getuid(), 2048);

    let import_params = authorizations::AuthSetBuilder::new()
        .no_auth_required()
        .algorithm(Algorithm::RSA)
        .digest(Digest::SHA_2_256)
        .purpose(KeyPurpose::SIGN)
        .purpose(KeyPurpose::VERIFY)
        .padding_mode(PaddingMode::RSA_PSS)
        .key_size(2048)
        .rsa_public_exponent(65537)
        .cert_not_before(0)
        .cert_not_after(253402300799000);

    import_rsa_sign_key_and_perform_sample_operation(
        &sec_level,
        Domain::APP,
        -1,
        Some(alias),
        import_params,
    );
}

/// Import RSA key without providing key-size and public exponent in import key parameters list.
/// Let Key-size and public-exponent to be determined from the imported key material. Verify
/// imported key parameters. Try to create an operation using the imported key. Test should be
/// able to create an operation successfully.
#[test]
fn keystore2_rsa_import_key_determine_key_size_and_pub_exponent() {
    let keystore2 = get_keystore_service();
    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();

    let alias = format!("ks_rsa_key_test_import_2_{}{}", getuid(), 2048);

    // key-size and public-exponent shouldn't be specified in import key parameters list.
    let import_params = authorizations::AuthSetBuilder::new()
        .no_auth_required()
        .algorithm(Algorithm::RSA)
        .digest(Digest::SHA_2_256)
        .purpose(KeyPurpose::SIGN)
        .purpose(KeyPurpose::VERIFY)
        .padding_mode(PaddingMode::RSA_PSS)
        .cert_not_before(0)
        .cert_not_after(253402300799000);

    import_rsa_sign_key_and_perform_sample_operation(
        &sec_level,
        Domain::APP,
        -1,
        Some(alias),
        import_params,
    );
}

/// Try to import RSA key with wrong key size as import-key-parameter. Test should fail to import
/// a key with `IMPORT_PARAMETER_MISMATCH` error code.
#[test]
fn keystore2_rsa_import_key_fails_with_keysize_param_mismatch_error() {
    let keystore2 = get_keystore_service();
    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();

    let alias = format!("ks_rsa_key_test_import_3_{}{}", getuid(), 2048);

    let import_params = authorizations::AuthSetBuilder::new()
        .no_auth_required()
        .algorithm(Algorithm::RSA)
        .digest(Digest::SHA_2_256)
        .purpose(KeyPurpose::SIGN)
        .purpose(KeyPurpose::VERIFY)
        .padding_mode(PaddingMode::RSA_PSS)
        .key_size(1024) // Wrong key size is specified, (actual key-size is 2048).
        .rsa_public_exponent(65537)
        .cert_not_before(0)
        .cert_not_after(253402300799000);

    let result = key_generations::map_ks_error(sec_level.importKey(
        &KeyDescriptor { domain: Domain::APP, nspace: -1, alias: Some(alias), blob: None },
        None,
        &import_params,
        0,
        key_generations::RSA_2048_KEY,
    ));

    assert!(result.is_err());
    assert_eq!(Error::Km(ErrorCode::IMPORT_PARAMETER_MISMATCH), result.unwrap_err());
}

/// Try to import RSA key with wrong public-exponent as import-key-parameter.
/// Test should fail to import a key with `IMPORT_PARAMETER_MISMATCH` error code.
#[test]
fn keystore2_rsa_import_key_fails_with_public_exponent_param_mismatch_error() {
    let keystore2 = get_keystore_service();
    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();

    let alias = format!("ks_rsa_key_test_import_4_{}{}", getuid(), 2048);

    let import_params = authorizations::AuthSetBuilder::new()
        .no_auth_required()
        .algorithm(Algorithm::RSA)
        .digest(Digest::SHA_2_256)
        .purpose(KeyPurpose::SIGN)
        .purpose(KeyPurpose::VERIFY)
        .padding_mode(PaddingMode::RSA_PSS)
        .key_size(2048)
        .rsa_public_exponent(3) // This doesn't match the key.
        .cert_not_before(0)
        .cert_not_after(253402300799000);

    let result = key_generations::map_ks_error(sec_level.importKey(
        &KeyDescriptor { domain: Domain::APP, nspace: -1, alias: Some(alias), blob: None },
        None,
        &import_params,
        0,
        key_generations::RSA_2048_KEY,
    ));

    assert!(result.is_err());
    assert_eq!(Error::Km(ErrorCode::IMPORT_PARAMETER_MISMATCH), result.unwrap_err());
}

/// Try to import a key with multiple purposes. Test should fail to import a key with
/// `INCOMPATIBLE_PURPOSE` error code. If the backend is `keymaster` then `importKey` shall be
/// successful.
#[test]
fn keystore2_rsa_import_key_with_multipurpose_fails_incompt_purpose_error() {
    let keystore2 = get_keystore_service();
    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();

    let alias = format!("ks_rsa_key_test_import_5_{}{}", getuid(), 2048);

    let import_params = authorizations::AuthSetBuilder::new()
        .no_auth_required()
        .algorithm(Algorithm::RSA)
        .digest(Digest::SHA_2_256)
        .purpose(KeyPurpose::SIGN)
        .purpose(KeyPurpose::ATTEST_KEY)
        .padding_mode(PaddingMode::RSA_PSS)
        .key_size(2048)
        .rsa_public_exponent(65537)
        .cert_not_before(0)
        .cert_not_after(253402300799000);

    let result = key_generations::map_ks_error(sec_level.importKey(
        &KeyDescriptor { domain: Domain::APP, nspace: -1, alias: Some(alias), blob: None },
        None,
        &import_params,
        0,
        key_generations::RSA_2048_KEY,
    ));

    if has_trusty_keymint() {
        assert!(result.is_err());
        assert_eq!(Error::Km(ErrorCode::INCOMPATIBLE_PURPOSE), result.unwrap_err());
    } else {
        assert!(result.is_ok());
    }
}

/// Import EC key and verify imported key parameters. Let ec-curve to be determined from the
/// imported key material. Try to create an operation using the imported key. Test should be
/// able to create an operation successfully.
#[test]
fn keystore2_import_ec_key_success() {
    let keystore2 = get_keystore_service();
    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();

    let alias = format!("ks_ec_key_test_import_1_{}{}", getuid(), 256);

    // Don't specify ec-curve.
    let import_params = authorizations::AuthSetBuilder::new()
        .no_auth_required()
        .algorithm(Algorithm::EC)
        .digest(Digest::SHA_2_256)
        .purpose(KeyPurpose::SIGN)
        .purpose(KeyPurpose::VERIFY)
        .cert_not_before(0)
        .cert_not_after(253402300799000);

    let key_metadata = key_generations::import_ec_p_256_key(
        &sec_level,
        Domain::APP,
        -1,
        Some(alias),
        import_params,
    )
    .expect("Failed to import EC key.");

    perform_sample_asym_sign_verify_op(&sec_level, &key_metadata, None, Some(Digest::SHA_2_256));
}

/// Try to import EC key with wrong ec-curve as import-key-parameter. Test should fail to import a
/// key with `IMPORT_PARAMETER_MISMATCH` error code.
#[test]
fn keystore2_ec_import_key_fails_with_mismatch_curve_error() {
    let keystore2 = get_keystore_service();
    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();

    let alias = format!("ks_ec_key_test_import_1_{}{}", getuid(), 256);

    let import_params = authorizations::AuthSetBuilder::new()
        .no_auth_required()
        .algorithm(Algorithm::EC)
        .digest(Digest::SHA_2_256)
        .ec_curve(EcCurve::P_224) // It doesn't match with key material.
        .purpose(KeyPurpose::SIGN)
        .purpose(KeyPurpose::VERIFY)
        .cert_not_before(0)
        .cert_not_after(253402300799000);

    let result = key_generations::map_ks_error(sec_level.importKey(
        &KeyDescriptor { domain: Domain::APP, nspace: -1, alias: Some(alias), blob: None },
        None,
        &import_params,
        0,
        key_generations::EC_P_256_KEY,
    ));
    assert!(result.is_err());
    assert_eq!(Error::Km(ErrorCode::IMPORT_PARAMETER_MISMATCH), result.unwrap_err());
}

/// Import AES key and verify key parameters. Try to create an operation using the imported key.
/// Test should be able to create an operation successfully.
#[test]
fn keystore2_import_aes_key_success() {
    let keystore2 = get_keystore_service();
    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();

    let alias = format!("ks_aes_key_test_import_1_{}{}", getuid(), 256);
    let key_metadata = key_generations::import_aes_key(&sec_level, Domain::APP, -1, Some(alias))
        .expect("Failed to import AES key.");

    let cipher_text = perform_sample_sym_key_encrypt_op(
        &sec_level,
        PaddingMode::PKCS7,
        BlockMode::ECB,
        &mut None,
        None,
        &key_metadata.key,
    )
    .unwrap();

    assert!(cipher_text.is_some());

    let plain_text = perform_sample_sym_key_decrypt_op(
        &sec_level,
        &cipher_text.unwrap(),
        PaddingMode::PKCS7,
        BlockMode::ECB,
        &mut None,
        None,
        &key_metadata.key,
    )
    .unwrap();

    assert!(plain_text.is_some());
    assert_eq!(plain_text.unwrap(), SAMPLE_PLAIN_TEXT.to_vec());
}

/// Import 3DES key and verify key parameters. Try to create an operation using the imported key.
/// Test should be able to create an operation successfully.
#[test]
fn keystore2_import_3des_key_success() {
    let keystore2 = get_keystore_service();
    let sec_level = key_generations::map_ks_error(
        keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT),
    )
    .unwrap();

    let alias = format!("ks_3des_key_test_import_1_{}{}", getuid(), 168);

    let key_metadata = key_generations::import_3des_key(&sec_level, Domain::APP, -1, Some(alias))
        .expect("Failed to import 3DES key.");

    let cipher_text = perform_sample_sym_key_encrypt_op(
        &sec_level,
        PaddingMode::PKCS7,
        BlockMode::ECB,
        &mut None,
        None,
        &key_metadata.key,
    )
    .unwrap();

    assert!(cipher_text.is_some());

    let plain_text = perform_sample_sym_key_decrypt_op(
        &sec_level,
        &cipher_text.unwrap(),
        PaddingMode::PKCS7,
        BlockMode::ECB,
        &mut None,
        None,
        &key_metadata.key,
    )
    .unwrap();

    assert!(plain_text.is_some());
    assert_eq!(plain_text.unwrap(), SAMPLE_PLAIN_TEXT.to_vec());
}

/// Import HMAC key and verify key parameters. Try to create an operation using the imported key.
/// Test should be able to create an operation successfully.
#[test]
fn keystore2_import_hmac_key_success() {
    let keystore2 = get_keystore_service();
    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();

    let alias = format!("ks_hmac_key_test_import_1_{}", getuid());

    let key_metadata = key_generations::import_hmac_key(&sec_level, Domain::APP, -1, Some(alias))
        .expect("Failed to import HMAC key.");

    perform_sample_hmac_sign_verify_op(&sec_level, &key_metadata.key);
}
