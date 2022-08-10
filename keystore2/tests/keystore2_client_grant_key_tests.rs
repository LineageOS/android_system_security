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

use nix::unistd::{getuid, Gid, Uid};
use rustutils::users::AID_USER_OFFSET;

use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    Digest::Digest, KeyPurpose::KeyPurpose, SecurityLevel::SecurityLevel,
};
use android_system_keystore2::aidl::android::system::keystore2::{
    Domain::Domain, KeyDescriptor::KeyDescriptor, KeyPermission::KeyPermission,
    ResponseCode::ResponseCode,
};

use keystore2_test_utils::{
    authorizations, get_keystore_service, key_generations, key_generations::Error, run_as,
};

use crate::keystore2_client_test_utils::perform_sample_sign_operation;

/// Generate an EC signing key and grant it to the user with given access vector.
fn generate_ec_key_and_grant_to_user(
    grantee_uid: i32,
    access_vector: i32,
) -> binder::Result<KeyDescriptor> {
    let keystore2 = get_keystore_service();
    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
    let alias = format!("{}{}", "ks_grant_test_key_1", getuid());

    let key_metadata = key_generations::generate_ec_p256_signing_key(
        &sec_level,
        Domain::SELINUX,
        key_generations::SELINUX_SHELL_NAMESPACE,
        Some(alias),
        None,
        None,
    )
    .unwrap();

    keystore2.grant(&key_metadata.key, grantee_uid, access_vector)
}

/// Try to grant a key with permission that does not map to any of the `KeyPermission` values.
/// An error is expected with values that does not map to set of permissions listed in
/// `KeyPermission`.
#[test]
fn keystore2_grant_key_with_invalid_perm_expecting_syserror() {
    const USER_ID: u32 = 99;
    const APPLICATION_ID: u32 = 10001;
    let grantee_uid = USER_ID * AID_USER_OFFSET + APPLICATION_ID;
    let invalid_access_vector = KeyPermission::CONVERT_STORAGE_KEY_TO_EPHEMERAL.0 << 19;

    let result = key_generations::map_ks_error(generate_ec_key_and_grant_to_user(
        grantee_uid.try_into().unwrap(),
        invalid_access_vector,
    ));
    assert!(result.is_err());
    assert_eq!(Error::Rc(ResponseCode::SYSTEM_ERROR), result.unwrap_err());
}

/// Try to grant a key with empty access vector `KeyPermission::NONE`, should be able to grant a
/// key with empty access vector successfully. In grantee context try to use the granted key, it
/// should fail to load the key with permission denied error.
#[test]
fn keystore2_grant_key_with_perm_none() {
    static TARGET_SU_CTX: &str = "u:r:su:s0";

    static GRANTEE_CTX: &str = "u:r:untrusted_app:s0:c91,c256,c10,c20";
    const USER_ID: u32 = 99;
    const APPLICATION_ID: u32 = 10001;
    static GRANTEE_UID: u32 = USER_ID * AID_USER_OFFSET + APPLICATION_ID;
    static GRANTEE_GID: u32 = GRANTEE_UID;

    let grant_key_nspace = unsafe {
        run_as::run_as(TARGET_SU_CTX, Uid::from_raw(0), Gid::from_raw(0), || {
            let empty_access_vector = KeyPermission::NONE.0;

            let grant_key = key_generations::map_ks_error(generate_ec_key_and_grant_to_user(
                GRANTEE_UID.try_into().unwrap(),
                empty_access_vector,
            ))
            .unwrap();

            assert_eq!(grant_key.domain, Domain::GRANT);

            grant_key.nspace
        })
    };

    // In grantee context try to load the key, it should fail to load the granted key as it is
    // granted with empty access vector.
    unsafe {
        run_as::run_as(
            GRANTEE_CTX,
            Uid::from_raw(GRANTEE_UID),
            Gid::from_raw(GRANTEE_GID),
            move || {
                let keystore2 = get_keystore_service();

                let result = key_generations::map_ks_error(keystore2.getKeyEntry(&KeyDescriptor {
                    domain: Domain::GRANT,
                    nspace: grant_key_nspace,
                    alias: None,
                    blob: None,
                }));
                assert!(result.is_err());
                assert_eq!(Error::Rc(ResponseCode::PERMISSION_DENIED), result.unwrap_err());
            },
        )
    };
}

/// Grant a key to the user (grantee) with `GET_INFO|USE` key permissions. Verify whether grantee
/// can succeed in loading the granted key and try to perform simple operation using this granted
/// key. Grantee should be able to load the key and use the key to perform crypto operation
/// successfully. Try to delete the granted key in grantee context where it is expected to fail to
/// delete it as `DELETE` permission is not granted.
#[test]
fn keystore2_grant_get_info_use_key_perm() {
    static TARGET_SU_CTX: &str = "u:r:su:s0";

    static GRANTEE_CTX: &str = "u:r:untrusted_app:s0:c91,c256,c10,c20";
    const USER_ID: u32 = 99;
    const APPLICATION_ID: u32 = 10001;
    static GRANTEE_UID: u32 = USER_ID * AID_USER_OFFSET + APPLICATION_ID;
    static GRANTEE_GID: u32 = GRANTEE_UID;

    // Generate a key and grant it to a user with GET_INFO|USE key permissions.
    let grant_key_nspace = unsafe {
        run_as::run_as(TARGET_SU_CTX, Uid::from_raw(0), Gid::from_raw(0), || {
            let access_vector = KeyPermission::GET_INFO.0 | KeyPermission::USE.0;
            let grant_key = key_generations::map_ks_error(generate_ec_key_and_grant_to_user(
                GRANTEE_UID.try_into().unwrap(),
                access_vector,
            ))
            .unwrap();

            assert_eq!(grant_key.domain, Domain::GRANT);

            grant_key.nspace
        })
    };

    // In grantee context load the key and try to perform crypto operation.
    unsafe {
        run_as::run_as(
            GRANTEE_CTX,
            Uid::from_raw(GRANTEE_UID),
            Gid::from_raw(GRANTEE_GID),
            move || {
                let keystore2 = get_keystore_service();
                let sec_level =
                    keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();

                // Load the granted key.
                let key_entry_response = keystore2
                    .getKeyEntry(&KeyDescriptor {
                        domain: Domain::GRANT,
                        nspace: grant_key_nspace,
                        alias: None,
                        blob: None,
                    })
                    .unwrap();

                // Perform sample crypto operation using granted key.
                let op_response = sec_level
                    .createOperation(
                        &key_entry_response.metadata.key,
                        &authorizations::AuthSetBuilder::new()
                            .purpose(KeyPurpose::SIGN)
                            .digest(Digest::SHA_2_256),
                        false,
                    )
                    .unwrap();
                assert!(op_response.iOperation.is_some());
                assert_eq!(
                    Ok(()),
                    key_generations::map_ks_error(perform_sample_sign_operation(
                        &op_response.iOperation.unwrap()
                    ))
                );

                // Try to delete the key, it is expected to be fail with permission denied error.
                let result = key_generations::map_ks_error(keystore2.deleteKey(&KeyDescriptor {
                    domain: Domain::GRANT,
                    nspace: grant_key_nspace,
                    alias: None,
                    blob: None,
                }));
                assert!(result.is_err());
                assert_eq!(Error::Rc(ResponseCode::PERMISSION_DENIED), result.unwrap_err());
            },
        )
    };
}
