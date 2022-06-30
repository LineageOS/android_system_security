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
use serde::{Deserialize, Serialize};

use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    Digest::Digest, ErrorCode::ErrorCode, KeyPurpose::KeyPurpose, SecurityLevel::SecurityLevel,
};
use android_system_keystore2::aidl::android::system::keystore2::{
    CreateOperationResponse::CreateOperationResponse, Domain::Domain,
    IKeystoreOperation::IKeystoreOperation, KeyDescriptor::KeyDescriptor,
    KeyPermission::KeyPermission, ResponseCode::ResponseCode,
};

use keystore2_test_utils::authorizations;
use keystore2_test_utils::get_keystore_service;
use keystore2_test_utils::key_generations;
use keystore2_test_utils::key_generations::Error;
use keystore2_test_utils::run_as;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
enum TestOutcome {
    Ok,
    BackendBusy,
    InvalidHandle,
    OtherErr,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct BarrierReached;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ForcedOp(pub bool);

/// Generate a EC_P256 key using given domain, namespace and alias.
/// Create an operation using the generated key and perform sample signing operation.
fn create_signing_operation(
    forced_op: ForcedOp,
    op_purpose: KeyPurpose,
    op_digest: Digest,
    domain: Domain,
    nspace: i64,
    alias: Option<String>,
) -> binder::Result<CreateOperationResponse> {
    let keystore2 = get_keystore_service();
    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();

    let key_metadata = key_generations::generate_ec_p256_signing_key(
        &sec_level, domain, nspace, alias, None, None,
    )
    .unwrap();

    sec_level.createOperation(
        &key_metadata.key,
        &authorizations::AuthSetBuilder::new().purpose(op_purpose).digest(op_digest),
        forced_op.0,
    )
}

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

/// Performs sample signing operation.
fn perform_sample_sign_operation(
    op: &binder::Strong<dyn IKeystoreOperation>,
) -> Result<(), binder::Status> {
    op.update(b"my message")?;
    let sig = op.finish(None, None)?;
    assert!(sig.is_some());
    Ok(())
}

/// Create new operation on child proc and perform simple operation after parent notification.
fn execute_op_run_as_child(
    target_ctx: &'static str,
    domain: Domain,
    nspace: i64,
    alias: Option<String>,
    auid: Uid,
    agid: Gid,
    forced_op: ForcedOp,
) -> run_as::ChildHandle<TestOutcome, BarrierReached> {
    unsafe {
        run_as::run_as_child(target_ctx, auid, agid, move |reader, writer| {
            let result = key_generations::map_ks_error(create_signing_operation(
                forced_op,
                KeyPurpose::SIGN,
                Digest::SHA_2_256,
                domain,
                nspace,
                alias,
            ));

            // Let the parent know that an operation has been started, then
            // wait until the parent notifies us to continue, so the operation
            // remains open.
            writer.send(&BarrierReached {});
            reader.recv();

            // Continue performing the operation after parent notifies.
            match &result {
                Ok(CreateOperationResponse { iOperation: Some(op), .. }) => {
                    match key_generations::map_ks_error(perform_sample_sign_operation(op)) {
                        Ok(()) => TestOutcome::Ok,
                        Err(Error::Km(ErrorCode::INVALID_OPERATION_HANDLE)) => {
                            TestOutcome::InvalidHandle
                        }
                        Err(e) => panic!("Error in performing op: {:#?}", e),
                    }
                }
                Ok(_) => TestOutcome::OtherErr,
                Err(Error::Rc(ResponseCode::BACKEND_BUSY)) => TestOutcome::BackendBusy,
                _ => TestOutcome::OtherErr,
            }
        })
        .expect("Failed to create an operation.")
    }
}

fn create_operations(
    target_ctx: &'static str,
    forced_op: ForcedOp,
    max_ops: i32,
) -> Vec<run_as::ChildHandle<TestOutcome, BarrierReached>> {
    let alias = format!("ks_op_test_key_{}", getuid());
    let base_gid = 99 * AID_USER_OFFSET + 10001;
    let base_uid = 99 * AID_USER_OFFSET + 10001;
    (0..max_ops)
        .into_iter()
        .map(|i| {
            execute_op_run_as_child(
                target_ctx,
                Domain::APP,
                key_generations::SELINUX_SHELL_NAMESPACE,
                Some(alias.to_string()),
                Uid::from_raw(base_uid + (i as u32)),
                Gid::from_raw(base_gid + (i as u32)),
                forced_op,
            )
        })
        .collect()
}

/// This test verifies that backend service throws BACKEND_BUSY error when all
/// operations slots are full. This test creates operations in child processes and
/// collects the status of operations performed in each child proc and determines
/// whether any child proc exited with error status.
#[test]
fn keystore2_backend_busy_test() {
    const MAX_OPS: i32 = 100;
    static TARGET_CTX: &str = "u:r:untrusted_app:s0:c91,c256,c10,c20";

    let mut child_handles = create_operations(TARGET_CTX, ForcedOp(false), MAX_OPS);

    // Wait until all child procs notifies us to continue,
    // so that there are definitely enough operations outstanding to trigger a BACKEND_BUSY.
    for ch in child_handles.iter_mut() {
        ch.recv();
    }
    // Notify each child to resume and finish.
    for ch in child_handles.iter_mut() {
        ch.send(&BarrierReached {});
    }

    // Collect the result and validate whether backend busy has occurred.
    let mut busy_count = 0;
    for ch in child_handles.into_iter() {
        if ch.get_result() == TestOutcome::BackendBusy {
            busy_count += 1;
        }
    }
    assert!(busy_count > 0)
}

/// This test confirms that forced operation is having high pruning power.
/// 1. Initially create regular operations such that there are enough operations outstanding
///    to trigger BACKEND_BUSY.
/// 2. Then, create a forced operation. System should be able to prune one of the regular
///    operations and create a slot for forced operation successfully.
#[test]
fn keystore2_forced_op_after_backendbusy_test() {
    const MAX_OPS: i32 = 100;
    static TARGET_CTX: &str = "u:r:untrusted_app:s0:c91,c256,c10,c20";

    // Create regular operations.
    let mut child_handles = create_operations(TARGET_CTX, ForcedOp(false), MAX_OPS);

    // Wait until all child procs notifies us to continue, so that there are enough
    // operations outstanding to trigger a BACKEND_BUSY.
    for ch in child_handles.iter_mut() {
        ch.recv();
    }

    // Create a forced operation.
    let auid = 99 * AID_USER_OFFSET + 10604;
    let agid = 99 * AID_USER_OFFSET + 10604;
    unsafe {
        run_as::run_as(
            key_generations::TARGET_VOLD_CTX,
            Uid::from_raw(auid),
            Gid::from_raw(agid),
            move || {
                let alias = format!("ks_prune_forced_op_key_{}", getuid());

                // To make room for this forced op, system should be able to prune one of the
                // above created regular operations and create a slot for this forced operation
                // successfully.
                create_signing_operation(
                    ForcedOp(true),
                    KeyPurpose::SIGN,
                    Digest::SHA_2_256,
                    Domain::SELINUX,
                    100,
                    Some(alias),
                )
                .expect("Client failed to create forced operation after BACKEND_BUSY state.");
            },
        );
    };

    // Notify each child to resume and finish.
    for ch in child_handles.iter_mut() {
        ch.send(&BarrierReached {});
    }

    // Collect the results of above created regular operations.
    let mut pruned_count = 0;
    let mut busy_count = 0;
    let mut _other_err = 0;
    for ch in child_handles.into_iter() {
        match ch.get_result() {
            TestOutcome::BackendBusy => {
                busy_count += 1;
            }
            TestOutcome::InvalidHandle => {
                pruned_count += 1;
            }
            _ => {
                _other_err += 1;
            }
        }
    }
    // Verify that there should be at least one backend busy has occurred while creating
    // above regular operations.
    assert!(busy_count > 0);

    // Verify that there should be at least one pruned operation which should have failed while
    // performing operation.
    assert!(pruned_count > 0);
}

/// This test confirms that forced operations can't be pruned.
///  1. Creates an initial forced operation and tries to complete the operation after BACKEND_BUSY
///     error is triggered.
///  2. Create MAX_OPS number of forced operations so that definitely enough number of operations
///     outstanding to trigger a BACKEND_BUSY.
///  3. Try to use initially created forced operation (in step #1) and able to perform the
///     operation successfully. This confirms that none of the later forced operations evicted the
///     initial forced operation.
#[test]
fn keystore2_max_forced_ops_test() {
    const MAX_OPS: i32 = 100;
    let auid = 99 * AID_USER_OFFSET + 10205;
    let agid = 99 * AID_USER_OFFSET + 10205;

    // Create initial forced operation in a child process
    // and wait for the parent to notify to perform operation.
    let alias = format!("ks_forced_op_key_{}", getuid());
    let mut first_op_handle = execute_op_run_as_child(
        key_generations::TARGET_SU_CTX,
        Domain::SELINUX,
        key_generations::SELINUX_SHELL_NAMESPACE,
        Some(alias),
        Uid::from_raw(auid),
        Gid::from_raw(agid),
        ForcedOp(true),
    );

    // Wait until above child proc notifies us to continue, so that there is definitely a forced
    // operation outstanding to perform a operation.
    first_op_handle.recv();

    // Create MAX_OPS number of forced operations.
    let mut child_handles =
        create_operations(key_generations::TARGET_SU_CTX, ForcedOp(true), MAX_OPS);

    // Wait until all child procs notifies us to continue, so that  there are enough operations
    // outstanding to trigger a BACKEND_BUSY.
    for ch in child_handles.iter_mut() {
        ch.recv();
    }

    // Notify initial created forced operation to continue performing the operations.
    first_op_handle.send(&BarrierReached {});

    // Collect initially created forced operation result and is expected to complete operation
    // successfully.
    let first_op_result = first_op_handle.get_result();
    assert_eq!(first_op_result, TestOutcome::Ok);

    // Notify each child to resume and finish.
    for ch in child_handles.iter_mut() {
        ch.send(&BarrierReached {});
    }

    // Collect the result and validate whether backend busy has occurred with MAX_OPS number
    // of forced operations.
    let busy_count = child_handles
        .into_iter()
        .map(|ch| ch.get_result())
        .filter(|r| *r == TestOutcome::BackendBusy)
        .count();
    assert!(busy_count > 0);
}

/// This test will verify the use case with the same owner(UID) requesting `n` number of operations.
/// This test confirms that when all operation slots are full and a new operation is requested,
/// an operation which is least recently used and lived longest will be pruned to make a room
/// for a new operation. Pruning strategy should prevent the operations of the other owners(UID)
/// from being pruned.
///
/// 1. Create an operation in a child process with `untrusted_app` context and wait for parent
///    notification to complete the operation.
/// 2. Let parent process create `n` number of operations such that there are enough operations
///    outstanding to trigger cannibalizing their own sibling operations.
/// 3. Sequentially try to use above created `n` number of operations and also add a new operation,
///    so that it should trigger cannibalizing one of their own sibling operations.
///    3.1 While trying to use these pruned operations an `INVALID_OPERATION_HANDLE` error is
///        expected as they are already pruned.
/// 4. Notify the child process to resume and complete the operation. It is expected to complete the
///    operation successfully.
/// 5. Try to use the latest operation of parent. It is expected to complete the operation
///    successfully.
#[test]
fn keystore2_ops_prune_test() {
    const MAX_OPS: usize = 40; // This should be at least 32 with sec_level TEE.

    static TARGET_CTX: &str = "u:r:untrusted_app:s0";
    const USER_ID: u32 = 99;
    const APPLICATION_ID: u32 = 10601;

    let uid = USER_ID * AID_USER_OFFSET + APPLICATION_ID;
    let gid = USER_ID * AID_USER_OFFSET + APPLICATION_ID;

    // Create an operation in an untrusted_app context. Wait until the parent notifies to continue.
    // Once the parent notifies, this operation is expected to be completed successfully.
    let alias = format!("ks_reg_op_key_{}", getuid());
    let mut child_handle = execute_op_run_as_child(
        TARGET_CTX,
        Domain::APP,
        -1,
        Some(alias),
        Uid::from_raw(uid),
        Gid::from_raw(gid),
        ForcedOp(false),
    );

    // Wait until child process notifies us to continue, so that an operation from child process is
    // outstanding to complete the operation.
    child_handle.recv();

    // Generate a key to use in below operations.
    let keystore2 = get_keystore_service();
    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
    let alias = format!("ks_prune_op_test_key_{}", getuid());
    let key_metadata = key_generations::generate_ec_p256_signing_key(
        &sec_level,
        Domain::SELINUX,
        key_generations::SELINUX_SHELL_NAMESPACE,
        Some(alias),
        None,
        None,
    )
    .unwrap();

    // Create multiple operations in this process to trigger cannibalizing sibling operations.
    let mut ops: Vec<binder::Result<CreateOperationResponse>> = (0..MAX_OPS)
        .into_iter()
        .map(|_| {
            sec_level.createOperation(
                &key_metadata.key,
                &authorizations::AuthSetBuilder::new()
                    .purpose(KeyPurpose::SIGN)
                    .digest(Digest::SHA_2_256),
                false,
            )
        })
        .collect();

    // Sequentially try to use operation handles created above and also add a new operation.
    for vec_index in 0..MAX_OPS {
        match &ops[vec_index] {
            Ok(CreateOperationResponse { iOperation: Some(op), .. }) => {
                // Older operation handle is pruned, if we try to use that an error is expected.
                assert_eq!(
                    Err(Error::Km(ErrorCode::INVALID_OPERATION_HANDLE)),
                    key_generations::map_ks_error(op.update(b"my message"))
                );
            }
            _ => panic!("Operation should have created successfully."),
        }

        // Create a new operation, it should trigger to cannibalize one of their own sibling
        // operations.
        ops.push(
            sec_level.createOperation(
                &key_metadata.key,
                &authorizations::AuthSetBuilder::new()
                    .purpose(KeyPurpose::SIGN)
                    .digest(Digest::SHA_2_256),
                false,
            ),
        );
    }

    // Notify child process to continue the operation.
    child_handle.send(&BarrierReached {});
    assert!((child_handle.get_result() == TestOutcome::Ok), "Failed to perform an operation");

    // Try to use the latest operation created by parent, should be able to use it successfully.
    match ops.last() {
        Some(Ok(CreateOperationResponse { iOperation: Some(op), .. })) => {
            assert_eq!(Ok(()), key_generations::map_ks_error(perform_sample_sign_operation(op)));
        }
        _ => panic!("Operation should have created successfully."),
    }
}

/// This test will try to load the key with Domain::BLOB.
/// INVALID_ARGUMENT error is expected.
#[test]
fn keystore2_get_key_entry_blob_fail() {
    let keystore2 = get_keystore_service();
    let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();

    // Generate a key with domain as BLOB.
    let key_metadata = key_generations::generate_ec_p256_signing_key(
        &sec_level,
        Domain::BLOB,
        key_generations::SELINUX_SHELL_NAMESPACE,
        None,
        None,
        None,
    )
    .unwrap();

    // Try to load the key using above generated KeyDescriptor.
    let result = key_generations::map_ks_error(keystore2.getKeyEntry(&key_metadata.key));
    assert!(result.is_err());
    assert_eq!(Error::Rc(ResponseCode::INVALID_ARGUMENT), result.unwrap_err());

    // Delete the generated key blob.
    sec_level.deleteKey(&key_metadata.key).unwrap();
}

/// Try to create forced operations with various contexts -
///   - untrusted_app
///   - system_server
///   - priv_app
/// `PERMISSION_DENIED` error response is expected.
#[test]
fn keystore2_forced_op_perm_denied_test() {
    static TARGET_CTXS: &[&str] =
        &["u:r:untrusted_app:s0", "u:r:system_server:s0", "u:r:priv_app:s0"];
    const USER_ID: u32 = 99;
    const APPLICATION_ID: u32 = 10601;

    let uid = USER_ID * AID_USER_OFFSET + APPLICATION_ID;
    let gid = USER_ID * AID_USER_OFFSET + APPLICATION_ID;

    for context in TARGET_CTXS.iter() {
        unsafe {
            run_as::run_as(context, Uid::from_raw(uid), Gid::from_raw(gid), move || {
                let alias = format!("ks_app_forced_op_test_key_{}", getuid());
                let result = key_generations::map_ks_error(create_signing_operation(
                    ForcedOp(true),
                    KeyPurpose::SIGN,
                    Digest::SHA_2_256,
                    Domain::APP,
                    -1,
                    Some(alias),
                ));
                assert!(result.is_err());
                assert_eq!(Error::Rc(ResponseCode::PERMISSION_DENIED), result.unwrap_err());
            });
        }
    }
}

/// Try to create a forced operation with `vold` context.
/// Should be able to create forced operation with `vold` context successfully.
#[test]
fn keystore2_forced_op_success_test() {
    static TARGET_CTX: &str = "u:r:vold:s0";
    const USER_ID: u32 = 99;
    const APPLICATION_ID: u32 = 10601;

    let uid = USER_ID * AID_USER_OFFSET + APPLICATION_ID;
    let gid = USER_ID * AID_USER_OFFSET + APPLICATION_ID;

    unsafe {
        run_as::run_as(TARGET_CTX, Uid::from_raw(uid), Gid::from_raw(gid), move || {
            let alias = format!("ks_vold_forced_op_key_{}", getuid());
            create_signing_operation(
                ForcedOp(true),
                KeyPurpose::SIGN,
                Digest::SHA_2_256,
                Domain::SELINUX,
                key_generations::SELINUX_VOLD_NAMESPACE,
                Some(alias),
            )
            .expect("Client with vold context failed to create forced operation.");
        });
    }
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
