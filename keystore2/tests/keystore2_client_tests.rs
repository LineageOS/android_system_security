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
    Digest::Digest, KeyPurpose::KeyPurpose, SecurityLevel::SecurityLevel,
};
use android_system_keystore2::aidl::android::system::keystore2::{
    Domain::Domain, ResponseCode::ResponseCode,
};

use keystore2_test_utils::authorizations;
use keystore2_test_utils::get_keystore_service;
use keystore2_test_utils::key_generations;
use keystore2_test_utils::run_as;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
enum TestOutcome {
    Ok,
    BackendBusy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct BarrierReached;

fn create_op_run_as_child(
    target_ctx: &'static str,
    auid: Uid,
    agid: Gid,
    forced_op: bool,
) -> run_as::ChildHandle<TestOutcome, BarrierReached> {
    unsafe {
        run_as::run_as_child(target_ctx, auid, agid, move |reader, writer| {
            let keystore2 = get_keystore_service();
            let sec_level = keystore2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
            let alias = format!("ks_prune_op_test_key_{}", getuid());
            let key_metadata = key_generations::generate_ec_p256_signing_key(
                &sec_level,
                Domain::APP,
                key_generations::SELINUX_SHELL_NAMESPACE,
                Some(alias),
                None,
                None,
            )
            .unwrap();

            let result = sec_level.createOperation(
                &key_metadata.key,
                &authorizations::AuthSetBuilder::new()
                    .purpose(KeyPurpose::SIGN)
                    .digest(Digest::SHA_2_256),
                forced_op,
            );

            // At this point the result must be `BACKEND_BUSY` or `Ok`.
            let outcome = match &result {
                Ok(_) => TestOutcome::Ok,
                Err(s) if s.service_specific_error() == ResponseCode::BACKEND_BUSY.0 => {
                    TestOutcome::BackendBusy
                }
                Err(e) => panic!("createOperation returned unexpected err: {:?}", e),
            };

            // Let the parent know that an operation has been started, then
            // wait until the parent notifies us to continue, so the operation
            // remains open.
            writer.send(&BarrierReached {});
            reader.recv();

            outcome
        })
        .expect("Failed to create child proc.")
    }
}

fn create_operations(
    target_ctx: &'static str,
    forced_op: bool,
    max_ops: i32,
) -> Vec<run_as::ChildHandle<TestOutcome, BarrierReached>> {
    let base_gid = 99 * AID_USER_OFFSET + 10001;
    let base_uid = 99 * AID_USER_OFFSET + 10001;
    (0..max_ops)
        .into_iter()
        .map(|i| {
            create_op_run_as_child(
                target_ctx,
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
    let forced_op = false;

    let mut child_handles = create_operations(TARGET_CTX, forced_op, MAX_OPS);

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
