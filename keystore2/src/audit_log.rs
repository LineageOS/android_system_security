// Copyright 2021, The Android Open Source Project
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

//! This module implements functions to log audit events to binary security log buffer for NIAP
//! compliance.

use crate::globals::LOGS_HANDLER;
use android_system_keystore2::aidl::android::system::keystore2::{
    Domain::Domain, KeyDescriptor::KeyDescriptor,
};
use libc::uid_t;
use structured_log::{structured_log, LOG_ID_SECURITY};

const TAG_KEY_GENERATED: u32 = 210024;
const TAG_KEY_IMPORTED: u32 = 210025;
const TAG_KEY_DESTROYED: u32 = 210026;
const TAG_KEY_INTEGRITY_VIOLATION: u32 = 210032;

const FLAG_NAMESPACE: i64 = 0x80000000;

/// Encode key owner as either uid or namespace with a flag.
fn key_owner(domain: Domain, nspace: i64, uid: i32) -> i32 {
    match domain {
        Domain::APP => uid,
        Domain::SELINUX => (nspace | FLAG_NAMESPACE) as i32,
        _ => {
            log::info!("Not logging audit event for key with unexpected domain");
            0
        }
    }
}

/// Logs key generation event to NIAP audit log.
pub fn log_key_generated(key: &KeyDescriptor, calling_app: uid_t, success: bool) {
    log_key_event(TAG_KEY_GENERATED, key, calling_app, success);
}

/// Logs key import event to NIAP audit log.
pub fn log_key_imported(key: &KeyDescriptor, calling_app: uid_t, success: bool) {
    log_key_event(TAG_KEY_IMPORTED, key, calling_app, success);
}

/// Logs key deletion event to NIAP audit log.
pub fn log_key_deleted(key: &KeyDescriptor, calling_app: uid_t, success: bool) {
    log_key_event(TAG_KEY_DESTROYED, key, calling_app, success);
}

/// Logs key integrity violation to NIAP audit log.
pub fn log_key_integrity_violation(key: &KeyDescriptor) {
    let owner = key_owner(key.domain, key.nspace, key.nspace as i32);
    let alias = String::from(key.alias.as_ref().map_or("none", String::as_str));
    LOGS_HANDLER.queue_lo(move |_| {
        let _result =
            structured_log!(log_id: LOG_ID_SECURITY, TAG_KEY_INTEGRITY_VIOLATION, alias, owner);
    });
}

fn log_key_event(tag: u32, key: &KeyDescriptor, calling_app: uid_t, success: bool) {
    let owner = key_owner(key.domain, key.nspace, calling_app as i32);
    let alias = String::from(key.alias.as_ref().map_or("none", String::as_str));
    LOGS_HANDLER.queue_lo(move |_| {
        let _result =
            structured_log!(log_id: LOG_ID_SECURITY, tag, i32::from(success), alias, owner);
    });
}
