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

use nix::unistd::{Gid, Uid};
use serde::{Deserialize, Serialize};

use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    BlockMode::BlockMode, Digest::Digest, ErrorCode::ErrorCode,
    KeyParameterValue::KeyParameterValue, KeyPurpose::KeyPurpose, PaddingMode::PaddingMode,
    SecurityLevel::SecurityLevel, Tag::Tag,
};
use android_system_keystore2::aidl::android::system::keystore2::{
    CreateOperationResponse::CreateOperationResponse, Domain::Domain,
    IKeystoreOperation::IKeystoreOperation, IKeystoreSecurityLevel::IKeystoreSecurityLevel,
    KeyDescriptor::KeyDescriptor, KeyParameters::KeyParameters, ResponseCode::ResponseCode,
};

use keystore2_test_utils::{
    authorizations, get_keystore_service, key_generations, key_generations::Error, run_as,
};

/// This enum is used to communicate between parent and child processes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TestOutcome {
    Ok,
    BackendBusy,
    InvalidHandle,
    OtherErr,
}

/// This is used to notify the child or parent process that the expected state is reched.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BarrierReached;

/// Forced operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForcedOp(pub bool);

/// Sample plain text input for encrypt operation.
pub const SAMPLE_PLAIN_TEXT: &[u8] = b"my message 11111";

/// Generate a EC_P256 key using given domain, namespace and alias.
/// Create an operation using the generated key and perform sample signing operation.
pub fn create_signing_operation(
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

/// Performs sample signing operation.
pub fn perform_sample_sign_operation(
    op: &binder::Strong<dyn IKeystoreOperation>,
) -> Result<(), binder::Status> {
    op.update(b"my message")?;
    let sig = op.finish(None, None)?;
    assert!(sig.is_some());
    Ok(())
}

/// Create new operation on child proc and perform simple operation after parent notification.
pub fn execute_op_run_as_child(
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

/// Get NONCE value from given key parameters list.
pub fn get_op_nonce(parameters: &KeyParameters) -> Option<Vec<u8>> {
    for key_param in &parameters.keyParameter {
        if key_param.tag == Tag::NONCE {
            if let KeyParameterValue::Blob(val) = &key_param.value {
                return Some(val.clone());
            }
        }
    }
    None
}

/// This performs sample encryption operation with given symmetric key (AES/3DES).
pub fn perform_sample_sym_key_encrypt_op(
    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
    padding_mode: PaddingMode,
    block_mode: BlockMode,
    nonce: &mut Option<Vec<u8>>,
    mac_len: Option<i32>,
    key: &KeyDescriptor,
) -> binder::Result<Option<Vec<u8>>> {
    let mut op_params = authorizations::AuthSetBuilder::new()
        .purpose(KeyPurpose::ENCRYPT)
        .padding_mode(padding_mode)
        .block_mode(block_mode);
    if let Some(value) = nonce {
        op_params = op_params.nonce(value.to_vec());
    }

    if let Some(val) = mac_len {
        op_params = op_params.mac_length(val);
    }

    let op_response = sec_level.createOperation(key, &op_params, false)?;
    assert!(op_response.iOperation.is_some());
    let op = op_response.iOperation.unwrap();
    if op_response.parameters.is_some() && nonce.is_none() {
        *nonce = get_op_nonce(&op_response.parameters.unwrap());
    }
    op.finish(Some(SAMPLE_PLAIN_TEXT), None)
}

/// This performs sample decryption operation with given symmetric key (AES/3DES).
pub fn perform_sample_sym_key_decrypt_op(
    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
    input: &[u8],
    padding_mode: PaddingMode,
    block_mode: BlockMode,
    nonce: &mut Option<Vec<u8>>,
    mac_len: Option<i32>,
    key: &KeyDescriptor,
) -> binder::Result<Option<Vec<u8>>> {
    let mut op_params = authorizations::AuthSetBuilder::new()
        .purpose(KeyPurpose::DECRYPT)
        .padding_mode(padding_mode)
        .block_mode(block_mode);
    if let Some(value) = nonce {
        op_params = op_params.nonce(value.to_vec());
    }

    if let Some(val) = mac_len {
        op_params = op_params.mac_length(val);
    }

    let op_response = sec_level.createOperation(key, &op_params, false)?;
    assert!(op_response.iOperation.is_some());
    let op = op_response.iOperation.unwrap();
    op.finish(Some(input), None)
}
