// Copyright 2023, The Android Open Source Project
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

//! This module mirrors the content in open-dice/include/dice/ops.h
//! It contains the set of functions that implement various operations that the
//! main DICE functions depend on.

use crate::dice::{Hash, InputValues, HASH_SIZE, PRIVATE_KEY_SEED_SIZE};
use crate::error::{check_result, Result};
use open_dice_cbor_bindgen::{DiceGenerateCertificate, DiceHash, DiceKdf};
use std::ptr;

/// Hashes the provided input using DICE's hash function `DiceHash`.
pub fn hash(input: &[u8]) -> Result<Hash> {
    let mut output: Hash = [0; HASH_SIZE];
    // SAFETY: DiceHash takes a sized input buffer and writes to a constant-sized output buffer.
    // The first argument context is not used in this function.
    check_result(unsafe {
        DiceHash(
            ptr::null_mut(), // context
            input.as_ptr(),
            input.len(),
            output.as_mut_ptr(),
        )
    })?;
    Ok(output)
}

/// An implementation of HKDF-SHA512. Derives a key of `derived_key.len()` bytes from `ikm`, `salt`,
/// and `info`. The derived key is written to the `derived_key`.
pub fn kdf(ikm: &[u8], salt: &[u8], info: &[u8], derived_key: &mut [u8]) -> Result<()> {
    // SAFETY: The function writes to the `derived_key`, within the given bounds, and only reads the
    // input values. The first argument context is not used in this function.
    check_result(unsafe {
        DiceKdf(
            ptr::null_mut(), // context
            derived_key.len(),
            ikm.as_ptr(),
            ikm.len(),
            salt.as_ptr(),
            salt.len(),
            info.as_ptr(),
            info.len(),
            derived_key.as_mut_ptr(),
        )
    })
}

/// Generates an X.509 certificate from the given `subject_private_key_seed` and
/// `input_values`, and signed by `authority_private_key_seed`.
/// The subject private key seed is supplied here so the implementation can choose
/// between asymmetric mechanisms, for example ECDSA vs Ed25519.
/// Returns the actual size of the generated certificate.
pub fn generate_certificate(
    subject_private_key_seed: &[u8; PRIVATE_KEY_SEED_SIZE],
    authority_private_key_seed: &[u8; PRIVATE_KEY_SEED_SIZE],
    input_values: &InputValues,
    certificate: &mut [u8],
) -> Result<usize> {
    let mut certificate_actual_size = 0;
    // SAFETY: The function writes to the `certificate` within the given bounds, and only reads the
    // input values and the key seeds. The first argument context is not used in this function.
    check_result(unsafe {
        DiceGenerateCertificate(
            ptr::null_mut(), // context
            subject_private_key_seed.as_ptr(),
            authority_private_key_seed.as_ptr(),
            input_values.as_ptr(),
            certificate.len(),
            certificate.as_mut_ptr(),
            &mut certificate_actual_size,
        )
    })?;
    Ok(certificate_actual_size)
}
