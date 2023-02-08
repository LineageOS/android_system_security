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

use crate::dice::{Hash, HASH_SIZE};
use crate::error::{check_result, Result};
use open_dice_cbor_bindgen::DiceHash;
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
