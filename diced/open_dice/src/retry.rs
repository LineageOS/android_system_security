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

//! This module implements a retry version for multiple DICE functions that
//! require preallocated output buffer. As the retry functions require
//! memory allocation on heap, currently we only expose these functions in
//! std environment.

use crate::bcc::bcc_format_config_descriptor;
use crate::error::{DiceError, Result};
use std::ffi::CStr;

/// Retries the given function with bigger output buffer size.
fn retry_with_bigger_buffer<F>(mut f: F) -> Result<Vec<u8>>
where
    F: FnMut(&mut Vec<u8>) -> Result<usize>,
{
    const INITIAL_BUFFER_SIZE: usize = 256;
    const MAX_BUFFER_SIZE: usize = 64 * 1024 * 1024;

    let mut buffer = vec![0u8; INITIAL_BUFFER_SIZE];
    while buffer.len() <= MAX_BUFFER_SIZE {
        match f(&mut buffer) {
            Err(DiceError::BufferTooSmall) => {
                let new_size = buffer.len() * 2;
                buffer.resize(new_size, 0);
            }
            Err(e) => return Err(e),
            Ok(actual_size) => {
                if actual_size > buffer.len() {
                    panic!(
                        "actual_size larger than buffer size: open-dice function
                         may have written past the end of the buffer."
                    );
                }
                buffer.truncate(actual_size);
                return Ok(buffer);
            }
        }
    }
    Err(DiceError::PlatformError)
}

/// Formats a configuration descriptor following the BCC's specification.
pub fn retry_bcc_format_config_descriptor(
    name: Option<&CStr>,
    version: Option<u64>,
    resettable: bool,
) -> Result<Vec<u8>> {
    retry_with_bigger_buffer(|buffer| {
        bcc_format_config_descriptor(name, version, resettable, buffer)
    })
}
