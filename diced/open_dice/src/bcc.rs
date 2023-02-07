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

//! This module mirrors the content in open-dice/include/dice/android/bcc.h

use crate::error::{check_result, Result};
use open_dice_bcc_bindgen::{
    BccConfigValues, BccFormatConfigDescriptor, BCC_INPUT_COMPONENT_NAME,
    BCC_INPUT_COMPONENT_VERSION, BCC_INPUT_RESETTABLE,
};
use std::{ffi::CStr, ptr};

/// Formats a configuration descriptor following the BCC's specification.
/// See https://cs.android.com/android/platform/superproject/+/master:hardware/interfaces/security/rkp/aidl/android/hardware/security/keymint/ProtectedData.aidl
pub fn bcc_format_config_descriptor(
    name: Option<&CStr>,
    version: Option<u64>,
    resettable: bool,
    buffer: &mut [u8],
) -> Result<usize> {
    let mut inputs = 0;
    if name.is_some() {
        inputs |= BCC_INPUT_COMPONENT_NAME;
    }
    if version.is_some() {
        inputs |= BCC_INPUT_COMPONENT_VERSION;
    }
    if resettable {
        inputs |= BCC_INPUT_RESETTABLE;
    }

    let values = BccConfigValues {
        inputs,
        component_name: name.map_or(ptr::null(), |p| p.as_ptr()),
        component_version: version.unwrap_or(0),
    };

    let mut buffer_size = 0;
    // SAFETY: The function writes to the buffer, within the given bounds, and only reads the
    // input values. It writes its result to buffer_size.
    check_result(unsafe {
        BccFormatConfigDescriptor(&values, buffer.len(), buffer.as_mut_ptr(), &mut buffer_size)
    })?;
    Ok(buffer_size)
}
