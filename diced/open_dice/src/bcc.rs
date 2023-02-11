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

use crate::dice::{Cdi, CdiValues, InputValues};
use crate::error::{check_result, Result};
use open_dice_bcc_bindgen::{
    BccConfigValues, BccFormatConfigDescriptor, BccMainFlow, BCC_INPUT_COMPONENT_NAME,
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

/// Executes the main BCC flow.
///
/// Given a full set of input values along with the current BCC and CDI values,
/// computes the next CDI values and matching updated BCC.
pub fn bcc_main_flow(
    current_cdi_attest: &Cdi,
    current_cdi_seal: &Cdi,
    current_bcc: &[u8],
    input_values: &InputValues,
    next_cdi_values: &mut CdiValues,
    next_bcc: &mut [u8],
) -> Result<usize> {
    let mut next_bcc_size = 0;
    // SAFETY: `BccMainFlow` only reads the current `bcc` and CDI values and writes
    // to `next_bcc` and next CDI values within its bounds. It also reads
    // `input_values` as a constant input and doesn't store any pointer.
    // The first argument can be null and is not used in the current implementation.
    check_result(unsafe {
        BccMainFlow(
            ptr::null_mut(), // context
            current_cdi_attest.as_ptr(),
            current_cdi_seal.as_ptr(),
            current_bcc.as_ptr(),
            current_bcc.len(),
            input_values.as_ptr(),
            next_bcc.len(),
            next_bcc.as_mut_ptr(),
            &mut next_bcc_size,
            next_cdi_values.cdi_attest.as_mut_ptr(),
            next_cdi_values.cdi_seal.as_mut_ptr(),
        )
    })?;
    Ok(next_bcc_size)
}
