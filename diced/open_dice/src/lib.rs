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

//! Implements safe wrappers around the public API of libopen-dice for
//! both std and nostd usages.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate core as std;

mod bcc;
mod dice;
mod error;
#[cfg(feature = "std")]
mod retry;

pub use bcc::bcc_format_config_descriptor;
pub use dice::{
    Cdi, Config, DiceMode, Hash, Hidden, InlineConfig, InputValues, CDI_SIZE, HASH_SIZE,
    HIDDEN_SIZE,
};
pub use error::{check_result, DiceError, Result};
#[cfg(feature = "std")]
pub use retry::retry_bcc_format_config_descriptor;
