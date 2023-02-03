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

//! Structs and functions about the types used in DICE.
//! This module mirrors the content in open-dice/include/dice/dice.h

use core::ptr;
use open_dice_cbor_bindgen::{
    DiceConfigType, DiceInputValues, DiceMode, DICE_HASH_SIZE, DICE_HIDDEN_SIZE,
    DICE_INLINE_CONFIG_SIZE,
};

/// The size of a DICE hash.
pub const HASH_SIZE: usize = DICE_HASH_SIZE as usize;
/// The size of the DICE hidden value.
pub const HIDDEN_SIZE: usize = DICE_HIDDEN_SIZE as usize;
/// The size of a DICE inline config.
const INLINE_CONFIG_SIZE: usize = DICE_INLINE_CONFIG_SIZE as usize;

/// Array type of hashes used by DICE.
pub type Hash = [u8; HASH_SIZE];
/// Array type of additional input.
pub type Hidden = [u8; HIDDEN_SIZE];
/// Array type of inline configuration values.
pub type InlineConfig = [u8; INLINE_CONFIG_SIZE];

/// Configuration descriptor for DICE input values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Config<'a> {
    /// Reference to an inline descriptor.
    Inline(&'a InlineConfig),
    /// Reference to a free form descriptor that will be hashed by the implementation.
    Descriptor(&'a [u8]),
}

impl Config<'_> {
    fn dice_config_type(&self) -> DiceConfigType {
        match self {
            Self::Inline(_) => DiceConfigType::kDiceConfigTypeInline,
            Self::Descriptor(_) => DiceConfigType::kDiceConfigTypeDescriptor,
        }
    }

    fn inline_config(&self) -> InlineConfig {
        match self {
            Self::Inline(inline) => **inline,
            Self::Descriptor(_) => [0u8; INLINE_CONFIG_SIZE],
        }
    }

    fn descriptor_ptr(&self) -> *const u8 {
        match self {
            Self::Descriptor(descriptor) => descriptor.as_ptr(),
            _ => ptr::null(),
        }
    }

    fn descriptor_size(&self) -> usize {
        match self {
            Self::Descriptor(descriptor) => descriptor.len(),
            _ => 0,
        }
    }
}

/// Wrap of `DiceInputValues`.
#[derive(Clone, Debug)]
pub struct InputValues(DiceInputValues);

impl InputValues {
    /// Creates a new `InputValues`.
    pub fn new(
        code_hash: &Hash,
        code_descriptor: Option<&[u8]>,
        config: Config,
        authority_hash: &Hash,
        authority_descriptor: Option<&[u8]>,
        mode: DiceMode,
        hidden: Option<&Hidden>,
    ) -> Self {
        Self(DiceInputValues {
            code_hash: *code_hash,
            code_descriptor: code_descriptor.map_or(ptr::null(), |d| d.as_ptr()),
            code_descriptor_size: code_descriptor.map_or(0, |d| d.len()),
            config_type: config.dice_config_type(),
            config_value: config.inline_config(),
            config_descriptor: config.descriptor_ptr(),
            config_descriptor_size: config.descriptor_size(),
            authority_hash: *authority_hash,
            authority_descriptor: authority_descriptor.map_or(ptr::null(), |d| d.as_ptr()),
            authority_descriptor_size: authority_descriptor.map_or(0, |d| d.len()),
            mode,
            hidden: hidden.map_or([0; HIDDEN_SIZE], |h| *h),
        })
    }

    /// Returns a raw pointer to the wrapped `DiceInputValues`.
    pub fn as_ptr(&self) -> *const DiceInputValues {
        &self.0 as *const DiceInputValues
    }
}
