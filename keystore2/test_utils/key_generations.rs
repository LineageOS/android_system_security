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

//! This module implements test utils to generate various types of keys.

use anyhow::Result;

use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    Algorithm::Algorithm, BlockMode::BlockMode, Digest::Digest, EcCurve::EcCurve,
    ErrorCode::ErrorCode, KeyOrigin::KeyOrigin, KeyParameter::KeyParameter,
    KeyParameterValue::KeyParameterValue, KeyPurpose::KeyPurpose, PaddingMode::PaddingMode,
    Tag::Tag,
};
use android_system_keystore2::aidl::android::system::keystore2::{
    Authorization::Authorization, Domain::Domain, IKeystoreSecurityLevel::IKeystoreSecurityLevel,
    KeyDescriptor::KeyDescriptor, KeyMetadata::KeyMetadata, ResponseCode::ResponseCode,
};

use crate::authorizations::AuthSetBuilder;
use android_system_keystore2::binder::{ExceptionCode, Result as BinderResult};

/// Shell namespace.
pub const SELINUX_SHELL_NAMESPACE: i64 = 1;
/// Vold namespace.
pub const SELINUX_VOLD_NAMESPACE: i64 = 100;

/// SU context.
pub const TARGET_SU_CTX: &str = "u:r:su:s0";

/// Vold context
pub const TARGET_VOLD_CTX: &str = "u:r:vold:s0";

/// Key parameters to generate a key.
pub struct KeyParams {
    /// Key Size.
    pub key_size: i32,
    /// Key Purposes.
    pub purpose: Vec<KeyPurpose>,
    /// Padding Mode.
    pub padding: Option<PaddingMode>,
    /// Digest.
    pub digest: Option<Digest>,
    /// MFG Digest.
    pub mgf_digest: Option<Digest>,
    /// Block Mode.
    pub block_mode: Option<BlockMode>,
    /// Attestation challenge.
    pub att_challenge: Option<Vec<u8>>,
    /// Attestation app id.
    pub att_app_id: Option<Vec<u8>>,
}

/// DER-encoded PKCS#8 format RSA key. Generated using:
/// openssl genrsa 2048 | openssl pkcs8 -topk8 -nocrypt -outform der | hexdump -e '30/1  "%02X" "\n"'
pub static RSA_2048_KEY: &[u8] = &[
    0x30, 0x82, 0x04, 0xBD, 0x02, 0x01, 0x00, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7,
    0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x82, 0x04, 0xA7, 0x30, 0x82, 0x04, 0xA3, 0x02, 0x01,
    0x00, 0x02, 0x82, 0x01, 0x01, 0x00, 0xE5, 0x14, 0xE3, 0xC2, 0x43, 0xF3, 0x0F, 0xCC, 0x22, 0x73,
    0x9C, 0x84, 0xCC, 0x1B, 0x6C, 0x97, 0x4B, 0xC9, 0xDF, 0x1F, 0xE2, 0xB8, 0x80, 0x85, 0xF9, 0x27,
    0xAB, 0x97, 0x94, 0x58, 0x4B, 0xC9, 0x40, 0x94, 0x5A, 0xB4, 0xD4, 0xF8, 0xD0, 0x36, 0xC4, 0x86,
    0x17, 0x7D, 0xA2, 0x48, 0x6D, 0x40, 0xF0, 0xB9, 0x61, 0x4F, 0xCE, 0x65, 0x80, 0x88, 0x81, 0x59,
    0x95, 0x11, 0x24, 0xF4, 0x36, 0xB7, 0xB7, 0x37, 0x44, 0xF4, 0x6C, 0x1C, 0xEB, 0x04, 0x19, 0x78,
    0xB2, 0x29, 0x4D, 0x21, 0x44, 0x16, 0x57, 0x58, 0x6D, 0x7D, 0x56, 0xB5, 0x99, 0xDD, 0xD2, 0xAD,
    0x02, 0x9A, 0x72, 0x16, 0x67, 0xD6, 0x00, 0x9F, 0x69, 0xE0, 0x25, 0xEE, 0x7C, 0x86, 0x54, 0x27,
    0x4B, 0x50, 0xEF, 0x60, 0x52, 0x60, 0x82, 0xAA, 0x09, 0x15, 0x72, 0xD2, 0xEB, 0x01, 0x52, 0x04,
    0x39, 0x60, 0xBC, 0x5E, 0x95, 0x07, 0xC8, 0xC2, 0x3A, 0x3A, 0xE2, 0xA4, 0x99, 0x6B, 0x27, 0xE3,
    0xA3, 0x55, 0x69, 0xC4, 0xB3, 0x2D, 0x19, 0xC4, 0x34, 0x76, 0xFC, 0x27, 0xDA, 0x22, 0xB2, 0x62,
    0x69, 0x25, 0xDE, 0x0D, 0xE7, 0x54, 0x3C, 0xBB, 0x61, 0xD2, 0x20, 0xDA, 0x7B, 0x6E, 0x63, 0xBD,
    0x9A, 0x4B, 0xCD, 0x75, 0xC6, 0xA1, 0x5E, 0x1C, 0x3E, 0xD5, 0x63, 0x59, 0x22, 0x7E, 0xE0, 0x6C,
    0x98, 0x25, 0x63, 0x97, 0x56, 0xDF, 0x71, 0xF5, 0x4C, 0x78, 0xE9, 0xE1, 0xD5, 0xFC, 0xF8, 0x5A,
    0x5B, 0xF6, 0x1D, 0xFA, 0x5A, 0x99, 0x4C, 0x99, 0x19, 0x21, 0x1D, 0xF5, 0x24, 0x07, 0xEF, 0x8A,
    0xC9, 0x9F, 0xE7, 0x3F, 0xBB, 0x46, 0x1A, 0x16, 0x96, 0xC6, 0xD6, 0x12, 0x7E, 0xDA, 0xCB, 0xEB,
    0x2F, 0x1D, 0x3B, 0x31, 0xCC, 0x55, 0x63, 0xA2, 0x6F, 0x8A, 0xDE, 0x35, 0x52, 0x40, 0x04, 0xBF,
    0xE0, 0x82, 0x32, 0xE1, 0x6D, 0x8B, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x82, 0x01, 0x00, 0x2D,
    0x1F, 0x71, 0x41, 0x79, 0xBA, 0xED, 0xD8, 0xAA, 0xCC, 0x94, 0xFE, 0xFF, 0x69, 0x43, 0x79, 0x85,
    0xBF, 0x2C, 0xC9, 0x0E, 0x12, 0x83, 0x96, 0x60, 0x1E, 0x75, 0x49, 0x35, 0x3A, 0x33, 0x2B, 0x60,
    0x22, 0x18, 0xBF, 0xD7, 0xD7, 0x6E, 0xC3, 0xEA, 0xEF, 0xF2, 0xBE, 0x97, 0x71, 0xA6, 0xBB, 0x8C,
    0xEF, 0x27, 0x00, 0xDE, 0x49, 0xD6, 0x08, 0x8D, 0x5A, 0x04, 0xE7, 0xCC, 0x9C, 0xA2, 0x0E, 0x8B,
    0xF3, 0x42, 0x0C, 0xD7, 0x22, 0xD7, 0x14, 0x06, 0xA4, 0x64, 0x8B, 0x88, 0x1A, 0xCE, 0x5B, 0x8C,
    0x36, 0xE9, 0xD2, 0x2F, 0x7B, 0x33, 0xE4, 0xA2, 0xB3, 0xDB, 0x78, 0x6A, 0x92, 0x89, 0x3F, 0x78,
    0xFD, 0xED, 0x8F, 0xEE, 0x48, 0xCC, 0x94, 0x75, 0x0D, 0x0C, 0x63, 0xD3, 0xD2, 0xE8, 0x47, 0x04,
    0x55, 0xD3, 0xD6, 0x3A, 0xB8, 0xDA, 0xFB, 0x76, 0x99, 0x48, 0x68, 0x0A, 0x92, 0xA2, 0xCD, 0xF7,
    0x45, 0x8B, 0x50, 0xFE, 0xF9, 0x1A, 0x33, 0x24, 0x3C, 0x2E, 0xDE, 0x88, 0xAD, 0xB2, 0x5B, 0x9F,
    0x44, 0xEA, 0xD1, 0x9F, 0xC7, 0x9F, 0x02, 0x5E, 0x31, 0x61, 0xB3, 0xD6, 0xE2, 0xE1, 0xBC, 0xFB,
    0x1C, 0xDB, 0xBD, 0xB2, 0x9A, 0xE5, 0xEF, 0xDA, 0xCD, 0x29, 0xA5, 0x45, 0xCC, 0x67, 0x01, 0x8B,
    0x1C, 0x1D, 0x0E, 0x8F, 0x73, 0x69, 0x4D, 0x4D, 0xF6, 0x9D, 0xA6, 0x6C, 0x9A, 0x1C, 0xF4, 0x5C,
    0xE4, 0x83, 0x9A, 0x77, 0x12, 0x01, 0xBD, 0xCE, 0x66, 0x3A, 0x4B, 0x3D, 0x6E, 0xE0, 0x6E, 0x82,
    0x98, 0xDE, 0x74, 0x11, 0x47, 0xEC, 0x7A, 0x3A, 0xA9, 0xD8, 0x48, 0x00, 0x26, 0x64, 0x47, 0x7B,
    0xAE, 0x55, 0x9D, 0x29, 0x22, 0xB4, 0xB3, 0xB9, 0xB1, 0x64, 0xEA, 0x3B, 0x5A, 0xD3, 0x3F, 0x8D,
    0x0F, 0x14, 0x7E, 0x4E, 0xB8, 0x1B, 0x06, 0xFC, 0xB1, 0x7E, 0xCD, 0xB9, 0x1A, 0x4E, 0xA1, 0x02,
    0x81, 0x81, 0x00, 0xF9, 0xDE, 0xEE, 0xED, 0x13, 0x2F, 0xBB, 0xE7, 0xE2, 0xB3, 0x2D, 0x98, 0xD2,
    0xE8, 0x25, 0x07, 0x5A, 0x1E, 0x51, 0x0A, 0xC8, 0xAD, 0x50, 0x4B, 0x80, 0xC6, 0x22, 0xF5, 0x9B,
    0x08, 0xE6, 0x3D, 0x01, 0xC6, 0x3E, 0xC8, 0xD2, 0x54, 0x9F, 0x91, 0x77, 0x95, 0xCD, 0xCA, 0xC7,
    0xE7, 0x47, 0x94, 0xA9, 0x5F, 0x4E, 0xBE, 0x31, 0x3D, 0xB4, 0xAF, 0x43, 0x0F, 0xDC, 0x8D, 0x9C,
    0x1E, 0x52, 0x7B, 0x72, 0x21, 0x34, 0xB3, 0x96, 0x7C, 0x9C, 0xB8, 0x51, 0x65, 0x60, 0xAC, 0x3D,
    0x11, 0x32, 0xB8, 0xD6, 0x34, 0x35, 0x66, 0xD0, 0x30, 0xB9, 0xE9, 0x67, 0x2C, 0x87, 0x73, 0x43,
    0x9C, 0x12, 0x16, 0x7D, 0x4A, 0xD9, 0xA3, 0x4C, 0x24, 0x64, 0x6A, 0x32, 0x8E, 0xC3, 0xD8, 0x00,
    0x90, 0x5C, 0x4D, 0x65, 0x01, 0x53, 0x8A, 0xD0, 0x87, 0xCE, 0x96, 0xEF, 0xFA, 0x73, 0x03, 0xF1,
    0xDC, 0x1B, 0x9B, 0x02, 0x81, 0x81, 0x00, 0xEA, 0xB3, 0x69, 0x00, 0x11, 0x0E, 0x50, 0xAA, 0xD3,
    0x22, 0x51, 0x78, 0x9D, 0xFF, 0x05, 0x62, 0xBC, 0x9A, 0x67, 0x86, 0xE1, 0xC5, 0x02, 0x2D, 0x14,
    0x11, 0x29, 0x30, 0xE7, 0x90, 0x5D, 0x72, 0x6F, 0xC5, 0x62, 0xEB, 0xD4, 0xB0, 0x3F, 0x3D, 0xDC,
    0xB9, 0xFC, 0x2B, 0x5C, 0xBD, 0x9E, 0x71, 0x81, 0x5C, 0xC5, 0xFE, 0xDF, 0x69, 0x73, 0x12, 0x66,
    0x92, 0x06, 0xD4, 0xD5, 0x8F, 0xDF, 0x14, 0x2E, 0x9C, 0xD0, 0x4C, 0xC2, 0x4D, 0x31, 0x2E, 0x47,
    0xA5, 0xDC, 0x8A, 0x83, 0x7B, 0xE8, 0xA5, 0xC3, 0x03, 0x98, 0xD8, 0xBF, 0xF4, 0x7D, 0x6E, 0x87,
    0x55, 0xE4, 0x0F, 0x15, 0x10, 0xC8, 0x76, 0x4F, 0xAD, 0x1D, 0x1C, 0x95, 0x41, 0x9D, 0x88, 0xEC,
    0x8C, 0xDA, 0xBA, 0x90, 0x7F, 0x8D, 0xD9, 0x8B, 0x47, 0x6C, 0x0C, 0xFF, 0xBA, 0x73, 0x00, 0x20,
    0x1F, 0xF7, 0x7E, 0x5F, 0xF4, 0xEC, 0xD1, 0x02, 0x81, 0x80, 0x16, 0xB7, 0x43, 0xB5, 0x5D, 0xD7,
    0x2B, 0x18, 0x0B, 0xAE, 0x0A, 0x69, 0x28, 0x53, 0x5E, 0x7A, 0x6A, 0xA0, 0xF2, 0xF1, 0x2E, 0x09,
    0x43, 0x91, 0x79, 0xA5, 0x89, 0xAC, 0x16, 0x6A, 0x1A, 0xB4, 0x55, 0x22, 0xF6, 0xB6, 0x3F, 0x18,
    0xDE, 0x60, 0xD5, 0x24, 0x53, 0x4F, 0x2A, 0x19, 0x46, 0x92, 0xA7, 0x4B, 0x38, 0xD7, 0x65, 0x96,
    0x9C, 0x84, 0x8A, 0x6E, 0x38, 0xB8, 0xCF, 0x06, 0x9A, 0xAD, 0x0A, 0x55, 0x26, 0x7B, 0x65, 0x24,
    0xF3, 0x02, 0x76, 0xB3, 0xE6, 0xB4, 0x01, 0xE1, 0x3C, 0x61, 0x3D, 0x68, 0x05, 0xAA, 0xD1, 0x26,
    0x7C, 0xE0, 0x51, 0x36, 0xE5, 0x21, 0x7F, 0x76, 0x02, 0xD6, 0xF4, 0x91, 0x07, 0x74, 0x27, 0x09,
    0xEF, 0xEF, 0x0F, 0xA5, 0x96, 0xFC, 0x5E, 0x20, 0xC1, 0xA3, 0x6F, 0x99, 0x4D, 0x45, 0x03, 0x6C,
    0x35, 0x45, 0xD7, 0x8F, 0x47, 0x41, 0x86, 0x8D, 0x62, 0x1D, 0x02, 0x81, 0x81, 0x00, 0xC3, 0x93,
    0x85, 0xA7, 0xFC, 0x8E, 0x85, 0x42, 0x14, 0x76, 0xC0, 0x95, 0x56, 0x73, 0xB0, 0xB5, 0x3A, 0x9D,
    0x20, 0x30, 0x11, 0xEA, 0xED, 0x89, 0x4A, 0xF3, 0x91, 0xF3, 0xA2, 0xC3, 0x76, 0x5B, 0x6A, 0x30,
    0x7D, 0xE2, 0x2F, 0x76, 0x3E, 0xFC, 0xF9, 0xF6, 0x31, 0xE0, 0xA0, 0x83, 0x92, 0x88, 0xDB, 0x57,
    0xC7, 0xD6, 0x3F, 0xAD, 0xCB, 0xAA, 0x45, 0xB6, 0xE1, 0xE2, 0x71, 0xA4, 0x56, 0x2C, 0xA7, 0x3B,
    0x1D, 0x89, 0x19, 0x50, 0xE1, 0xEE, 0xC2, 0xDD, 0xC0, 0x0D, 0xDC, 0xCB, 0x60, 0x6E, 0xE1, 0x37,
    0x1A, 0x23, 0x64, 0xB2, 0x03, 0xE4, 0x1A, 0xFA, 0xC3, 0xF4, 0x9D, 0x85, 0x42, 0xC6, 0xF4, 0x56,
    0x39, 0xB0, 0x1B, 0xE0, 0x75, 0xBA, 0x28, 0x04, 0xA8, 0x30, 0x57, 0x41, 0x33, 0x9F, 0x58, 0xA4,
    0xC7, 0xB1, 0x7D, 0x58, 0x8D, 0x84, 0x49, 0x40, 0xDA, 0x28, 0x81, 0x25, 0xC4, 0x41, 0x02, 0x81,
    0x80, 0x13, 0x20, 0x65, 0xD5, 0x96, 0x98, 0x8D, 0x16, 0x73, 0xA1, 0x31, 0x73, 0x79, 0xBA, 0xEC,
    0xB0, 0xD9, 0x0C, 0xF6, 0xEF, 0x2F, 0xC2, 0xE7, 0x96, 0x9B, 0xA1, 0x2D, 0xE9, 0xFB, 0x45, 0xB9,
    0xD0, 0x30, 0xE2, 0xBD, 0x30, 0x4F, 0xB6, 0xFE, 0x24, 0x02, 0xCF, 0x8D, 0x51, 0x48, 0x45, 0xD9,
    0xF7, 0x20, 0x53, 0x1C, 0x0B, 0xA9, 0x7E, 0xC2, 0xA2, 0x65, 0xCC, 0x3E, 0x0E, 0x0D, 0xF1, 0x62,
    0xDD, 0x5F, 0xBC, 0x55, 0x9B, 0x58, 0x26, 0x40, 0x6A, 0xEE, 0x02, 0x55, 0x36, 0xE9, 0xBA, 0x82,
    0x5A, 0xFD, 0x3C, 0xDF, 0xA6, 0x26, 0x32, 0x81, 0xA9, 0x5E, 0x46, 0xBE, 0xBA, 0xDC, 0xD3, 0x2A,
    0x3A, 0x3B, 0xC1, 0x4E, 0xF7, 0x1A, 0xDC, 0x4B, 0xAF, 0x67, 0x1B, 0x3A, 0x83, 0x0D, 0x04, 0xDE,
    0x27, 0x47, 0xFC, 0xE6, 0x39, 0x89, 0x7B, 0x66, 0xF9, 0x50, 0x4D, 0xF1, 0xAC, 0x20, 0x43, 0x7E,
    0xEE,
];

/// DER-encoded PKCS#8 format EC key. Generated using:
/// openssl ecparam -name prime256v1 -genkey | openssl pkcs8 -topk8 -nocrypt -outform der | hexdump -e '30/1  "%02X" "\n"'
pub static EC_P_256_KEY: &[u8] = &[
    0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02,
    0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x04, 0x6D, 0x30, 0x6B, 0x02,
    0x01, 0x01, 0x04, 0x20, 0xB9, 0x1D, 0xAF, 0x50, 0xFD, 0xD8, 0x6A, 0x40, 0xAB, 0x2C, 0xCB, 0x54,
    0x4E, 0xED, 0xF1, 0x64, 0xBC, 0x30, 0x25, 0xFB, 0xC4, 0x69, 0x00, 0x34, 0x1A, 0x82, 0xA3, 0x72,
    0x5D, 0xC7, 0xA9, 0x85, 0xA1, 0x44, 0x03, 0x42, 0x00, 0x04, 0xE8, 0x53, 0x0A, 0xF2, 0xD3, 0x68,
    0x40, 0x48, 0x8C, 0xB4, 0x2F, 0x11, 0x34, 0xD7, 0xF4, 0x4A, 0x5C, 0x33, 0xFF, 0xF6, 0x2B, 0xF7,
    0x98, 0x0F, 0x02, 0xA5, 0xD7, 0x4F, 0xF9, 0xDE, 0x60, 0x9C, 0x6E, 0xB0, 0x45, 0xDA, 0x3F, 0xF4,
    0x34, 0x23, 0x9B, 0x4C, 0x3A, 0x09, 0x9C, 0x5E, 0x5D, 0x37, 0x96, 0xAC, 0x4A, 0xE7, 0x65, 0x2B,
    0xD6, 0x84, 0x98, 0xEA, 0x96, 0x91, 0xFB, 0x78, 0xED, 0x86,
];

/// To map Keystore errors.
#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub enum Error {
    /// Keystore2 error code
    #[error("ResponseCode {0:?}")]
    Rc(ResponseCode),
    /// Keymint error code
    #[error("ErrorCode {0:?}")]
    Km(ErrorCode),
    /// Exception
    #[error("Binder exception {0:?}")]
    Binder(ExceptionCode),
    /// This is returned if the C implementation of extractSubjectFromCertificate failed.
    #[error("Failed to validate certificate chain.")]
    ValidateCertChainFailed,
}

/// Keystore2 error mapping.
pub fn map_ks_error<T>(r: BinderResult<T>) -> Result<T, Error> {
    r.map_err(|s| {
        match s.exception_code() {
            ExceptionCode::SERVICE_SPECIFIC => {
                match s.service_specific_error() {
                    se if se < 0 => {
                        // Negative service specific errors are KM error codes.
                        Error::Km(ErrorCode(se))
                    }
                    se => {
                        // Positive service specific errors are KS response codes.
                        Error::Rc(ResponseCode(se))
                    }
                }
            }
            // We create `Error::Binder` to preserve the exception code
            // for logging.
            e_code => Error::Binder(e_code),
        }
    })
}

/// Generate EC Key using given security level and domain with below key parameters and
/// optionally allow the generated key to be attested with factory provisioned attest key using
/// given challenge and application id -
///     Purposes: SIGN and VERIFY
///     Digest: SHA_2_256
///     Curve: P_256
pub fn generate_ec_p256_signing_key(
    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
    domain: Domain,
    nspace: i64,
    alias: Option<String>,
    att_challenge: Option<&[u8]>,
    att_app_id: Option<&[u8]>,
) -> binder::Result<KeyMetadata> {
    let mut key_attest = false;
    let mut gen_params = AuthSetBuilder::new()
        .no_auth_required()
        .algorithm(Algorithm::EC)
        .purpose(KeyPurpose::SIGN)
        .purpose(KeyPurpose::VERIFY)
        .digest(Digest::SHA_2_256)
        .ec_curve(EcCurve::P_256);

    if let Some(challenge) = att_challenge {
        key_attest = true;
        gen_params = gen_params.clone().attestation_challenge(challenge.to_vec());
    }

    if let Some(app_id) = att_app_id {
        key_attest = true;
        gen_params = gen_params.clone().attestation_app_id(app_id.to_vec());
    }

    match sec_level.generateKey(
        &KeyDescriptor { domain, nspace, alias, blob: None },
        None,
        &gen_params,
        0,
        b"entropy",
    ) {
        Ok(key_metadata) => {
            assert!(key_metadata.certificate.is_some());
            if key_attest {
                assert!(key_metadata.certificateChain.is_some());
            }
            if domain == Domain::BLOB {
                assert!(key_metadata.key.blob.is_some());
            }

            Ok(key_metadata)
        }
        Err(e) => Err(e),
    }
}

/// Generate EC signing key.
pub fn generate_ec_key(
    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
    domain: Domain,
    nspace: i64,
    alias: Option<String>,
    ec_curve: EcCurve,
    digest: Digest,
) -> binder::Result<KeyMetadata> {
    let gen_params = AuthSetBuilder::new()
        .no_auth_required()
        .algorithm(Algorithm::EC)
        .purpose(KeyPurpose::SIGN)
        .purpose(KeyPurpose::VERIFY)
        .digest(digest)
        .ec_curve(ec_curve);

    let key_metadata = sec_level.generateKey(
        &KeyDescriptor { domain, nspace, alias, blob: None },
        None,
        &gen_params,
        0,
        b"entropy",
    )?;

    // Must have a public key.
    assert!(key_metadata.certificate.is_some());

    // Should not have an attestation record.
    assert!(key_metadata.certificateChain.is_none());

    if domain == Domain::BLOB {
        assert!(key_metadata.key.blob.is_some());
    } else {
        assert!(key_metadata.key.blob.is_none());
    }
    Ok(key_metadata)
}

/// Generate a RSA key with the given key parameters, alias, domain and namespace.
pub fn generate_rsa_key(
    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
    domain: Domain,
    nspace: i64,
    alias: Option<String>,
    key_params: &KeyParams,
    attest_key: Option<&KeyDescriptor>,
) -> binder::Result<KeyMetadata> {
    let mut gen_params = AuthSetBuilder::new()
        .no_auth_required()
        .algorithm(Algorithm::RSA)
        .rsa_public_exponent(65537)
        .key_size(key_params.key_size);

    for purpose in &key_params.purpose {
        gen_params = gen_params.purpose(*purpose);
    }
    if let Some(value) = key_params.digest {
        gen_params = gen_params.digest(value)
    }
    if let Some(value) = key_params.padding {
        gen_params = gen_params.padding_mode(value);
    }
    if let Some(value) = key_params.mgf_digest {
        gen_params = gen_params.mgf_digest(value);
    }
    if let Some(value) = key_params.block_mode {
        gen_params = gen_params.block_mode(value)
    }
    if let Some(value) = &key_params.att_challenge {
        gen_params = gen_params.attestation_challenge(value.to_vec())
    }
    if let Some(value) = &key_params.att_app_id {
        gen_params = gen_params.attestation_app_id(value.to_vec())
    }

    let key_metadata = sec_level.generateKey(
        &KeyDescriptor { domain, nspace, alias, blob: None },
        attest_key,
        &gen_params,
        0,
        b"entropy",
    )?;

    // Must have a public key.
    assert!(key_metadata.certificate.is_some());

    if attest_key.is_none() && key_params.att_challenge.is_some() && key_params.att_app_id.is_some()
    {
        // Should have an attestation record.
        assert!(key_metadata.certificateChain.is_some());
    } else {
        // Should not have an attestation record.
        assert!(key_metadata.certificateChain.is_none());
    }

    assert!(
        (domain == Domain::BLOB && key_metadata.key.blob.is_some())
            || key_metadata.key.blob.is_none()
    );

    Ok(key_metadata)
}

/// Generate AES/3DES key.
pub fn generate_sym_key(
    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
    algorithm: Algorithm,
    size: i32,
    alias: &str,
    padding_mode: &PaddingMode,
    block_mode: &BlockMode,
    min_mac_len: Option<i32>,
) -> binder::Result<KeyMetadata> {
    let mut gen_params = AuthSetBuilder::new()
        .no_auth_required()
        .algorithm(algorithm)
        .purpose(KeyPurpose::ENCRYPT)
        .purpose(KeyPurpose::DECRYPT)
        .key_size(size)
        .padding_mode(*padding_mode)
        .block_mode(*block_mode);

    if let Some(val) = min_mac_len {
        gen_params = gen_params.min_mac_length(val);
    }

    let key_metadata = sec_level.generateKey(
        &KeyDescriptor {
            domain: Domain::APP,
            nspace: -1,
            alias: Some(alias.to_string()),
            blob: None,
        },
        None,
        &gen_params,
        0,
        b"entropy",
    )?;

    // Should not have public certificate.
    assert!(key_metadata.certificate.is_none());

    // Should not have an attestation record.
    assert!(key_metadata.certificateChain.is_none());
    Ok(key_metadata)
}

/// Generate HMAC key.
pub fn generate_hmac_key(
    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
    alias: &str,
    key_size: i32,
    min_mac_len: i32,
    digest: Digest,
) -> binder::Result<KeyMetadata> {
    let gen_params = AuthSetBuilder::new()
        .no_auth_required()
        .algorithm(Algorithm::HMAC)
        .purpose(KeyPurpose::SIGN)
        .purpose(KeyPurpose::VERIFY)
        .key_size(key_size)
        .min_mac_length(min_mac_len)
        .digest(digest);

    let key_metadata = sec_level.generateKey(
        &KeyDescriptor {
            domain: Domain::APP,
            nspace: -1,
            alias: Some(alias.to_string()),
            blob: None,
        },
        None,
        &gen_params,
        0,
        b"entropy",
    )?;

    // Should not have public certificate.
    assert!(key_metadata.certificate.is_none());

    // Should not have an attestation record.
    assert!(key_metadata.certificateChain.is_none());

    Ok(key_metadata)
}

/// Generate RSA or EC attestation keys using below parameters -
///     Purpose: ATTEST_KEY
///     Digest: Digest::SHA_2_256
///     Padding: PaddingMode::RSA_PKCS1_1_5_SIGN
///     RSA-Key-Size: 2048
///     EC-Curve: EcCurve::P_256
pub fn generate_attestation_key(
    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
    algorithm: Algorithm,
    att_challenge: &[u8],
    att_app_id: &[u8],
) -> binder::Result<KeyMetadata> {
    assert!(algorithm == Algorithm::RSA || algorithm == Algorithm::EC);

    if algorithm == Algorithm::RSA {
        let alias = "ks_rsa_attest_test_key";
        let metadata = generate_rsa_key(
            sec_level,
            Domain::APP,
            -1,
            Some(alias.to_string()),
            &KeyParams {
                key_size: 2048,
                purpose: vec![KeyPurpose::ATTEST_KEY],
                padding: Some(PaddingMode::RSA_PKCS1_1_5_SIGN),
                digest: Some(Digest::SHA_2_256),
                mgf_digest: None,
                block_mode: None,
                att_challenge: Some(att_challenge.to_vec()),
                att_app_id: Some(att_app_id.to_vec()),
            },
            None,
        )
        .unwrap();
        Ok(metadata)
    } else {
        let metadata = generate_ec_attestation_key(
            sec_level,
            att_challenge,
            att_app_id,
            Digest::SHA_2_256,
            EcCurve::P_256,
        )
        .unwrap();

        Ok(metadata)
    }
}

/// Generate EC attestation key with the given
///    curve, attestation-challenge and attestation-app-id.
pub fn generate_ec_attestation_key(
    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
    att_challenge: &[u8],
    att_app_id: &[u8],
    digest: Digest,
    ec_curve: EcCurve,
) -> binder::Result<KeyMetadata> {
    let alias = "ks_attest_ec_test_key";
    let gen_params = AuthSetBuilder::new()
        .no_auth_required()
        .algorithm(Algorithm::EC)
        .purpose(KeyPurpose::ATTEST_KEY)
        .ec_curve(ec_curve)
        .digest(digest)
        .attestation_challenge(att_challenge.to_vec())
        .attestation_app_id(att_app_id.to_vec());

    let attestation_key_metadata = sec_level.generateKey(
        &KeyDescriptor {
            domain: Domain::APP,
            nspace: -1,
            alias: Some(alias.to_string()),
            blob: None,
        },
        None,
        &gen_params,
        0,
        b"entropy",
    )?;

    // Should have public certificate.
    assert!(attestation_key_metadata.certificate.is_some());
    // Should have an attestation record.
    assert!(attestation_key_metadata.certificateChain.is_some());

    Ok(attestation_key_metadata)
}

/// Generate EC-P-256 key and attest it with given attestation key.
pub fn generate_ec_256_attested_key(
    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
    alias: Option<String>,
    att_challenge: &[u8],
    att_app_id: &[u8],
    attest_key: &KeyDescriptor,
) -> binder::Result<KeyMetadata> {
    let ec_gen_params = AuthSetBuilder::new()
        .no_auth_required()
        .algorithm(Algorithm::EC)
        .purpose(KeyPurpose::SIGN)
        .purpose(KeyPurpose::VERIFY)
        .digest(Digest::SHA_2_256)
        .ec_curve(EcCurve::P_256)
        .attestation_challenge(att_challenge.to_vec())
        .attestation_app_id(att_app_id.to_vec());

    let ec_key_metadata = sec_level
        .generateKey(
            &KeyDescriptor { domain: Domain::APP, nspace: -1, alias, blob: None },
            Some(attest_key),
            &ec_gen_params,
            0,
            b"entropy",
        )
        .unwrap();

    // Should have public certificate.
    assert!(ec_key_metadata.certificate.is_some());
    // Shouldn't have an attestation record.
    assert!(ec_key_metadata.certificateChain.is_none());

    Ok(ec_key_metadata)
}

fn check_key_param(authorizations: &[Authorization], key_param: KeyParameter) -> bool {
    for authrization in authorizations {
        if authrization.keyParameter == key_param {
            return true;
        }
    }

    false
}

/// Imports above defined RSA key - `RSA_2048_KEY` and validates imported key parameters.
pub fn import_rsa_2048_key(
    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
    domain: Domain,
    nspace: i64,
    alias: Option<String>,
    import_params: AuthSetBuilder,
) -> binder::Result<KeyMetadata> {
    let key_metadata = sec_level
        .importKey(
            &KeyDescriptor { domain, nspace, alias, blob: None },
            None,
            &import_params,
            0,
            RSA_2048_KEY,
        )
        .unwrap();

    assert!(key_metadata.certificate.is_some());
    assert!(key_metadata.certificateChain.is_none());

    assert!(check_key_param(
        &key_metadata.authorizations,
        KeyParameter { tag: Tag::ALGORITHM, value: KeyParameterValue::Algorithm(Algorithm::RSA) }
    ));

    assert!(check_key_param(
        &key_metadata.authorizations,
        KeyParameter { tag: Tag::KEY_SIZE, value: KeyParameterValue::Integer(2048) }
    ));

    assert!(check_key_param(
        &key_metadata.authorizations,
        KeyParameter { tag: Tag::DIGEST, value: KeyParameterValue::Digest(Digest::SHA_2_256) }
    ));

    assert!(check_key_param(
        &key_metadata.authorizations,
        KeyParameter {
            tag: Tag::RSA_PUBLIC_EXPONENT,
            value: KeyParameterValue::LongInteger(65537)
        }
    ));

    assert!(check_key_param(
        &key_metadata.authorizations,
        KeyParameter {
            tag: Tag::PADDING,
            value: KeyParameterValue::PaddingMode(PaddingMode::RSA_PSS)
        }
    ));

    assert!(check_key_param(
        &key_metadata.authorizations,
        KeyParameter { tag: Tag::ORIGIN, value: KeyParameterValue::Origin(KeyOrigin::IMPORTED) }
    ));

    Ok(key_metadata)
}

/// Imports above defined EC key - `EC_P_256_KEY` and validates imported key parameters.
pub fn import_ec_p_256_key(
    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
    domain: Domain,
    nspace: i64,
    alias: Option<String>,
    import_params: AuthSetBuilder,
) -> binder::Result<KeyMetadata> {
    let key_metadata = sec_level
        .importKey(
            &KeyDescriptor { domain, nspace, alias, blob: None },
            None,
            &import_params,
            0,
            EC_P_256_KEY,
        )
        .unwrap();

    assert!(key_metadata.certificate.is_some());
    assert!(key_metadata.certificateChain.is_none());

    assert!(check_key_param(
        &key_metadata.authorizations,
        KeyParameter { tag: Tag::ALGORITHM, value: KeyParameterValue::Algorithm(Algorithm::EC) }
    ));

    assert!(check_key_param(
        &key_metadata.authorizations,
        KeyParameter { tag: Tag::EC_CURVE, value: KeyParameterValue::EcCurve(EcCurve::P_256) }
    ));

    assert!(check_key_param(
        &key_metadata.authorizations,
        KeyParameter { tag: Tag::DIGEST, value: KeyParameterValue::Digest(Digest::SHA_2_256) }
    ));
    assert!(check_key_param(
        &key_metadata.authorizations,
        KeyParameter { tag: Tag::ORIGIN, value: KeyParameterValue::Origin(KeyOrigin::IMPORTED) }
    ));

    Ok(key_metadata)
}

/// Import sample AES key and validate its key parameters.
pub fn import_aes_key(
    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
    domain: Domain,
    nspace: i64,
    alias: Option<String>,
) -> binder::Result<KeyMetadata> {
    static AES_KEY: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let key_size = AES_KEY.len() * 8;

    let import_params = AuthSetBuilder::new()
        .no_auth_required()
        .algorithm(Algorithm::AES)
        .block_mode(BlockMode::ECB)
        .key_size(key_size.try_into().unwrap())
        .purpose(KeyPurpose::ENCRYPT)
        .purpose(KeyPurpose::DECRYPT)
        .padding_mode(PaddingMode::PKCS7);

    let key_metadata = sec_level.importKey(
        &KeyDescriptor { domain, nspace, alias, blob: None },
        None,
        &import_params,
        0,
        AES_KEY,
    )?;

    assert!(check_key_param(
        &key_metadata.authorizations,
        KeyParameter { tag: Tag::ALGORITHM, value: KeyParameterValue::Algorithm(Algorithm::AES) }
    ));
    assert!(check_key_param(
        &key_metadata.authorizations,
        KeyParameter { tag: Tag::KEY_SIZE, value: KeyParameterValue::Integer(128) }
    ));
    assert!(check_key_param(
        &key_metadata.authorizations,
        KeyParameter {
            tag: Tag::PADDING,
            value: KeyParameterValue::PaddingMode(PaddingMode::PKCS7)
        }
    ));
    assert!(check_key_param(
        &key_metadata.authorizations,
        KeyParameter { tag: Tag::BLOCK_MODE, value: KeyParameterValue::BlockMode(BlockMode::ECB) }
    ));
    assert!(check_key_param(
        &key_metadata.authorizations,
        KeyParameter { tag: Tag::ORIGIN, value: KeyParameterValue::Origin(KeyOrigin::IMPORTED) }
    ));

    Ok(key_metadata)
}

/// Import sample 3DES key and validate its key parameters.
pub fn import_3des_key(
    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
    domain: Domain,
    nspace: i64,
    alias: Option<String>,
) -> binder::Result<KeyMetadata> {
    static TRIPLE_DES_KEY: &[u8] = &[
        0xa4, 0x9d, 0x75, 0x64, 0x19, 0x9e, 0x97, 0xcb, 0x52, 0x9d, 0x2c, 0x9d, 0x97, 0xbf, 0x2f,
        0x98, 0xd3, 0x5e, 0xdf, 0x57, 0xba, 0x1f, 0x73, 0x58,
    ];

    let import_params = AuthSetBuilder::new()
        .no_auth_required()
        .algorithm(Algorithm::TRIPLE_DES)
        .block_mode(BlockMode::ECB)
        .key_size(168)
        .purpose(KeyPurpose::ENCRYPT)
        .purpose(KeyPurpose::DECRYPT)
        .padding_mode(PaddingMode::PKCS7);

    let key_metadata = sec_level.importKey(
        &KeyDescriptor { domain, nspace, alias, blob: None },
        None,
        &import_params,
        0,
        TRIPLE_DES_KEY,
    )?;

    assert!(check_key_param(
        &key_metadata.authorizations,
        KeyParameter {
            tag: Tag::ALGORITHM,
            value: KeyParameterValue::Algorithm(Algorithm::TRIPLE_DES)
        }
    ));
    assert!(check_key_param(
        &key_metadata.authorizations,
        KeyParameter { tag: Tag::KEY_SIZE, value: KeyParameterValue::Integer(168) }
    ));
    assert!(check_key_param(
        &key_metadata.authorizations,
        KeyParameter {
            tag: Tag::PADDING,
            value: KeyParameterValue::PaddingMode(PaddingMode::PKCS7)
        }
    ));
    assert!(check_key_param(
        &key_metadata.authorizations,
        KeyParameter { tag: Tag::BLOCK_MODE, value: KeyParameterValue::BlockMode(BlockMode::ECB) }
    ));
    assert!(check_key_param(
        &key_metadata.authorizations,
        KeyParameter { tag: Tag::ORIGIN, value: KeyParameterValue::Origin(KeyOrigin::IMPORTED) }
    ));

    Ok(key_metadata)
}

/// Import sample HMAC key and validate its key parameters.
pub fn import_hmac_key(
    sec_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
    domain: Domain,
    nspace: i64,
    alias: Option<String>,
) -> binder::Result<KeyMetadata> {
    static HMAC_KEY: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let key_size = HMAC_KEY.len() * 8;

    let import_params = AuthSetBuilder::new()
        .no_auth_required()
        .algorithm(Algorithm::HMAC)
        .key_size(key_size.try_into().unwrap())
        .purpose(KeyPurpose::SIGN)
        .purpose(KeyPurpose::VERIFY)
        .digest(Digest::SHA_2_256)
        .min_mac_length(256);

    let key_metadata = sec_level.importKey(
        &KeyDescriptor { domain, nspace, alias, blob: None },
        None,
        &import_params,
        0,
        HMAC_KEY,
    )?;

    assert!(check_key_param(
        &key_metadata.authorizations,
        KeyParameter { tag: Tag::ALGORITHM, value: KeyParameterValue::Algorithm(Algorithm::HMAC) }
    ));
    assert!(check_key_param(
        &key_metadata.authorizations,
        KeyParameter { tag: Tag::KEY_SIZE, value: KeyParameterValue::Integer(128) }
    ));
    assert!(check_key_param(
        &key_metadata.authorizations,
        KeyParameter { tag: Tag::DIGEST, value: KeyParameterValue::Digest(Digest::SHA_2_256) }
    ));
    assert!(check_key_param(
        &key_metadata.authorizations,
        KeyParameter { tag: Tag::ORIGIN, value: KeyParameterValue::Origin(KeyOrigin::IMPORTED) }
    ));

    Ok(key_metadata)
}
