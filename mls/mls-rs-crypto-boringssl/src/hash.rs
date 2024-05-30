// Copyright 2024, The Android Open Source Project
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

//! Hash functions and hash-based message authentication codes.

use bssl_crypto::digest;
use bssl_crypto::hmac::{HmacSha256, HmacSha512};
use mls_rs_core::crypto::CipherSuite;
use thiserror::Error;

/// Errors returned from hash functions and HMACs.
#[derive(Debug, Error)]
pub enum HashError {
    /// Error returned when unsupported cipher suite is requested.
    #[error("unsupported cipher suite")]
    UnsupportedCipherSuite,
}

/// Hash function and HMAC implementations backed by BoringSSL.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Hash {
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

impl Hash {
    /// Creates a new Hash.
    pub fn new(cipher_suite: CipherSuite) -> Result<Self, HashError> {
        match cipher_suite {
            CipherSuite::CURVE25519_AES128
            | CipherSuite::P256_AES128
            | CipherSuite::CURVE25519_CHACHA => Ok(Hash::Sha256),
            CipherSuite::P384_AES256 => Ok(Hash::Sha384),
            CipherSuite::CURVE448_AES256
            | CipherSuite::CURVE448_CHACHA
            | CipherSuite::P521_AES256 => Ok(Hash::Sha512),
            _ => Err(HashError::UnsupportedCipherSuite),
        }
    }

    /// Hashes `data`.
    pub fn hash(&self, data: &[u8]) -> Vec<u8> {
        match self {
            Hash::Sha256 => digest::Sha256::hash(data).to_vec(),
            Hash::Sha384 => digest::Sha384::hash(data).to_vec(),
            Hash::Sha512 => digest::Sha512::hash(data).to_vec(),
        }
    }

    /// Computes the HMAC of `data` using `key`.
    pub fn mac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, HashError> {
        match self {
            Hash::Sha256 => Ok(HmacSha256::mac(key, data).to_vec()),
            Hash::Sha384 => Err(HashError::UnsupportedCipherSuite),
            Hash::Sha512 => Ok(HmacSha512::mac(key, data).to_vec()),
        }
    }
}

#[cfg(all(not(mls_build_async), test))]
mod test {
    use super::{Hash, HashError};
    use crate::test_helpers::decode_hex;
    use assert_matches::assert_matches;
    use mls_rs_core::crypto::CipherSuite;

    // bssl_crypto::hmac test vectors.

    #[test]
    fn sha256() {
        let hash = Hash::new(CipherSuite::P256_AES128).unwrap();
        assert_eq!(
            hash.hash(&decode_hex::<4>("74ba2521")),
            decode_hex::<32>("b16aa56be3880d18cd41e68384cf1ec8c17680c45a02b1575dc1518923ae8b0e")
        );
    }

    #[test]
    fn sha384() {
        let hash = Hash::new(CipherSuite::P384_AES256).unwrap();
        assert_eq!(
            hash.hash(b"abc"),
            decode_hex::<48>("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7")
        );
    }

    #[test]
    fn sha512() {
        let hash = Hash::new(CipherSuite::CURVE448_CHACHA).unwrap();
        assert_eq!(
            hash.hash(&decode_hex::<4>("23be86d5")),
            decode_hex::<64>(concat!(
                "76d42c8eadea35a69990c63a762f330614a4699977f058adb988f406fb0be8f2",
                "ea3dce3a2bbd1d827b70b9b299ae6f9e5058ee97b50bd4922d6d37ddc761f8eb"
            ))
        );
    }

    #[test]
    fn hmac_sha256() {
        let expected = vec![
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0xb,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x0, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ];
        let key: [u8; 20] = [0x0b; 20];
        let data = b"Hi There";

        let hmac = Hash::new(CipherSuite::CURVE25519_AES128).unwrap();
        assert_eq!(expected, hmac.mac(&key, data).unwrap());
    }

    #[test]
    fn hmac_sha384() {
        let key: [u8; 20] = [0x0b; 20];
        let data = b"Hi There";

        let hmac = Hash::new(CipherSuite::P384_AES256).unwrap();
        assert_matches!(hmac.mac(&key, data), Err(HashError::UnsupportedCipherSuite));
    }

    #[test]
    fn hmac_sha512() {
        let expected = vec![
            135, 170, 124, 222, 165, 239, 97, 157, 79, 240, 180, 36, 26, 29, 108, 176, 35, 121,
            244, 226, 206, 78, 194, 120, 122, 208, 179, 5, 69, 225, 124, 222, 218, 168, 51, 183,
            214, 184, 167, 2, 3, 139, 39, 78, 174, 163, 244, 228, 190, 157, 145, 78, 235, 97, 241,
            112, 46, 105, 108, 32, 58, 18, 104, 84,
        ];
        let key: [u8; 20] = [0x0b; 20];
        let data = b"Hi There";

        let hmac = Hash::new(CipherSuite::CURVE448_CHACHA).unwrap();
        assert_eq!(expected, hmac.mac(&key, data).unwrap());
    }
}
