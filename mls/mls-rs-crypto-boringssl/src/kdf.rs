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

//! Key derivation function.

use bssl_crypto::digest;
use bssl_crypto::hkdf::{HkdfSha256, HkdfSha512, Prk, Salt};
use mls_rs_core::crypto::CipherSuite;
use mls_rs_core::error::IntoAnyError;
use mls_rs_crypto_traits::{KdfId, KdfType};
use thiserror::Error;

/// Errors returned from KDF.
#[derive(Debug, Error)]
pub enum KdfError {
    /// Error returned when the input key material (IKM) is too short.
    #[error("KDF IKM of length {len}, expected length at least {min_len}")]
    TooShortIkm {
        /// Invalid IKM length.
        len: usize,
        /// Minimum IKM length.
        min_len: usize,
    },
    /// Error returned when the pseudorandom key (PRK) is too short.
    #[error("KDF PRK of length {len}, expected length at least {min_len}")]
    TooShortPrk {
        /// Invalid PRK length.
        len: usize,
        /// Minimum PRK length.
        min_len: usize,
    },
    /// Error returned when the output key material (OKM) requested it too long.
    #[error("KDF OKM of length {len} requested, expected length at most {max_len}")]
    TooLongOkm {
        /// Invalid OKM length.
        len: usize,
        /// Maximum OKM length.
        max_len: usize,
    },
    /// Error returned when unsupported cipher suite is requested.
    #[error("unsupported cipher suite")]
    UnsupportedCipherSuite,
}

impl IntoAnyError for KdfError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
}

/// KdfType implementation backed by BoringSSL.
#[derive(Clone)]
pub struct Kdf(KdfId);

impl Kdf {
    /// Creates a new Kdf.
    pub fn new(cipher_suite: CipherSuite) -> Option<Self> {
        KdfId::new(cipher_suite).map(Self)
    }
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(all(target_arch = "wasm32", mls_build_async), maybe_async::must_be_async(?Send))]
#[cfg_attr(all(not(target_arch = "wasm32"), mls_build_async), maybe_async::must_be_async)]
impl KdfType for Kdf {
    type Error = KdfError;

    async fn extract(&self, salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>, KdfError> {
        if ikm.is_empty() {
            return Err(KdfError::TooShortIkm { len: 0, min_len: 1 });
        }

        let salt = if salt.is_empty() { Salt::None } else { Salt::NonEmpty(salt) };

        match self.0 {
            KdfId::HkdfSha256 => {
                Ok(HkdfSha256::extract(ikm, salt).as_bytes()[..self.extract_size()].to_vec())
            }
            KdfId::HkdfSha512 => {
                Ok(HkdfSha512::extract(ikm, salt).as_bytes()[..self.extract_size()].to_vec())
            }
            _ => Err(KdfError::UnsupportedCipherSuite),
        }
    }

    async fn expand(&self, prk: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, KdfError> {
        if prk.len() < self.extract_size() {
            return Err(KdfError::TooShortPrk { len: prk.len(), min_len: self.extract_size() });
        }

        match self.0 {
            KdfId::HkdfSha256 => match Prk::new::<digest::Sha256>(prk) {
                Some(hkdf) => {
                    let mut out = vec![0; len];
                    match hkdf.expand_into(info, &mut out) {
                        Ok(_) => Ok(out),
                        Err(_) => {
                            Err(KdfError::TooLongOkm { len, max_len: HkdfSha256::MAX_OUTPUT_LEN })
                        }
                    }
                }
                None => Err(KdfError::TooShortPrk { len: prk.len(), min_len: self.extract_size() }),
            },
            KdfId::HkdfSha512 => match Prk::new::<digest::Sha512>(prk) {
                Some(hkdf) => {
                    let mut out = vec![0; len];
                    match hkdf.expand_into(info, &mut out) {
                        Ok(_) => Ok(out),
                        Err(_) => {
                            Err(KdfError::TooLongOkm { len, max_len: HkdfSha512::MAX_OUTPUT_LEN })
                        }
                    }
                }
                None => Err(KdfError::TooShortPrk { len: prk.len(), min_len: self.extract_size() }),
            },
            _ => Err(KdfError::UnsupportedCipherSuite),
        }
    }

    fn extract_size(&self) -> usize {
        self.0.extract_size()
    }

    fn kdf_id(&self) -> u16 {
        self.0 as u16
    }
}

#[cfg(all(not(mls_build_async), test))]
mod test {
    use super::{Kdf, KdfError, KdfType};
    use crate::test_helpers::decode_hex;
    use assert_matches::assert_matches;
    use bssl_crypto::hkdf::{HkdfSha256, HkdfSha512};
    use mls_rs_core::crypto::CipherSuite;

    #[test]
    fn sha256() {
        // https://www.rfc-editor.org/rfc/rfc5869.html#appendix-A.1
        let salt: [u8; 13] = decode_hex("000102030405060708090a0b0c");
        let ikm: [u8; 22] = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let info: [u8; 10] = decode_hex("f0f1f2f3f4f5f6f7f8f9");
        let expected_prk: [u8; 32] =
            decode_hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        let expected_okm: [u8; 42] = decode_hex(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        );

        let kdf = Kdf::new(CipherSuite::CURVE25519_AES128).unwrap();
        let prk = kdf.extract(&salt, &ikm).unwrap();
        assert_eq!(prk, expected_prk);
        assert_eq!(kdf.expand(&prk, &info, 42).unwrap(), expected_okm);
    }

    #[test]
    fn sha512() {
        // https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/hkdf_sha512_test.json#L141
        let salt: [u8; 16] = decode_hex("1d6f3b38a1e607b5e6bcd4af1800a9d3");
        let ikm: [u8; 16] = decode_hex("5d3db20e8238a90b62a600fa57fdb318");
        let info: [u8; 20] = decode_hex("2bc5f39032b6fc87da69ba8711ce735b169646fd");
        let expected_okm: [u8; 42] = decode_hex(
            "8c3cf7122dcb5eb7efaf02718f1faf70bca20dcb75070e9d0871a413a6c05fc195a75aa9ffc349d70aae",
        );

        let kdf = Kdf::new(CipherSuite::CURVE448_CHACHA).unwrap();
        let prk = kdf.extract(&salt, &ikm).unwrap();
        assert_eq!(kdf.expand(&prk, &info, 42).unwrap(), expected_okm);
    }

    #[test]
    fn sha256_extract_short_ikm() {
        let kdf = Kdf::new(CipherSuite::CURVE25519_AES128).unwrap();
        assert_matches!(kdf.extract(b"salty", b""), Err(KdfError::TooShortIkm { .. }));
    }

    #[test]
    fn sha256_expand_short_prk() {
        let prk_short: [u8; 16] = decode_hex("077709362c2e32df0ddc3f0dc47bba63");
        let info: [u8; 10] = decode_hex("f0f1f2f3f4f5f6f7f8f9");

        let kdf = Kdf::new(CipherSuite::CURVE25519_AES128).unwrap();
        assert_matches!(kdf.expand(&prk_short, &info, 42), Err(KdfError::TooShortPrk { .. }));
    }

    #[test]
    fn sha256_expand_long_okm() {
        // https://www.rfc-editor.org/rfc/rfc5869.html#appendix-A.1
        let prk: [u8; 32] =
            decode_hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        let info: [u8; 10] = decode_hex("f0f1f2f3f4f5f6f7f8f9");

        let kdf = Kdf::new(CipherSuite::CURVE25519_AES128).unwrap();
        assert_matches!(
            kdf.expand(&prk, &info, HkdfSha256::MAX_OUTPUT_LEN + 1),
            Err(KdfError::TooLongOkm { .. })
        );
    }

    #[test]
    fn sha512_extract_short_ikm() {
        let kdf = Kdf::new(CipherSuite::CURVE448_CHACHA).unwrap();
        assert_matches!(kdf.extract(b"salty", b""), Err(KdfError::TooShortIkm { .. }));
    }

    #[test]
    fn sha512_expand_short_prk() {
        let prk_short: [u8; 16] = decode_hex("077709362c2e32df0ddc3f0dc47bba63");
        let info: [u8; 10] = decode_hex("f0f1f2f3f4f5f6f7f8f9");

        let kdf = Kdf::new(CipherSuite::CURVE448_CHACHA).unwrap();
        assert_matches!(kdf.expand(&prk_short, &info, 42), Err(KdfError::TooShortPrk { .. }));
    }

    #[test]
    fn sha512_expand_long_okm() {
        // https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/hkdf_sha512_test.json#L141
        let salt: [u8; 16] = decode_hex("1d6f3b38a1e607b5e6bcd4af1800a9d3");
        let ikm: [u8; 16] = decode_hex("5d3db20e8238a90b62a600fa57fdb318");
        let info: [u8; 20] = decode_hex("2bc5f39032b6fc87da69ba8711ce735b169646fd");

        let kdf_sha512 = Kdf::new(CipherSuite::CURVE448_CHACHA).unwrap();
        let prk = kdf_sha512.extract(&salt, &ikm).unwrap();
        assert_matches!(
            kdf_sha512.expand(&prk, &info, HkdfSha512::MAX_OUTPUT_LEN + 1),
            Err(KdfError::TooLongOkm { .. })
        );
    }

    #[test]
    fn unsupported_cipher_suites() {
        let ikm: [u8; 22] = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt: [u8; 13] = decode_hex("000102030405060708090a0b0c");

        assert_matches!(
            Kdf::new(CipherSuite::P384_AES256).unwrap().extract(&salt, &ikm),
            Err(KdfError::UnsupportedCipherSuite)
        );
    }
}
