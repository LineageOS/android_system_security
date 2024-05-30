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

//! Authenticated encryption with additional data.

use bssl_crypto::aead::{Aead, Aes128Gcm, Aes256Gcm, Chacha20Poly1305};
use mls_rs_core::crypto::CipherSuite;
use mls_rs_core::error::IntoAnyError;
use mls_rs_crypto_traits::{AeadId, AeadType, AES_TAG_LEN};

use core::array::TryFromSliceError;
use thiserror::Error;

/// Errors returned from AEAD.
#[derive(Debug, Error)]
pub enum AeadError {
    /// Error returned when conversion from slice to array fails.
    #[error(transparent)]
    TryFromSliceError(#[from] TryFromSliceError),
    /// Error returned when the ciphertext is invalid.
    #[error("AEAD ciphertext was invalid")]
    InvalidCiphertext,
    /// Error returned when the ciphertext length is too short.
    #[error("AEAD ciphertext of length {len}, expected length at least {min_len}")]
    TooShortCiphertext {
        /// Invalid ciphertext length.
        len: usize,
        /// Minimum ciphertext length.
        min_len: usize,
    },
    /// Error returned when the plaintext is empty.
    #[error("message cannot be empty")]
    EmptyPlaintext,
    /// Error returned when the key length is invalid.
    #[error("AEAD key of invalid length {len}, expected length {expected_len}")]
    InvalidKeyLen {
        /// Invalid key length.
        len: usize,
        /// Expected key length.
        expected_len: usize,
    },
    /// Error returned when the nonce size is invalid.
    #[error("AEAD nonce of invalid length {len}, expected length {expected_len}")]
    InvalidNonceLen {
        /// Invalid nonce length.
        len: usize,
        /// Expected nonce length.
        expected_len: usize,
    },
    /// Error returned when unsupported cipher suite is requested.
    #[error("unsupported cipher suite")]
    UnsupportedCipherSuite,
}

impl IntoAnyError for AeadError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
}

/// AeadType implementation backed by BoringSSL.
#[derive(Clone)]
pub struct AeadWrapper(AeadId);

impl AeadWrapper {
    /// Creates a new AeadWrapper.
    pub fn new(cipher_suite: CipherSuite) -> Option<Self> {
        AeadId::new(cipher_suite).map(Self)
    }
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(all(target_arch = "wasm32", mls_build_async), maybe_async::must_be_async(?Send))]
#[cfg_attr(all(not(target_arch = "wasm32"), mls_build_async), maybe_async::must_be_async)]
impl AeadType for AeadWrapper {
    type Error = AeadError;

    async fn seal<'a>(
        &self,
        key: &[u8],
        data: &[u8],
        aad: Option<&'a [u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        if data.is_empty() {
            return Err(AeadError::EmptyPlaintext);
        }
        if key.len() != self.key_size() {
            return Err(AeadError::InvalidKeyLen { len: key.len(), expected_len: self.key_size() });
        }
        if nonce.len() != self.nonce_size() {
            return Err(AeadError::InvalidNonceLen {
                len: nonce.len(),
                expected_len: self.nonce_size(),
            });
        }

        let nonce_array = nonce[..self.nonce_size()].try_into()?;

        match self.0 {
            AeadId::Aes128Gcm => {
                let cipher = Aes128Gcm::new(key[..self.key_size()].try_into()?);
                Ok(cipher.seal(nonce_array, data, aad.unwrap_or_default()))
            }
            AeadId::Aes256Gcm => {
                let cipher = Aes256Gcm::new(key[..self.key_size()].try_into()?);
                Ok(cipher.seal(nonce_array, data, aad.unwrap_or_default()))
            }
            AeadId::Chacha20Poly1305 => {
                let cipher = Chacha20Poly1305::new(key[..self.key_size()].try_into()?);
                Ok(cipher.seal(nonce_array, data, aad.unwrap_or_default()))
            }
            _ => Err(AeadError::UnsupportedCipherSuite),
        }
    }

    async fn open<'a>(
        &self,
        key: &[u8],
        ciphertext: &[u8],
        aad: Option<&'a [u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        if ciphertext.len() < AES_TAG_LEN {
            return Err(AeadError::TooShortCiphertext {
                len: ciphertext.len(),
                min_len: AES_TAG_LEN,
            });
        }
        if key.len() != self.key_size() {
            return Err(AeadError::InvalidKeyLen { len: key.len(), expected_len: self.key_size() });
        }
        if nonce.len() != self.nonce_size() {
            return Err(AeadError::InvalidNonceLen {
                len: nonce.len(),
                expected_len: self.nonce_size(),
            });
        }

        let nonce_array = nonce[..self.nonce_size()].try_into()?;

        match self.0 {
            AeadId::Aes128Gcm => {
                let cipher = Aes128Gcm::new(key[..self.key_size()].try_into()?);
                cipher
                    .open(nonce_array, ciphertext, aad.unwrap_or_default())
                    .ok_or(AeadError::InvalidCiphertext)
            }
            AeadId::Aes256Gcm => {
                let cipher = Aes256Gcm::new(key[..self.key_size()].try_into()?);
                cipher
                    .open(nonce_array, ciphertext, aad.unwrap_or_default())
                    .ok_or(AeadError::InvalidCiphertext)
            }
            AeadId::Chacha20Poly1305 => {
                let cipher = Chacha20Poly1305::new(key[..self.key_size()].try_into()?);
                cipher
                    .open(nonce_array, ciphertext, aad.unwrap_or_default())
                    .ok_or(AeadError::InvalidCiphertext)
            }
            _ => Err(AeadError::UnsupportedCipherSuite),
        }
    }

    #[inline(always)]
    fn key_size(&self) -> usize {
        self.0.key_size()
    }

    fn nonce_size(&self) -> usize {
        self.0.nonce_size()
    }

    fn aead_id(&self) -> u16 {
        self.0 as u16
    }
}

#[cfg(all(not(mls_build_async), test))]
mod test {
    use super::{AeadError, AeadWrapper};
    use assert_matches::assert_matches;
    use mls_rs_core::crypto::CipherSuite;
    use mls_rs_crypto_traits::{AeadType, AES_TAG_LEN};

    fn get_aeads() -> Vec<AeadWrapper> {
        [
            CipherSuite::CURVE25519_AES128,
            CipherSuite::CURVE25519_CHACHA,
            CipherSuite::CURVE448_AES256,
        ]
        .into_iter()
        .map(|suite| AeadWrapper::new(suite).unwrap())
        .collect()
    }

    #[test]
    fn seal_and_open() {
        for aead in get_aeads() {
            let key = vec![42u8; aead.key_size()];
            let nonce = vec![42u8; aead.nonce_size()];
            let plaintext = b"message";

            let ciphertext = aead.seal(&key, plaintext, None, &nonce).unwrap();
            assert_eq!(
                plaintext,
                aead.open(&key, ciphertext.as_slice(), None, &nonce).unwrap().as_slice(),
                "open failed for AEAD with ID {}",
                aead.aead_id(),
            );
        }
    }

    #[test]
    fn seal_and_open_with_invalid_key() {
        for aead in get_aeads() {
            let data = b"top secret data that's long enough";
            let nonce = vec![42u8; aead.nonce_size()];

            let key_short = vec![42u8; aead.key_size() - 1];
            assert_matches!(
                aead.seal(&key_short, data, None, &nonce),
                Err(AeadError::InvalidKeyLen { .. }),
                "seal with short key should fail for AEAD with ID {}",
                aead.aead_id(),
            );
            assert_matches!(
                aead.open(&key_short, data, None, &nonce),
                Err(AeadError::InvalidKeyLen { .. }),
                "open with short key should fail for AEAD with ID {}",
                aead.aead_id(),
            );

            let key_long = vec![42u8; aead.key_size() + 1];
            assert_matches!(
                aead.seal(&key_long, data, None, &nonce),
                Err(AeadError::InvalidKeyLen { .. }),
                "seal with long key should fail for AEAD with ID {}",
                aead.aead_id(),
            );
            assert_matches!(
                aead.open(&key_long, data, None, &nonce),
                Err(AeadError::InvalidKeyLen { .. }),
                "open with long key should fail for AEAD with ID {}",
                aead.aead_id(),
            );
        }
    }

    #[test]
    fn invalid_ciphertext() {
        for aead in get_aeads() {
            let key = vec![42u8; aead.key_size()];
            let nonce = vec![42u8; aead.nonce_size()];

            let ciphertext_short = [0u8; AES_TAG_LEN - 1];
            assert_matches!(
                aead.open(&key, &ciphertext_short, None, &nonce),
                Err(AeadError::TooShortCiphertext { .. }),
                "open with short ciphertext should fail for AEAD with ID {}",
                aead.aead_id(),
            );
        }
    }

    #[test]
    fn associated_data_mismatch() {
        for aead in get_aeads() {
            let key = vec![42u8; aead.key_size()];
            let nonce = vec![42u8; aead.nonce_size()];

            let ciphertext = aead.seal(&key, b"message", Some(b"foo"), &nonce).unwrap();
            assert_matches!(
                aead.open(&key, &ciphertext, Some(b"bar"), &nonce),
                Err(AeadError::InvalidCiphertext),
                "open with incorrect associated data should fail for AEAD with ID {}",
                aead.aead_id(),
            );
            assert_matches!(
                aead.open(&key, &ciphertext, None, &nonce),
                Err(AeadError::InvalidCiphertext),
                "open with incorrect associated data should fail for AEAD with ID {}",
                aead.aead_id(),
            );
        }
    }

    #[test]
    fn invalid_nonce() {
        for aead in get_aeads() {
            let key = vec![42u8; aead.key_size()];
            let data = b"top secret data that's long enough";

            let nonce_short = vec![42u8; aead.nonce_size() - 1];
            assert_matches!(
                aead.seal(&key, data, None, &nonce_short),
                Err(AeadError::InvalidNonceLen { .. }),
                "seal with short nonce should fail for AEAD with ID {}",
                aead.aead_id(),
            );
            assert_matches!(
                aead.open(&key, data, None, &nonce_short),
                Err(AeadError::InvalidNonceLen { .. }),
                "open with short nonce should fail for AEAD with ID {}",
                aead.aead_id(),
            );

            let nonce_long = vec![42u8; aead.nonce_size() + 1];
            assert_matches!(
                aead.seal(&key, data, None, &nonce_long),
                Err(AeadError::InvalidNonceLen { .. }),
                "seal with long nonce should fail for AEAD with ID {}",
                aead.aead_id(),
            );
            assert_matches!(
                aead.open(&key, data, None, &nonce_long),
                Err(AeadError::InvalidNonceLen { .. }),
                "open with long nonce should fail for AEAD with ID {}",
                aead.aead_id(),
            );
        }
    }
}
