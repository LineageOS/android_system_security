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

//! Elliptic curve Diffie–Hellman.

use bssl_crypto::x25519;
use mls_rs_core::crypto::{CipherSuite, HpkePublicKey, HpkeSecretKey};
use mls_rs_core::error::IntoAnyError;
use mls_rs_crypto_traits::{Curve, DhType};

use core::array::TryFromSliceError;
use thiserror::Error;

/// Errors returned from ECDH.
#[derive(Debug, Error)]
pub enum EcdhError {
    /// Error returned when conversion from slice to array fails.
    #[error(transparent)]
    TryFromSliceError(#[from] TryFromSliceError),
    /// Error returned when the public key is invalid.
    #[error("ECDH public key was invalid")]
    InvalidPubKey,
    /// Error returned when the private key length is invalid.
    #[error("ECDH private key of invalid length {len}, expected length {expected_len}")]
    InvalidPrivKeyLen {
        /// Invalid key length.
        len: usize,
        /// Expected key length.
        expected_len: usize,
    },
    /// Error returned when the public key length is invalid.
    #[error("ECDH public key of invalid length {len}, expected length {expected_len}")]
    InvalidPubKeyLen {
        /// Invalid key length.
        len: usize,
        /// Expected key length.
        expected_len: usize,
    },
    /// Error returned when unsupported cipher suite is requested.
    #[error("unsupported cipher suite")]
    UnsupportedCipherSuite,
}

impl IntoAnyError for EcdhError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
}

/// DhType implementation backed by BoringSSL.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ecdh(Curve);

impl Ecdh {
    /// Creates a new Ecdh.
    pub fn new(cipher_suite: CipherSuite) -> Option<Self> {
        Curve::from_ciphersuite(cipher_suite, /*for_sig=*/ false).map(Self)
    }
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(all(target_arch = "wasm32", mls_build_async), maybe_async::must_be_async(?Send))]
#[cfg_attr(all(not(target_arch = "wasm32"), mls_build_async), maybe_async::must_be_async)]
impl DhType for Ecdh {
    type Error = EcdhError;

    async fn dh(
        &self,
        secret_key: &HpkeSecretKey,
        public_key: &HpkePublicKey,
    ) -> Result<Vec<u8>, Self::Error> {
        if self.0 != Curve::X25519 {
            return Err(EcdhError::UnsupportedCipherSuite);
        }
        if secret_key.len() != x25519::PRIVATE_KEY_LEN {
            return Err(EcdhError::InvalidPrivKeyLen {
                len: secret_key.len(),
                expected_len: x25519::PRIVATE_KEY_LEN,
            });
        }
        if public_key.len() != x25519::PUBLIC_KEY_LEN {
            return Err(EcdhError::InvalidPubKeyLen {
                len: public_key.len(),
                expected_len: x25519::PUBLIC_KEY_LEN,
            });
        }

        let private_key = x25519::PrivateKey(secret_key[..x25519::PRIVATE_KEY_LEN].try_into()?);
        match private_key.compute_shared_key(public_key[..x25519::PUBLIC_KEY_LEN].try_into()?) {
            Some(x) => Ok(x.to_vec()),
            None => Err(EcdhError::InvalidPubKey),
        }
    }

    async fn to_public(&self, secret_key: &HpkeSecretKey) -> Result<HpkePublicKey, Self::Error> {
        if self.0 != Curve::X25519 {
            return Err(EcdhError::UnsupportedCipherSuite);
        }
        if secret_key.len() != x25519::PRIVATE_KEY_LEN {
            return Err(EcdhError::InvalidPrivKeyLen {
                len: secret_key.len(),
                expected_len: x25519::PRIVATE_KEY_LEN,
            });
        }

        let private_key = x25519::PrivateKey(secret_key[..x25519::PRIVATE_KEY_LEN].try_into()?);
        Ok(private_key.to_public().to_vec().into())
    }

    async fn generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        if self.0 != Curve::X25519 {
            return Err(EcdhError::UnsupportedCipherSuite);
        }

        let (public_key, private_key) = x25519::PrivateKey::generate();
        Ok((private_key.0.to_vec().into(), public_key.to_vec().into()))
    }

    fn bitmask_for_rejection_sampling(&self) -> Option<u8> {
        self.0.curve_bitmask()
    }

    fn public_key_validate(&self, key: &HpkePublicKey) -> Result<(), Self::Error> {
        if self.0 != Curve::X25519 {
            return Err(EcdhError::UnsupportedCipherSuite);
        }

        // bssl_crypto does not implement validation of curve25519 public keys.
        // Note: Neither does x25519_dalek used by RustCrypto's implementation of this function.
        if key.len() != x25519::PUBLIC_KEY_LEN {
            return Err(EcdhError::InvalidPubKeyLen {
                len: key.len(),
                expected_len: x25519::PUBLIC_KEY_LEN,
            });
        }
        Ok(())
    }

    fn secret_key_size(&self) -> usize {
        self.0.secret_key_size()
    }
}

#[cfg(all(not(mls_build_async), test))]
mod test {
    use super::{DhType, Ecdh, EcdhError};
    use crate::test_helpers::decode_hex;
    use assert_matches::assert_matches;
    use mls_rs_core::crypto::{CipherSuite, HpkePublicKey, HpkeSecretKey};

    #[test]
    fn dh() {
        // https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/x25519_test.json#L23
        let private_key = HpkeSecretKey::from(
            decode_hex::<32>("c8a9d5a91091ad851c668b0736c1c9a02936c0d3ad62670858088047ba057475")
                .to_vec(),
        );
        let public_key = HpkePublicKey::from(
            decode_hex::<32>("504a36999f489cd2fdbc08baff3d88fa00569ba986cba22548ffde80f9806829")
                .to_vec(),
        );
        let expected_shared_secret: [u8; 32] =
            decode_hex("436a2c040cf45fea9b29a0cb81b1f41458f863d0d61b453d0a982720d6d61320");

        let x25519 = Ecdh::new(CipherSuite::CURVE25519_AES128).unwrap();
        assert_eq!(x25519.dh(&private_key, &public_key).unwrap(), expected_shared_secret);
    }

    #[test]
    fn dh_invalid_key() {
        let x25519 = Ecdh::new(CipherSuite::CURVE25519_AES128).unwrap();

        let private_key_short =
            HpkeSecretKey::from(decode_hex::<16>("c8a9d5a91091ad851c668b0736c1c9a0").to_vec());
        let public_key = HpkePublicKey::from(
            decode_hex::<32>("504a36999f489cd2fdbc08baff3d88fa00569ba986cba22548ffde80f9806829")
                .to_vec(),
        );
        assert_matches!(
            x25519.dh(&private_key_short, &public_key),
            Err(EcdhError::InvalidPrivKeyLen { .. })
        );

        let private_key = HpkeSecretKey::from(
            decode_hex::<32>("c8a9d5a91091ad851c668b0736c1c9a02936c0d3ad62670858088047ba057475")
                .to_vec(),
        );
        let public_key_short =
            HpkePublicKey::from(decode_hex::<16>("504a36999f489cd2fdbc08baff3d88fa").to_vec());
        assert_matches!(
            x25519.dh(&private_key, &public_key_short),
            Err(EcdhError::InvalidPubKeyLen { .. })
        );
    }

    #[test]
    fn to_public() {
        // https://www.rfc-editor.org/rfc/rfc7748.html#section-6.1
        let private_key = HpkeSecretKey::from(
            decode_hex::<32>("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
                .to_vec(),
        );
        let expected_public_key = HpkePublicKey::from(
            decode_hex::<32>("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
                .to_vec(),
        );

        let x25519 = Ecdh::new(CipherSuite::CURVE25519_CHACHA).unwrap();
        assert_eq!(x25519.to_public(&private_key).unwrap(), expected_public_key);
    }

    #[test]
    fn to_public_invalid_key() {
        let private_key_short =
            HpkeSecretKey::from(decode_hex::<16>("c8a9d5a91091ad851c668b0736c1c9a0").to_vec());

        let x25519 = Ecdh::new(CipherSuite::CURVE25519_CHACHA).unwrap();
        assert_matches!(
            x25519.to_public(&private_key_short),
            Err(EcdhError::InvalidPrivKeyLen { .. })
        );
    }

    #[test]
    fn generate() {
        let x25519 = Ecdh::new(CipherSuite::CURVE25519_AES128).unwrap();
        assert!(x25519.generate().is_ok());
    }

    #[test]
    fn public_key_validate() {
        // https://www.rfc-editor.org/rfc/rfc7748.html#section-6.1
        let public_key = HpkePublicKey::from(
            decode_hex::<32>("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
                .to_vec(),
        );

        let x25519 = Ecdh::new(CipherSuite::CURVE25519_AES128).unwrap();
        assert!(x25519.public_key_validate(&public_key).is_ok());
    }

    #[test]
    fn public_key_validate_invalid_key() {
        let public_key_short =
            HpkePublicKey::from(decode_hex::<16>("504a36999f489cd2fdbc08baff3d88fa").to_vec());

        let x25519 = Ecdh::new(CipherSuite::CURVE25519_AES128).unwrap();
        assert_matches!(
            x25519.public_key_validate(&public_key_short),
            Err(EcdhError::InvalidPubKeyLen { .. })
        );
    }

    #[test]
    fn unsupported_cipher_suites() {
        for suite in vec![
            CipherSuite::P256_AES128,
            CipherSuite::P384_AES256,
            CipherSuite::P521_AES256,
            CipherSuite::CURVE448_CHACHA,
            CipherSuite::CURVE448_AES256,
        ] {
            assert_matches!(
                Ecdh::new(suite).unwrap().generate(),
                Err(EcdhError::UnsupportedCipherSuite)
            );
        }
    }
}
