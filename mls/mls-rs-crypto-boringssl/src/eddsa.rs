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

//! Edwards-curve digital signature algorithm.

use bssl_crypto::{ed25519, InvalidSignatureError};
use mls_rs_core::crypto::{CipherSuite, SignaturePublicKey, SignatureSecretKey};
use mls_rs_crypto_traits::Curve;

use core::array::TryFromSliceError;
use thiserror::Error;

/// Errors returned from EdDSA.
#[derive(Debug, Error)]
pub enum EdDsaError {
    /// Error returned when conversion from slice to array fails.
    #[error(transparent)]
    TryFromSliceError(#[from] TryFromSliceError),
    /// Error returned on an invalid signature.
    #[error("invalid signature")]
    InvalidSig(InvalidSignatureError),
    /// Error returned when the private key length is invalid.
    #[error("EdDSA private key of invalid length {len}, expected length {expected_len}")]
    InvalidPrivKeyLen {
        /// Invalid key length.
        len: usize,
        /// Expected key length.
        expected_len: usize,
    },
    /// Error returned when the public key length is invalid.
    #[error("EdDSA public key of invalid length {len}, expected length {expected_len}")]
    InvalidPubKeyLen {
        /// Invalid key length.
        len: usize,
        /// Expected key length.
        expected_len: usize,
    },
    /// Error returned when the signature length is invalid.
    #[error("EdDSA signature of invalid length {len}, expected length {expected_len}")]
    InvalidSigLen {
        /// Invalid signature length.
        len: usize,
        /// Expected signature length.
        expected_len: usize,
    },
    /// Error returned when unsupported cipher suite is requested.
    #[error("unsupported cipher suite")]
    UnsupportedCipherSuite,
}

// Explicitly implemented as InvalidSignatureError's as_dyn_error does not satisfy trait bounds.
impl From<InvalidSignatureError> for EdDsaError {
    fn from(e: InvalidSignatureError) -> Self {
        EdDsaError::InvalidSig(e)
    }
}

/// EdDSA implementation backed by BoringSSL.
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub struct EdDsa(Curve);

impl EdDsa {
    /// Creates a new EdDsa.
    pub fn new(cipher_suite: CipherSuite) -> Option<Self> {
        Curve::from_ciphersuite(cipher_suite, /*for_sig=*/ true).map(Self)
    }

    /// Generates a key pair.
    pub fn signature_key_generate(
        &self,
    ) -> Result<(SignatureSecretKey, SignaturePublicKey), EdDsaError> {
        if self.0 != Curve::Ed25519 {
            return Err(EdDsaError::UnsupportedCipherSuite);
        }

        let private_key = ed25519::PrivateKey::generate();
        let public_key = private_key.to_public();
        Ok((private_key.to_seed().to_vec().into(), public_key.as_bytes().to_vec().into()))
    }

    /// Derives the public key from the private key.
    pub fn signature_key_derive_public(
        &self,
        secret_key: &SignatureSecretKey,
    ) -> Result<SignaturePublicKey, EdDsaError> {
        if self.0 != Curve::Ed25519 {
            return Err(EdDsaError::UnsupportedCipherSuite);
        }
        if secret_key.len() != ed25519::SEED_LEN {
            return Err(EdDsaError::InvalidPrivKeyLen {
                len: secret_key.len(),
                expected_len: ed25519::SEED_LEN,
            });
        }

        let private_key =
            ed25519::PrivateKey::from_seed(secret_key[..ed25519::SEED_LEN].try_into()?);
        Ok(private_key.to_public().as_bytes().to_vec().into())
    }

    /// Signs `data` using `secret_key`.
    pub fn sign(
        &self,
        secret_key: &SignatureSecretKey,
        data: &[u8],
    ) -> Result<Vec<u8>, EdDsaError> {
        if self.0 != Curve::Ed25519 {
            return Err(EdDsaError::UnsupportedCipherSuite);
        }
        if secret_key.len() != ed25519::SEED_LEN {
            return Err(EdDsaError::InvalidPrivKeyLen {
                len: secret_key.len(),
                expected_len: ed25519::SEED_LEN,
            });
        }

        let private_key =
            ed25519::PrivateKey::from_seed(secret_key[..ed25519::SEED_LEN].try_into()?);
        Ok(private_key.sign(data).to_vec())
    }

    /// Verifies `signature` is a valid signature of `data` using `public_key`.
    pub fn verify(
        &self,
        public_key: &SignaturePublicKey,
        signature: &[u8],
        data: &[u8],
    ) -> Result<(), EdDsaError> {
        if self.0 != Curve::Ed25519 {
            return Err(EdDsaError::UnsupportedCipherSuite);
        }
        if public_key.len() != ed25519::PUBLIC_KEY_LEN {
            return Err(EdDsaError::InvalidPubKeyLen {
                len: public_key.len(),
                expected_len: ed25519::PUBLIC_KEY_LEN,
            });
        }
        if signature.len() != ed25519::SIGNATURE_LEN {
            return Err(EdDsaError::InvalidSigLen {
                len: signature.len(),
                expected_len: ed25519::SIGNATURE_LEN,
            });
        }

        let public_key = ed25519::PublicKey::from_bytes(
            public_key.as_bytes()[..ed25519::PUBLIC_KEY_LEN].try_into()?,
        );
        match public_key.verify(data, signature[..ed25519::SIGNATURE_LEN].try_into()?) {
            Ok(_) => Ok(()),
            Err(e) => Err(EdDsaError::InvalidSig(e)),
        }
    }
}

#[cfg(all(not(mls_build_async), test))]
mod test {
    use super::{EdDsa, EdDsaError};
    use crate::test_helpers::decode_hex;
    use assert_matches::assert_matches;
    use mls_rs_core::crypto::{CipherSuite, SignaturePublicKey, SignatureSecretKey};

    #[test]
    fn signature_key_generate() {
        let ed25519 = EdDsa::new(CipherSuite::CURVE25519_AES128).unwrap();
        assert!(ed25519.signature_key_generate().is_ok());
    }

    #[test]
    fn signature_key_derive_public() {
        // Test 1 from https://www.rfc-editor.org/rfc/rfc8032#section-7.1
        let private_key = SignatureSecretKey::from(
            decode_hex::<32>("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .to_vec(),
        );
        let expected_public_key = SignaturePublicKey::from(
            decode_hex::<32>("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .to_vec(),
        );

        let ed25519 = EdDsa::new(CipherSuite::CURVE25519_CHACHA).unwrap();
        assert_eq!(ed25519.signature_key_derive_public(&private_key).unwrap(), expected_public_key);
    }

    #[test]
    fn signature_key_derive_public_invalid_key() {
        let private_key_short =
            SignatureSecretKey::from(decode_hex::<16>("9d61b19deffd5a60ba844af492ec2cc4").to_vec());

        let ed25519 = EdDsa::new(CipherSuite::CURVE25519_CHACHA).unwrap();
        assert_matches!(
            ed25519.signature_key_derive_public(&private_key_short),
            Err(EdDsaError::InvalidPrivKeyLen { .. })
        );
    }

    #[test]
    fn sign_verify() {
        // Test 3 from https://www.rfc-editor.org/rfc/rfc8032#section-7.1
        let private_key = SignatureSecretKey::from(
            decode_hex::<32>("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7")
                .to_vec(),
        );
        let data: [u8; 2] = decode_hex("af82");
        let expected_sig = decode_hex::<64>("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a").to_vec();

        let ed25519 = EdDsa::new(CipherSuite::CURVE25519_AES128).unwrap();
        let sig = ed25519.sign(&private_key, &data).unwrap();
        assert_eq!(sig, expected_sig);

        let public_key = ed25519.signature_key_derive_public(&private_key).unwrap();
        assert!(ed25519.verify(&public_key, &sig, &data).is_ok());
    }

    #[test]
    fn sign_invalid_key() {
        let private_key_short =
            SignatureSecretKey::from(decode_hex::<16>("c5aa8df43f9f837bedb7442f31dcb7b1").to_vec());

        let ed25519 = EdDsa::new(CipherSuite::CURVE25519_AES128).unwrap();
        assert_matches!(
            ed25519.sign(&private_key_short, &decode_hex::<2>("af82")),
            Err(EdDsaError::InvalidPrivKeyLen { .. })
        );
    }

    #[test]
    fn verify_invalid_key() {
        let public_key_short =
            SignaturePublicKey::from(decode_hex::<16>("fc51cd8e6218a1a38da47ed00230f058").to_vec());
        let sig = decode_hex::<64>("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a").to_vec();
        let data: [u8; 2] = decode_hex("af82");

        let ed25519 = EdDsa::new(CipherSuite::CURVE25519_AES128).unwrap();
        assert_matches!(
            ed25519.verify(&public_key_short, &sig, &data),
            Err(EdDsaError::InvalidPubKeyLen { .. })
        );
    }

    #[test]
    fn verify_invalid_sig() {
        let public_key = SignaturePublicKey::from(
            decode_hex::<32>("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025")
                .to_vec(),
        );
        let sig_short =
            decode_hex::<32>("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac")
                .to_vec();
        let data: [u8; 2] = decode_hex("af82");

        let ed25519 = EdDsa::new(CipherSuite::CURVE25519_AES128).unwrap();
        assert_matches!(
            ed25519.verify(&public_key, &sig_short, &data),
            Err(EdDsaError::InvalidSigLen { .. })
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
                EdDsa::new(suite).unwrap().signature_key_generate(),
                Err(EdDsaError::UnsupportedCipherSuite)
            );
        }
    }
}
