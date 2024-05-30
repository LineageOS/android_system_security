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

//! Implements mls_rs_core's CryptoProvider and CipherSuiteProvider backed by BoringSSL.

pub mod aead;
pub mod ecdh;
pub mod eddsa;
pub mod hash;
pub mod hpke;
pub mod kdf;

#[cfg(test)]
mod test_helpers;

use mls_rs_core::crypto::{
    CipherSuite, CipherSuiteProvider, CryptoProvider, HpkeCiphertext, HpkePublicKey, HpkeSecretKey,
    SignaturePublicKey, SignatureSecretKey,
};
use mls_rs_core::error::{AnyError, IntoAnyError};
use mls_rs_crypto_traits::{AeadType, KdfType, KemType};
use thiserror::Error;
use zeroize::Zeroizing;

use aead::AeadWrapper;
use ecdh::Ecdh;
use eddsa::{EdDsa, EdDsaError};
use hash::{Hash, HashError};
use hpke::{ContextR, ContextS, DhKem, Hpke, HpkeError};
use kdf::Kdf;

/// Errors returned from BoringsslCryptoProvider.
#[derive(Debug, Error)]
pub enum BoringsslCryptoError {
    /// Error returned from hash functions and HMACs.
    #[error(transparent)]
    HashError(#[from] HashError),
    /// Error returned from KEMs.
    #[error(transparent)]
    KemError(AnyError),
    /// Error returned from KDFs.
    #[error(transparent)]
    KdfError(AnyError),
    /// Error returned from AEADs.
    #[error(transparent)]
    AeadError(AnyError),
    /// Error returned from HPKE.
    #[error(transparent)]
    HpkeError(#[from] HpkeError),
    /// Error returned from EdDSA.
    #[error(transparent)]
    EdDsaError(#[from] EdDsaError),
}

impl IntoAnyError for BoringsslCryptoError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
}

/// CryptoProvider trait implementation backed by BoringSSL.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct BoringsslCryptoProvider {
    /// Available cipher suites.
    pub enabled_cipher_suites: Vec<CipherSuite>,
}

impl BoringsslCryptoProvider {
    /// Creates a new BoringsslCryptoProvider.
    pub fn new() -> Self {
        Default::default()
    }

    /// Sets the enabled cipher suites.
    pub fn with_enabled_cipher_suites(enabled_cipher_suites: Vec<CipherSuite>) -> Self {
        Self { enabled_cipher_suites }
    }

    /// Returns all available cipher suites.
    pub fn all_supported_cipher_suites() -> Vec<CipherSuite> {
        vec![CipherSuite::CURVE25519_AES128, CipherSuite::CURVE25519_CHACHA]
    }
}

impl Default for BoringsslCryptoProvider {
    fn default() -> Self {
        Self { enabled_cipher_suites: Self::all_supported_cipher_suites() }
    }
}

impl CryptoProvider for BoringsslCryptoProvider {
    type CipherSuiteProvider = BoringsslCipherSuite<DhKem<Ecdh, Kdf>, Kdf, AeadWrapper>;

    fn supported_cipher_suites(&self) -> Vec<CipherSuite> {
        self.enabled_cipher_suites.clone()
    }

    fn cipher_suite_provider(
        &self,
        cipher_suite: CipherSuite,
    ) -> Option<Self::CipherSuiteProvider> {
        if !self.enabled_cipher_suites.contains(&cipher_suite) {
            return None;
        }

        let ecdh = Ecdh::new(cipher_suite)?;
        let kdf = Kdf::new(cipher_suite)?;
        let kem = DhKem::new(cipher_suite, ecdh, kdf.clone())?;
        let aead = AeadWrapper::new(cipher_suite)?;

        BoringsslCipherSuite::new(cipher_suite, kem, kdf, aead)
    }
}

/// CipherSuiteProvider trait implementation backed by BoringSSL.
#[derive(Clone)]
pub struct BoringsslCipherSuite<KEM, KDF, AEAD>
where
    KEM: KemType + Clone,
    KDF: KdfType + Clone,
    AEAD: AeadType + Clone,
{
    cipher_suite: CipherSuite,
    hash: Hash,
    kem: KEM,
    kdf: KDF,
    aead: AEAD,
    hpke: Hpke,
    eddsa: EdDsa,
}

impl<KEM, KDF, AEAD> BoringsslCipherSuite<KEM, KDF, AEAD>
where
    KEM: KemType + Clone,
    KDF: KdfType + Clone,
    AEAD: AeadType + Clone,
{
    /// Creates a new BoringsslCipherSuite.
    pub fn new(cipher_suite: CipherSuite, kem: KEM, kdf: KDF, aead: AEAD) -> Option<Self> {
        Some(Self {
            cipher_suite,
            hash: Hash::new(cipher_suite).ok()?,
            kem,
            kdf,
            aead,
            hpke: Hpke::new(cipher_suite),
            eddsa: EdDsa::new(cipher_suite)?,
        })
    }

    /// Returns random bytes generated via BoringSSL.
    pub fn random_bytes(&self, out: &mut [u8]) -> Result<(), BoringsslCryptoError> {
        bssl_crypto::rand_bytes(out);
        Ok(())
    }
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(all(target_arch = "wasm32", mls_build_async), maybe_async::must_be_async(?Send))]
#[cfg_attr(all(not(target_arch = "wasm32"), mls_build_async), maybe_async::must_be_async)]
impl<KEM, KDF, AEAD> CipherSuiteProvider for BoringsslCipherSuite<KEM, KDF, AEAD>
where
    KEM: KemType + Clone + Send + Sync,
    KDF: KdfType + Clone + Send + Sync,
    AEAD: AeadType + Clone + Send + Sync,
{
    type Error = BoringsslCryptoError;
    type HpkeContextS = ContextS;
    type HpkeContextR = ContextR;

    fn cipher_suite(&self) -> CipherSuite {
        self.cipher_suite
    }

    fn random_bytes(&self, out: &mut [u8]) -> Result<(), Self::Error> {
        self.random_bytes(out)
    }

    async fn hash(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Ok(self.hash.hash(data))
    }

    async fn mac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Ok(self.hash.mac(key, data)?)
    }

    async fn kem_generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        self.kem.generate().await.map_err(|e| BoringsslCryptoError::KemError(e.into_any_error()))
    }

    async fn kem_derive(&self, ikm: &[u8]) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        self.kem.derive(ikm).await.map_err(|e| BoringsslCryptoError::KemError(e.into_any_error()))
    }

    fn kem_public_key_validate(&self, key: &HpkePublicKey) -> Result<(), Self::Error> {
        self.kem
            .public_key_validate(key)
            .map_err(|e| BoringsslCryptoError::KemError(e.into_any_error()))
    }

    async fn kdf_extract(
        &self,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        self.kdf
            .extract(salt, ikm)
            .await
            .map_err(|e| BoringsslCryptoError::KdfError(e.into_any_error()))
            .map(Zeroizing::new)
    }

    async fn kdf_expand(
        &self,
        prk: &[u8],
        info: &[u8],
        len: usize,
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        self.kdf
            .expand(prk, info, len)
            .await
            .map_err(|e| BoringsslCryptoError::KdfError(e.into_any_error()))
            .map(Zeroizing::new)
    }

    fn kdf_extract_size(&self) -> usize {
        self.kdf.extract_size()
    }

    async fn aead_seal(
        &self,
        key: &[u8],
        data: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        self.aead
            .seal(key, data, aad, nonce)
            .await
            .map_err(|e| BoringsslCryptoError::AeadError(e.into_any_error()))
    }

    async fn aead_open(
        &self,
        key: &[u8],
        cipher_text: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        self.aead
            .open(key, cipher_text, aad, nonce)
            .await
            .map_err(|e| BoringsslCryptoError::AeadError(e.into_any_error()))
            .map(Zeroizing::new)
    }

    fn aead_key_size(&self) -> usize {
        self.aead.key_size()
    }

    fn aead_nonce_size(&self) -> usize {
        self.aead.nonce_size()
    }

    async fn hpke_setup_s(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
    ) -> Result<(Vec<u8>, Self::HpkeContextS), Self::Error> {
        Ok(self.hpke.setup_sender(remote_key, info).await?)
    }

    async fn hpke_seal(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        pt: &[u8],
    ) -> Result<HpkeCiphertext, Self::Error> {
        Ok(self.hpke.seal(remote_key, info, aad, pt).await?)
    }

    async fn hpke_setup_r(
        &self,
        enc: &[u8],
        local_secret: &HpkeSecretKey,
        // Other implementations use `_local_public` to skip derivation of the public from the
        // private key for the KEM decapsulation step, but BoringSSL's API does not accept a public
        // key and instead derives it under the hood.
        _local_public: &HpkePublicKey,
        info: &[u8],
    ) -> Result<Self::HpkeContextR, Self::Error> {
        Ok(self.hpke.setup_receiver(enc, local_secret, info).await?)
    }

    async fn hpke_open(
        &self,
        ciphertext: &HpkeCiphertext,
        local_secret: &HpkeSecretKey,
        // Other implementations use `_local_public` to skip derivation of the public from the
        // private key for hpke_setup_r()'s KEM decapsulation step, but BoringSSL's API does not
        // accept a public key and instead derives it under the hood.
        _local_public: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, Self::Error> {
        Ok(self.hpke.open(ciphertext, local_secret, info, aad).await?)
    }

    async fn signature_key_generate(
        &self,
    ) -> Result<(SignatureSecretKey, SignaturePublicKey), Self::Error> {
        Ok(self.eddsa.signature_key_generate()?)
    }

    async fn signature_key_derive_public(
        &self,
        secret_key: &SignatureSecretKey,
    ) -> Result<SignaturePublicKey, Self::Error> {
        Ok(self.eddsa.signature_key_derive_public(secret_key)?)
    }

    async fn sign(
        &self,
        secret_key: &SignatureSecretKey,
        data: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        Ok(self.eddsa.sign(secret_key, data)?)
    }

    async fn verify(
        &self,
        public_key: &SignaturePublicKey,
        signature: &[u8],
        data: &[u8],
    ) -> Result<(), Self::Error> {
        Ok(self.eddsa.verify(public_key, signature, data)?)
    }
}

#[cfg(all(not(mls_build_async), test))]
mod test {
    use super::BoringsslCryptoProvider;
    use crate::test_helpers::decode_hex;
    use mls_rs_core::crypto::{
        CipherSuite, CipherSuiteProvider, CryptoProvider, HpkeContextR, HpkeContextS,
        HpkePublicKey, HpkeSecretKey, SignaturePublicKey, SignatureSecretKey,
    };

    fn get_cipher_suites() -> Vec<CipherSuite> {
        vec![CipherSuite::CURVE25519_AES128, CipherSuite::CURVE25519_CHACHA]
    }

    #[test]
    fn supported_cipher_suites() {
        let bssl = BoringsslCryptoProvider::new();
        assert_eq!(bssl.supported_cipher_suites().len(), 2);
    }

    #[test]
    fn unsupported_cipher_suites() {
        let bssl = BoringsslCryptoProvider::new();
        for suite in vec![
            CipherSuite::P256_AES128,
            CipherSuite::CURVE448_AES256,
            CipherSuite::P521_AES256,
            CipherSuite::CURVE448_CHACHA,
            CipherSuite::P384_AES256,
        ] {
            assert!(bssl.cipher_suite_provider(suite).is_none());
        }
    }

    #[test]
    fn cipher_suite() {
        let bssl = BoringsslCryptoProvider::new();
        for suite in get_cipher_suites() {
            let crypto = bssl.cipher_suite_provider(suite).unwrap();
            assert_eq!(crypto.cipher_suite(), suite);
        }
    }

    #[test]
    fn random_bytes() {
        let bssl = BoringsslCryptoProvider::new();
        for suite in get_cipher_suites() {
            let crypto = bssl.cipher_suite_provider(suite).unwrap();
            let mut buf = [0; 32];
            let _ = crypto.random_bytes(&mut buf);
        }
    }

    #[test]
    fn hash() {
        let bssl = BoringsslCryptoProvider::new();
        for suite in get_cipher_suites() {
            let crypto = bssl.cipher_suite_provider(suite).unwrap();
            assert_eq!(
                crypto.hash(&decode_hex::<4>("74ba2521")).unwrap(),
                // bssl_crypto::hmac test vector.
                decode_hex::<32>(
                    "b16aa56be3880d18cd41e68384cf1ec8c17680c45a02b1575dc1518923ae8b0e"
                )
            );
        }
    }

    #[test]
    fn mac() {
        let bssl = BoringsslCryptoProvider::new();
        for suite in get_cipher_suites() {
            let crypto = bssl.cipher_suite_provider(suite).unwrap();
            // bssl_crypto::hmac test vector.
            let expected = vec![
                0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0xb,
                0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x0, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
                0x2e, 0x32, 0xcf, 0xf7,
            ];
            let key: [u8; 20] = [0x0b; 20];
            let data = b"Hi There";

            assert_eq!(crypto.mac(&key, data).unwrap(), expected);
        }
    }

    #[test]
    fn kem_generate() {
        let bssl = BoringsslCryptoProvider::new();
        for suite in get_cipher_suites() {
            let crypto = bssl.cipher_suite_provider(suite).unwrap();
            assert!(crypto.kem_generate().is_ok());
        }
    }

    #[test]
    fn kem_derive() {
        let bssl = BoringsslCryptoProvider::new();
        for suite in get_cipher_suites() {
            let crypto = bssl.cipher_suite_provider(suite).unwrap();
            // https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.1.1
            let ikm: [u8; 32] =
                decode_hex("7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234");
            let expected_sk = HpkeSecretKey::from(
                decode_hex::<32>(
                    "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736",
                )
                .to_vec(),
            );
            let expected_pk = HpkePublicKey::from(
                decode_hex::<32>(
                    "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
                )
                .to_vec(),
            );

            let (sk, pk) = crypto.kem_derive(&ikm).unwrap();
            assert_eq!(sk, expected_sk);
            assert_eq!(pk, expected_pk);
        }
    }

    #[test]
    fn kem_public_key_validate() {
        let bssl = BoringsslCryptoProvider::new();
        for suite in get_cipher_suites() {
            let crypto = bssl.cipher_suite_provider(suite).unwrap();
            // https://www.rfc-editor.org/rfc/rfc7748.html#section-6.1
            let public_key = HpkePublicKey::from(
                decode_hex::<32>(
                    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
                )
                .to_vec(),
            );
            assert!(crypto.kem_public_key_validate(&public_key).is_ok());
        }
    }

    #[test]
    fn kdf_extract_and_expand() {
        let bssl = BoringsslCryptoProvider::new();
        for suite in get_cipher_suites() {
            let crypto = bssl.cipher_suite_provider(suite).unwrap();
            // https://www.rfc-editor.org/rfc/rfc5869.html#appendix-A.1
            let ikm: [u8; 22] = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
            let salt: [u8; 13] = decode_hex("000102030405060708090a0b0c");
            let info: [u8; 10] = decode_hex("f0f1f2f3f4f5f6f7f8f9");
            let expected_prk: [u8; 32] =
                decode_hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
            let expected_okm : [u8; 42] = decode_hex(
                    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
                );

            let prk = crypto.kdf_extract(&salt, &ikm).unwrap();
            assert_eq!(prk.as_ref(), expected_prk);
            assert_eq!(crypto.kdf_expand(&prk.as_ref(), &info, 42).unwrap().as_ref(), expected_okm);
        }
    }

    #[test]
    fn kdf_extract_size() {
        let bssl = BoringsslCryptoProvider::new();
        for suite in get_cipher_suites() {
            let crypto = bssl.cipher_suite_provider(suite).unwrap();
            assert_eq!(crypto.kdf_extract_size(), 32);
        }
    }

    #[test]
    fn aead() {
        let bssl = BoringsslCryptoProvider::new();
        for suite in get_cipher_suites() {
            let crypto = bssl.cipher_suite_provider(suite).unwrap();
            let key = vec![42u8; crypto.aead_key_size()];
            let associated_data = vec![42u8, 12];
            let nonce = vec![42u8; crypto.aead_nonce_size()];
            let plaintext = b"message";

            let ciphertext =
                crypto.aead_seal(&key, plaintext, Some(&associated_data), &nonce).unwrap();
            assert_eq!(
                plaintext,
                crypto
                    .aead_open(&key, ciphertext.as_slice(), Some(&associated_data), &nonce)
                    .unwrap()
                    .as_slice()
            );
        }
    }

    #[test]
    fn hpke_setup_seal_open_export() {
        let bssl = BoringsslCryptoProvider::new();
        for suite in get_cipher_suites() {
            let crypto = bssl.cipher_suite_provider(suite).unwrap();
            // https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.1.1
            let receiver_pub_key = HpkePublicKey::from(
                decode_hex::<32>(
                    "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",
                )
                .to_vec(),
            );
            let receiver_priv_key = HpkeSecretKey::from(
                decode_hex::<32>(
                    "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8",
                )
                .to_vec(),
            );

            let info = b"some_info";
            let plaintext = b"plaintext";
            let associated_data = b"some_ad";
            let exporter_ctx = b"export_ctx";

            let (enc, mut sender_ctx) = crypto.hpke_setup_s(&receiver_pub_key, info).unwrap();
            let mut receiver_ctx =
                crypto.hpke_setup_r(&enc, &receiver_priv_key, &receiver_pub_key, info).unwrap();
            let ct = sender_ctx.seal(Some(associated_data), plaintext).unwrap();
            assert_eq!(plaintext.as_ref(), receiver_ctx.open(Some(associated_data), &ct).unwrap(),);
            assert_eq!(
                sender_ctx.export(exporter_ctx, 32).unwrap(),
                receiver_ctx.export(exporter_ctx, 32).unwrap(),
            );
        }
    }

    #[test]
    fn hpke_seal_open() {
        let bssl = BoringsslCryptoProvider::new();
        for suite in get_cipher_suites() {
            let crypto = bssl.cipher_suite_provider(suite).unwrap();
            // https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.1.1
            let receiver_pub_key = HpkePublicKey::from(
                decode_hex::<32>(
                    "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",
                )
                .to_vec(),
            );
            let receiver_priv_key = HpkeSecretKey::from(
                decode_hex::<32>(
                    "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8",
                )
                .to_vec(),
            );

            let info = b"some_info";
            let plaintext = b"plaintext";
            let associated_data = b"some_ad";

            let ct = crypto
                .hpke_seal(&receiver_pub_key, info, Some(associated_data), plaintext)
                .unwrap();
            assert_eq!(
                plaintext.as_ref(),
                crypto
                    .hpke_open(
                        &ct,
                        &receiver_priv_key,
                        &receiver_pub_key,
                        info,
                        Some(associated_data)
                    )
                    .unwrap(),
            );
        }
    }

    #[test]
    fn signature_key_generate() {
        let bssl = BoringsslCryptoProvider::new();
        for suite in get_cipher_suites() {
            let crypto = bssl.cipher_suite_provider(suite).unwrap();
            assert!(crypto.signature_key_generate().is_ok());
        }
    }

    #[test]
    fn signature_key_derive_public() {
        let bssl = BoringsslCryptoProvider::new();
        for suite in get_cipher_suites() {
            let crypto = bssl.cipher_suite_provider(suite).unwrap();
            // Test 1 from https://www.rfc-editor.org/rfc/rfc8032#section-7.1
            let private_key = SignatureSecretKey::from(
                decode_hex::<32>(
                    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                )
                .to_vec(),
            );
            let expected_public_key = SignaturePublicKey::from(
                decode_hex::<32>(
                    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                )
                .to_vec(),
            );

            assert_eq!(
                crypto.signature_key_derive_public(&private_key).unwrap(),
                expected_public_key
            );
        }
    }

    #[test]
    fn sign_verify() {
        let bssl = BoringsslCryptoProvider::new();
        for suite in get_cipher_suites() {
            let crypto = bssl.cipher_suite_provider(suite).unwrap();
            // Test 3 from https://www.rfc-editor.org/rfc/rfc8032#section-7.1
            let private_key = SignatureSecretKey::from(
                decode_hex::<32>(
                    "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                )
                .to_vec(),
            );
            let data: [u8; 2] = decode_hex("af82");
            let expected_sig = decode_hex::<64>("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a").to_vec();

            let sig = crypto.sign(&private_key, &data).unwrap();
            assert_eq!(sig, expected_sig);

            let public_key = crypto.signature_key_derive_public(&private_key).unwrap();
            assert!(crypto.verify(&public_key, &sig, &data).is_ok());
        }
    }
}
