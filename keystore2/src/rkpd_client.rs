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

//! Helper wrapper around RKPD interface.

use crate::error::{map_binder_status_code, Error, ErrorCode};
use crate::globals::get_remotely_provisioned_component_name;
use crate::ks_err;
use crate::utils::watchdog as wd;
use android_hardware_security_keymint::aidl::android::hardware::security::keymint::SecurityLevel::SecurityLevel;
use android_security_rkp_aidl::aidl::android::security::rkp::{
    IGetKeyCallback::BnGetKeyCallback, IGetKeyCallback::IGetKeyCallback,
    IGetRegistrationCallback::BnGetRegistrationCallback,
    IGetRegistrationCallback::IGetRegistrationCallback, IRegistration::IRegistration,
    IRemoteProvisioning::IRemoteProvisioning,
    IStoreUpgradedKeyCallback::BnStoreUpgradedKeyCallback,
    IStoreUpgradedKeyCallback::IStoreUpgradedKeyCallback,
    RemotelyProvisionedKey::RemotelyProvisionedKey,
};
use android_security_rkp_aidl::binder::{BinderFeatures, Interface, Strong};
use anyhow::{Context, Result};
use futures::channel::oneshot;
use futures::executor::block_on;
use std::sync::Mutex;

/// Thread-safe channel for sending a value once and only once. If a value has
/// already been send, subsequent calls to send will noop.
struct SafeSender<T> {
    inner: Mutex<Option<oneshot::Sender<T>>>,
}

impl<T> SafeSender<T> {
    fn new(sender: oneshot::Sender<T>) -> Self {
        Self { inner: Mutex::new(Some(sender)) }
    }

    fn send(&self, value: T) {
        if let Some(inner) = self.inner.lock().unwrap().take() {
            // assert instead of unwrap, because on failure send returns Err(value)
            assert!(inner.send(value).is_ok(), "thread state is terminally broken");
        }
    }
}

struct GetRegistrationCallback {
    registration_tx: SafeSender<Result<binder::Strong<dyn IRegistration>>>,
}

impl GetRegistrationCallback {
    pub fn new_native_binder(
        registration_tx: oneshot::Sender<Result<binder::Strong<dyn IRegistration>>>,
    ) -> Strong<dyn IGetRegistrationCallback> {
        let result: Self =
            GetRegistrationCallback { registration_tx: SafeSender::new(registration_tx) };
        BnGetRegistrationCallback::new_binder(result, BinderFeatures::default())
    }
}

impl Interface for GetRegistrationCallback {}

impl IGetRegistrationCallback for GetRegistrationCallback {
    fn onSuccess(&self, registration: &Strong<dyn IRegistration>) -> binder::Result<()> {
        let _wp = wd::watch_millis("IGetRegistrationCallback::onSuccess", 500);
        self.registration_tx.send(Ok(registration.clone()));
        Ok(())
    }
    fn onCancel(&self) -> binder::Result<()> {
        let _wp = wd::watch_millis("IGetRegistrationCallback::onCancel", 500);
        log::warn!("IGetRegistrationCallback cancelled");
        self.registration_tx.send(
            Err(Error::Km(ErrorCode::OPERATION_CANCELLED))
                .context(ks_err!("GetRegistrationCallback cancelled.")),
        );
        Ok(())
    }
    fn onError(&self, error: &str) -> binder::Result<()> {
        let _wp = wd::watch_millis("IGetRegistrationCallback::onError", 500);
        log::error!("IGetRegistrationCallback failed: '{error}'");
        self.registration_tx.send(
            Err(Error::Km(ErrorCode::UNKNOWN_ERROR))
                .context(ks_err!("GetRegistrationCallback failed: {:?}", error)),
        );
        Ok(())
    }
}

/// Make a new connection to a IRegistration service.
async fn get_rkpd_registration(
    security_level: &SecurityLevel,
) -> Result<binder::Strong<dyn IRegistration>> {
    let remote_provisioning: Strong<dyn IRemoteProvisioning> =
        map_binder_status_code(binder::get_interface("remote_provisioning"))
            .context(ks_err!("Trying to connect to IRemoteProvisioning service."))?;

    let rpc_name = get_remotely_provisioned_component_name(security_level)
        .context(ks_err!("Trying to get IRPC name."))?;

    let (tx, rx) = oneshot::channel();
    let cb = GetRegistrationCallback::new_native_binder(tx);

    remote_provisioning
        .getRegistration(&rpc_name, &cb)
        .context(ks_err!("Trying to get registration."))?;

    rx.await.unwrap()
}

struct GetKeyCallback {
    key_tx: SafeSender<Result<RemotelyProvisionedKey>>,
}

impl GetKeyCallback {
    pub fn new_native_binder(
        key_tx: oneshot::Sender<Result<RemotelyProvisionedKey>>,
    ) -> Strong<dyn IGetKeyCallback> {
        let result: Self = GetKeyCallback { key_tx: SafeSender::new(key_tx) };
        BnGetKeyCallback::new_binder(result, BinderFeatures::default())
    }
}

impl Interface for GetKeyCallback {}

impl IGetKeyCallback for GetKeyCallback {
    fn onSuccess(&self, key: &RemotelyProvisionedKey) -> binder::Result<()> {
        let _wp = wd::watch_millis("IGetKeyCallback::onSuccess", 500);
        self.key_tx.send(Ok(RemotelyProvisionedKey {
            keyBlob: key.keyBlob.clone(),
            encodedCertChain: key.encodedCertChain.clone(),
        }));
        Ok(())
    }
    fn onCancel(&self) -> binder::Result<()> {
        let _wp = wd::watch_millis("IGetKeyCallback::onCancel", 500);
        log::warn!("IGetKeyCallback cancelled");
        self.key_tx.send(
            Err(Error::Km(ErrorCode::OPERATION_CANCELLED))
                .context(ks_err!("GetKeyCallback cancelled.")),
        );
        Ok(())
    }
    fn onError(&self, error: &str) -> binder::Result<()> {
        let _wp = wd::watch_millis("IGetKeyCallback::onError", 500);
        log::error!("IGetKeyCallback failed: {error}");
        self.key_tx.send(
            Err(Error::Km(ErrorCode::UNKNOWN_ERROR))
                .context(ks_err!("GetKeyCallback failed: {:?}", error)),
        );
        Ok(())
    }
}

async fn get_rkpd_attestation_key_async(
    security_level: &SecurityLevel,
    caller_uid: u32,
) -> Result<RemotelyProvisionedKey> {
    let registration = get_rkpd_registration(security_level)
        .await
        .context(ks_err!("Trying to get to IRegistration service."))?;

    let (tx, rx) = oneshot::channel();
    let cb = GetKeyCallback::new_native_binder(tx);

    registration
        .getKey(caller_uid.try_into().unwrap(), &cb)
        .context(ks_err!("Trying to get key."))?;

    rx.await.unwrap()
}

struct StoreUpgradedKeyCallback {
    completer: SafeSender<Result<()>>,
}

impl StoreUpgradedKeyCallback {
    pub fn new_native_binder(
        completer: oneshot::Sender<Result<()>>,
    ) -> Strong<dyn IStoreUpgradedKeyCallback> {
        let result: Self = StoreUpgradedKeyCallback { completer: SafeSender::new(completer) };
        BnStoreUpgradedKeyCallback::new_binder(result, BinderFeatures::default())
    }
}

impl Interface for StoreUpgradedKeyCallback {}

impl IStoreUpgradedKeyCallback for StoreUpgradedKeyCallback {
    fn onSuccess(&self) -> binder::Result<()> {
        let _wp = wd::watch_millis("IGetRegistrationCallback::onSuccess", 500);
        self.completer.send(Ok(()));
        Ok(())
    }

    fn onError(&self, error: &str) -> binder::Result<()> {
        let _wp = wd::watch_millis("IGetRegistrationCallback::onError", 500);
        log::error!("IGetRegistrationCallback failed: {error}");
        self.completer.send(
            Err(Error::Km(ErrorCode::UNKNOWN_ERROR))
                .context(ks_err!("Failed to store upgraded key: {:?}", error)),
        );
        Ok(())
    }
}

async fn store_rkpd_attestation_key_async(
    security_level: &SecurityLevel,
    key_blob: &[u8],
    upgraded_blob: &[u8],
) -> Result<()> {
    let registration = get_rkpd_registration(security_level)
        .await
        .context(ks_err!("Trying to get to IRegistration service."))?;

    let (tx, rx) = oneshot::channel();
    let cb = StoreUpgradedKeyCallback::new_native_binder(tx);

    registration
        .storeUpgradedKeyAsync(key_blob, upgraded_blob, &cb)
        .context(ks_err!("Failed to store upgraded blob with RKPD."))?;

    rx.await.unwrap()
}

/// Get attestation key from RKPD.
pub fn get_rkpd_attestation_key(
    security_level: &SecurityLevel,
    caller_uid: u32,
) -> Result<RemotelyProvisionedKey> {
    let _wp = wd::watch_millis("Calling get_rkpd_attestation_key()", 500);
    block_on(get_rkpd_attestation_key_async(security_level, caller_uid))
}

/// Store attestation key in RKPD.
pub fn store_rkpd_attestation_key(
    security_level: &SecurityLevel,
    key_blob: &[u8],
    upgraded_blob: &[u8],
) -> Result<()> {
    let _wp = wd::watch_millis("Calling store_rkpd_attestation_key()", 500);
    block_on(store_rkpd_attestation_key_async(security_level, key_blob, upgraded_blob))
}

#[cfg(test)]
mod tests {
    use super::*;
    use android_security_rkp_aidl::aidl::android::security::rkp::IRegistration::BnRegistration;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    #[derive(Default)]
    struct MockRegistrationValues {
        _key: RemotelyProvisionedKey,
    }

    #[derive(Default)]
    struct MockRegistration(Arc<Mutex<MockRegistrationValues>>);

    impl MockRegistration {
        pub fn new_native_binder() -> Strong<dyn IRegistration> {
            let result: Self = Default::default();
            BnRegistration::new_binder(result, BinderFeatures::default())
        }
    }

    impl Interface for MockRegistration {}

    impl IRegistration for MockRegistration {
        fn getKey(&self, _: i32, _: &Strong<dyn IGetKeyCallback>) -> binder::Result<()> {
            todo!()
        }

        fn cancelGetKey(&self, _: &Strong<dyn IGetKeyCallback>) -> binder::Result<()> {
            todo!()
        }

        fn storeUpgradedKeyAsync(
            &self,
            _: &[u8],
            _: &[u8],
            _: &Strong<dyn IStoreUpgradedKeyCallback>,
        ) -> binder::Result<()> {
            todo!()
        }
    }

    fn get_mock_registration() -> Result<binder::Strong<dyn IRegistration>> {
        let (tx, rx) = oneshot::channel();
        let cb = GetRegistrationCallback::new_native_binder(tx);
        let mock_registration = MockRegistration::new_native_binder();

        assert!(cb.onSuccess(&mock_registration).is_ok());
        block_on(rx).unwrap()
    }

    // Using the same key ID makes test cases race with each other. So, we use separate key IDs for
    // different test cases.
    fn get_next_key_id() -> u32 {
        static ID: AtomicU32 = AtomicU32::new(0);
        ID.fetch_add(1, Ordering::Relaxed)
    }

    #[test]
    fn test_get_registration_cb_success() {
        let registration = get_mock_registration();
        assert!(registration.is_ok());
    }

    #[test]
    fn test_get_registration_cb_cancel() {
        let (tx, rx) = oneshot::channel();
        let cb = GetRegistrationCallback::new_native_binder(tx);
        assert!(cb.onCancel().is_ok());

        let result = block_on(rx).unwrap();
        assert_eq!(
            result.unwrap_err().downcast::<Error>().unwrap(),
            Error::Km(ErrorCode::OPERATION_CANCELLED)
        );
    }

    #[test]
    fn test_get_registration_cb_error() {
        let (tx, rx) = oneshot::channel();
        let cb = GetRegistrationCallback::new_native_binder(tx);
        assert!(cb.onError("error").is_ok());

        let result = block_on(rx).unwrap();
        assert_eq!(
            result.unwrap_err().downcast::<Error>().unwrap(),
            Error::Km(ErrorCode::UNKNOWN_ERROR)
        );
    }

    #[test]
    fn test_get_key_cb_success() {
        let mock_key =
            RemotelyProvisionedKey { keyBlob: vec![1, 2, 3], encodedCertChain: vec![4, 5, 6] };
        let (tx, rx) = oneshot::channel();
        let cb = GetKeyCallback::new_native_binder(tx);
        assert!(cb.onSuccess(&mock_key).is_ok());

        let key = block_on(rx).unwrap().unwrap();
        assert_eq!(key, mock_key);
    }

    #[test]
    fn test_get_key_cb_cancel() {
        let (tx, rx) = oneshot::channel();
        let cb = GetKeyCallback::new_native_binder(tx);
        assert!(cb.onCancel().is_ok());

        let result = block_on(rx).unwrap();
        assert_eq!(
            result.unwrap_err().downcast::<Error>().unwrap(),
            Error::Km(ErrorCode::OPERATION_CANCELLED)
        );
    }

    #[test]
    fn test_get_key_cb_error() {
        let (tx, rx) = oneshot::channel();
        let cb = GetKeyCallback::new_native_binder(tx);
        assert!(cb.onError("error").is_ok());

        let result = block_on(rx).unwrap();
        assert_eq!(
            result.unwrap_err().downcast::<Error>().unwrap(),
            Error::Km(ErrorCode::UNKNOWN_ERROR)
        );
    }

    #[test]
    fn test_store_upgraded_cb_success() {
        let (tx, rx) = oneshot::channel();
        let cb = StoreUpgradedKeyCallback::new_native_binder(tx);
        assert!(cb.onSuccess().is_ok());

        block_on(rx).unwrap().unwrap();
    }

    #[test]
    fn test_store_upgraded_key_cb_error() {
        let (tx, rx) = oneshot::channel();
        let cb = StoreUpgradedKeyCallback::new_native_binder(tx);
        assert!(cb.onError("oh no! it failed").is_ok());

        let result = block_on(rx).unwrap();
        assert_eq!(
            result.unwrap_err().downcast::<Error>().unwrap(),
            Error::Km(ErrorCode::UNKNOWN_ERROR)
        );
    }

    #[test]
    fn test_get_rkpd_attestation_key() {
        binder::ProcessState::start_thread_pool();
        let key = get_rkpd_attestation_key(&SecurityLevel::TRUSTED_ENVIRONMENT, 0).unwrap();
        assert!(!key.keyBlob.is_empty());
        assert!(!key.encodedCertChain.is_empty());
    }

    #[test]
    fn test_get_rkpd_attestation_key_same_caller() {
        binder::ProcessState::start_thread_pool();
        let sec_level = SecurityLevel::TRUSTED_ENVIRONMENT;
        let key_id = get_next_key_id();

        // Multiple calls should return the same key.
        let first_key = get_rkpd_attestation_key(&sec_level, key_id).unwrap();
        let second_key = get_rkpd_attestation_key(&sec_level, key_id).unwrap();

        assert_eq!(first_key.keyBlob, second_key.keyBlob);
        assert_eq!(first_key.encodedCertChain, second_key.encodedCertChain);
    }

    #[test]
    fn test_get_rkpd_attestation_key_different_caller() {
        binder::ProcessState::start_thread_pool();
        let sec_level = SecurityLevel::TRUSTED_ENVIRONMENT;
        let first_key_id = get_next_key_id();
        let second_key_id = get_next_key_id();

        // Different callers should be getting different keys.
        let first_key = get_rkpd_attestation_key(&sec_level, first_key_id).unwrap();
        let second_key = get_rkpd_attestation_key(&sec_level, second_key_id).unwrap();

        assert_ne!(first_key.keyBlob, second_key.keyBlob);
        assert_ne!(first_key.encodedCertChain, second_key.encodedCertChain);
    }

    #[test]
    fn test_store_rkpd_attestation_key() {
        binder::ProcessState::start_thread_pool();
        let sec_level = SecurityLevel::TRUSTED_ENVIRONMENT;
        let key_id = get_next_key_id();
        let key = get_rkpd_attestation_key(&SecurityLevel::TRUSTED_ENVIRONMENT, key_id).unwrap();

        assert!(store_rkpd_attestation_key(&sec_level, &key.keyBlob, &key.keyBlob).is_ok());
    }
}
