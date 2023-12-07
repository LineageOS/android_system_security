// Copyright 2020, The Android Open Source Project
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

package android.security.authorization;

import android.hardware.security.keymint.HardwareAuthToken;
import android.hardware.security.keymint.HardwareAuthenticatorType;
import android.security.authorization.AuthorizationTokens;

// TODO: mark the interface with @SensitiveData when the annotation is ready (b/176110256).

/**
 * IKeystoreAuthorization interface exposes the methods for other system components to
 * provide keystore with the information required to enforce authorizations on key usage.
 * @hide
 */
 @SensitiveData
interface IKeystoreAuthorization {
    /**
     * Allows the Android authenticators to hand over an auth token to Keystore.
     * Callers require 'AddAuth' permission.
     * ## Error conditions:
     * `ResponseCode::PERMISSION_DENIED` - if the callers do not have the 'AddAuth' permission.
     * `ResponseCode::SYSTEM_ERROR` - if failed to store the auth token in the database or if failed
     * to add the auth token to the operation, if it is a per-op auth token.
     *
     * @param authToken The auth token created by an authenticator, upon user authentication.
     */
    void addAuthToken(in HardwareAuthToken authToken);

    /**
     * Tells Keystore that the device is now unlocked for a user.  Requires the 'Unlock' permission.
     *
     * This method makes Keystore start allowing the use of the given user's keys that require an
     * unlocked device, following the device boot or an earlier call to onDeviceLocked() which
     * disabled the use of such keys.  In addition, once per boot, this method must be called with a
     * password before keys that require user authentication can be used.
     *
     * To enable access to these keys, this method attempts to decrypt and cache the user's super
     * keys.  If the password is given, i.e. if the unlock occurred using an LSKF-equivalent
     * mechanism, then both the AfterFirstUnlock and UnlockedDeviceRequired super keys are decrypted
     * (if not already done).  Otherwise, only the UnlockedDeviceRequired super keys are decrypted,
     * and this only works if a valid HardwareAuthToken has been added to Keystore for one of the
     * 'unlockingSids' that was passed to the last call to onDeviceLocked() for the user.
     *
     * ## Error conditions:
     * `ResponseCode::PERMISSION_DENIED` - if the caller does not have the 'Unlock' permission.
     * `ResponseCode::VALUE_CORRUPTED` - if a super key can not be decrypted.
     * `ResponseCode::KEY_NOT_FOUND` - if a super key is not found.
     * `ResponseCode::SYSTEM_ERROR` - if another error occurred.
     *
     * @param userId The Android user ID of the user for which the device is now unlocked
     * @param password If available, a secret derived from the user's synthetic password
     */
    void onDeviceUnlocked(in int userId, in @nullable byte[] password);

    /**
     * Tells Keystore that the device is now locked for a user.  Requires the 'Lock' permission.
     *
     * This method makes Keystore stop allowing the use of the given user's keys that require an
     * unlocked device.  This is done through logical enforcement, and also through cryptographic
     * enforcement by wiping the UnlockedDeviceRequired super keys from memory.
     *
     * unlockingSids is the list of SIDs of the user's biometrics with which the device may be
     * unlocked later.  If this list is non-empty, then instead of completely wiping the
     * UnlockedDeviceRequired super keys from memory, this method re-encrypts these super keys with
     * a new AES key that is imported into KeyMint and bound to the given SIDs.  This allows the
     * UnlockedDeviceRequired super keys to be recovered if the device is unlocked with a biometric.
     *
     * ## Error conditions:
     * `ResponseCode::PERMISSION_DENIED` - if the caller does not have the 'Lock' permission.
     *
     * @param userId The Android user ID of the user for which the device is now locked
     * @param unlockingSids The user's list of biometric SIDs
     */
    void onDeviceLocked(in int userId, in long[] unlockingSids);

    /**
     * Allows Credstore to retrieve a HardwareAuthToken and a TimestampToken.
     * Identity Credential Trusted App can run either in the TEE or in other secure Hardware.
     * So, credstore always need to retrieve a TimestampToken along with a HardwareAuthToken.
     *
     * The passed in |challenge| parameter must always be non-zero.
     *
     * The returned TimestampToken will always have its |challenge| field set to
     * the |challenge| parameter.
     *
     * This method looks through auth-tokens cached by keystore which match
     * the passed-in |secureUserId|.
     * The most recent matching auth token which has a |challenge| field which matches
     * the passed-in |challenge| parameter is returned.
     * In this case the |authTokenMaxAgeMillis| parameter is not used.
     *
     * Otherwise, the most recent matching auth token which is younger
     * than |authTokenMaxAgeMillis| is returned.
     *
     * This method is called by credstore (and only credstore).
     *
     * The caller requires 'get_auth_token' permission.
     *
     * ## Error conditions:
     * `ResponseCode::PERMISSION_DENIED` - if the caller does not have the 'get_auth_token'
     *                                     permission.
     * `ResponseCode::SYSTEM_ERROR` - if failed to obtain an authtoken from the database.
     * `ResponseCode::NO_AUTH_TOKEN_FOUND` - a matching auth token is not found.
     * `ResponseCode::INVALID_ARGUMENT` - if the passed-in |challenge| parameter is zero.
     */
    AuthorizationTokens getAuthTokensForCredStore(in long challenge, in long secureUserId,
     in long authTokenMaxAgeMillis);

    /**
     * Returns the last successful authentication time since boot for the given user with any of the
     * given authenticator types. This is determined by inspecting the cached auth tokens.
     *
     * ## Error conditions:
     * `ResponseCode::NO_AUTH_TOKEN_FOUND` - if there is no matching authentication token found
     */
    long getLastAuthTime(in long secureUserId, in HardwareAuthenticatorType[] authTypes);
}
