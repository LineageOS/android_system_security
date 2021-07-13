/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "FakeCompOs.h"

#include "CertUtils.h"
#include "KeyConstants.h"

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/result.h>
#include <android-base/scopeguard.h>

#include <binder/IServiceManager.h>

#include <openssl/nid.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

using android::String16;

using android::hardware::security::keymint::Algorithm;
using android::hardware::security::keymint::Digest;
using android::hardware::security::keymint::KeyParameter;
using android::hardware::security::keymint::KeyParameterValue;
using android::hardware::security::keymint::KeyPurpose;
using android::hardware::security::keymint::PaddingMode;
using android::hardware::security::keymint::SecurityLevel;
using android::hardware::security::keymint::Tag;

using android::system::keystore2::CreateOperationResponse;
using android::system::keystore2::Domain;

using android::base::Error;
using android::base::Result;

using android::binder::Status;

// TODO: Allocate a namespace for CompOS
const int64_t kCompOsNamespace = 101;

Result<std::unique_ptr<FakeCompOs>> FakeCompOs::newInstance() {
    std::unique_ptr<FakeCompOs> compOs(new FakeCompOs);
    auto init = compOs->initialize();
    if (init.ok()) {
        return compOs;
    } else {
        return init.error();
    }
}

FakeCompOs::FakeCompOs() {}

Result<void> FakeCompOs::initialize() {
    auto sm = android::defaultServiceManager();
    if (!sm) {
        return Error() << "No ServiceManager";
    }
    auto rawService = sm->getService(String16("android.system.keystore2.IKeystoreService/default"));
    if (!rawService) {
        return Error() << "No Keystore service";
    }
    mService = interface_cast<android::system::keystore2::IKeystoreService>(rawService);
    if (!mService) {
        return Error() << "Bad Keystore service";
    }

    // TODO: We probably want SecurityLevel::SOFTWARE here, in the VM, but Keystore doesn't do it
    auto status = mService->getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT, &mSecurityLevel);
    if (!status.isOk()) {
        return Error() << status;
    }

    return {};
}

Result<FakeCompOs::KeyData> FakeCompOs::generateKey() const {
    std::vector<KeyParameter> params;

    KeyParameter algo;
    algo.tag = Tag::ALGORITHM;
    algo.value = KeyParameterValue::make<KeyParameterValue::algorithm>(Algorithm::RSA);
    params.push_back(algo);

    KeyParameter key_size;
    key_size.tag = Tag::KEY_SIZE;
    key_size.value = KeyParameterValue::make<KeyParameterValue::integer>(kRsaKeySize);
    params.push_back(key_size);

    KeyParameter digest;
    digest.tag = Tag::DIGEST;
    digest.value = KeyParameterValue::make<KeyParameterValue::digest>(Digest::SHA_2_256);
    params.push_back(digest);

    KeyParameter padding;
    padding.tag = Tag::PADDING;
    padding.value =
        KeyParameterValue::make<KeyParameterValue::paddingMode>(PaddingMode::RSA_PKCS1_1_5_SIGN);
    params.push_back(padding);

    KeyParameter exponent;
    exponent.tag = Tag::RSA_PUBLIC_EXPONENT;
    exponent.value = KeyParameterValue::make<KeyParameterValue::longInteger>(kRsaKeyExponent);
    params.push_back(exponent);

    KeyParameter purpose;
    purpose.tag = Tag::PURPOSE;
    purpose.value = KeyParameterValue::make<KeyParameterValue::keyPurpose>(KeyPurpose::SIGN);
    params.push_back(purpose);

    KeyParameter auth;
    auth.tag = Tag::NO_AUTH_REQUIRED;
    auth.value = KeyParameterValue::make<KeyParameterValue::boolValue>(true);
    params.push_back(auth);

    KeyDescriptor descriptor;
    descriptor.domain = Domain::BLOB;
    descriptor.nspace = kCompOsNamespace;

    KeyMetadata metadata;
    auto status = mSecurityLevel->generateKey(descriptor, {}, params, 0, {}, &metadata);
    if (!status.isOk()) {
        return Error() << "Failed to generate key";
    }

    auto& cert = metadata.certificate;
    if (!cert) {
        return Error() << "No certificate.";
    }

    auto& blob = metadata.key.blob;
    if (!blob) {
        return Error() << "No blob.";
    }

    KeyData key_data{std::move(metadata.certificate.value()), std::move(metadata.key.blob.value())};
    return key_data;
}

Result<FakeCompOs::ByteVector> FakeCompOs::signData(const ByteVector& keyBlob,
                                                    const ByteVector& data) const {
    KeyDescriptor descriptor;
    descriptor.domain = Domain::BLOB;
    descriptor.nspace = kCompOsNamespace;
    descriptor.blob = keyBlob;

    std::vector<KeyParameter> parameters;

    {
        KeyParameter algo;
        algo.tag = Tag::ALGORITHM;
        algo.value = KeyParameterValue::make<KeyParameterValue::algorithm>(Algorithm::RSA);
        parameters.push_back(algo);

        KeyParameter digest;
        digest.tag = Tag::DIGEST;
        digest.value = KeyParameterValue::make<KeyParameterValue::digest>(Digest::SHA_2_256);
        parameters.push_back(digest);

        KeyParameter padding;
        padding.tag = Tag::PADDING;
        padding.value = KeyParameterValue::make<KeyParameterValue::paddingMode>(
            PaddingMode::RSA_PKCS1_1_5_SIGN);
        parameters.push_back(padding);

        KeyParameter purpose;
        purpose.tag = Tag::PURPOSE;
        purpose.value = KeyParameterValue::make<KeyParameterValue::keyPurpose>(KeyPurpose::SIGN);
        parameters.push_back(purpose);
    }

    Status status;

    CreateOperationResponse response;
    status = mSecurityLevel->createOperation(descriptor, parameters, /*forced=*/false, &response);
    if (!status.isOk()) {
        return Error() << "Failed to create operation: " << status;
    }

    auto operation = response.iOperation;
    auto abort_guard = android::base::make_scope_guard([&] { operation->abort(); });

    if (response.operationChallenge.has_value()) {
        return Error() << "Key requires user authorization";
    }

    std::optional<ByteVector> signature;
    status = operation->finish(data, {}, &signature);
    if (!status.isOk()) {
        return Error() << "Failed to sign data: " << status;
    }

    abort_guard.Disable();

    if (!signature.has_value()) {
        return Error() << "No signature received from keystore.";
    }

    return signature.value();
}

Result<void> FakeCompOs::loadAndVerifyKey(const ByteVector& keyBlob,
                                          const ByteVector& publicKey) const {
    // To verify the key is valid, we use it to sign some data, and then verify the signature using
    // the supplied public key.

    ByteVector data(32);
    if (RAND_bytes(data.data(), data.size()) != 1) {
        return Error() << "No random bytes";
    }

    auto signature = signData(keyBlob, data);
    if (!signature.ok()) {
        return signature.error();
    }

    std::string signatureString(reinterpret_cast<char*>(signature.value().data()),
                                signature.value().size());
    std::string dataString(reinterpret_cast<char*>(data.data()), data.size());
    return verifySignature(dataString, signatureString, publicKey);
}
