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

#pragma once

#include <memory>
#include <string>
#include <vector>

#include <android-base/result.h>

#include <utils/StrongPointer.h>

#include <android/system/keystore2/IKeystoreService.h>

class FakeCompOs {
    using IKeystoreService = ::android::system::keystore2::IKeystoreService;
    using IKeystoreSecurityLevel = ::android::system::keystore2::IKeystoreSecurityLevel;
    using KeyDescriptor = ::android::system::keystore2::KeyDescriptor;
    using KeyMetadata = ::android::system::keystore2::KeyMetadata;

  public:
    using ByteVector = std::vector<uint8_t>;

    static android::base::Result<std::unique_ptr<FakeCompOs>>
    startInstance(const std::string& instanceImagePath);

    android::base::Result<void> loadAndVerifyKey(const ByteVector& keyBlob,
                                                 const ByteVector& publicKey) const;

  private:
    FakeCompOs();

    android::base::Result<void> initialize();

    android::base::Result<ByteVector> signData(const ByteVector& keyBlob,
                                               const ByteVector& data) const;

    KeyDescriptor mDescriptor;
    android::sp<IKeystoreService> mService;
    android::sp<IKeystoreSecurityLevel> mSecurityLevel;
};
