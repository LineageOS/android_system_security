/*
 * Copyright (c) 2022, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <future>
#include <optional>

#include <android/hardware/security/keymint/IRemotelyProvisionedComponent.h>

namespace android {
namespace security {
namespace identity {

using ::android::hardware::security::keymint::IRemotelyProvisionedComponent;
using ::android::security::rkp::RemotelyProvisionedKey;

std::optional<std::string> getRpcId(const sp<IRemotelyProvisionedComponent>& rpc);

std::optional<std::future<std::optional<RemotelyProvisionedKey>>>
getRpcKeyFuture(const sp<IRemotelyProvisionedComponent>& rpc, int32_t keyId);

}  // namespace identity
}  // namespace security
}  // namespace android
