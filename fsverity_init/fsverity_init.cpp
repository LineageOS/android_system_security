/*
 * Copyright (C) 2019 The Android Open Source Project
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

//
// fsverity_init is a tool for loading X.509 certificates into the kernel keyring used by the
// fsverity builtin signature verification kernel feature
// (https://www.kernel.org/doc/html/latest/filesystems/fsverity.html#built-in-signature-verification).
// Starting in Android 14, Android has actually stopped using this feature, as it was too inflexible
// and caused problems.  It has been replaced by userspace signature verification.  Also, some uses
// of fsverity in Android are now for integrity-only use cases.
//
// Regardless, there may exist fsverity files on-disk that were created by Android 13 or earlier.
// These files still have builtin signatures.  If the kernel is an older kernel that still has
// CONFIG_FS_VERITY_BUILTIN_SIGNATURES enabled, these files cannot be opened unless the
// corresponding key is in the ".fs-verity" keyring.  Therefore, this tool still has to exist and be
// used to load keys into the kernel, even though this has no security purpose anymore.
//
// This tool can be removed as soon as all supported kernels are guaranteed to have
// CONFIG_FS_VERITY_BUILTIN_SIGNATURES disabled, or alternatively as soon as support for upgrades
// from Android 13 or earlier is no longer required.
//

#define LOG_TAG "fsverity_init"

#include <sys/types.h>

#include <filesystem>
#include <string>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <log/log.h>
#include <mini_keyctl_utils.h>

bool LoadKeyToKeyring(key_serial_t keyring_id, const char* desc, const char* data, size_t size) {
    key_serial_t key = add_key("asymmetric", desc, data, size, keyring_id);
    if (key < 0) {
        PLOG(ERROR) << "Failed to add key";
        return false;
    }
    return true;
}

bool LoadKeyFromStdin(key_serial_t keyring_id, const char* keyname) {
    std::string content;
    if (!android::base::ReadFdToString(STDIN_FILENO, &content)) {
        LOG(ERROR) << "Failed to read key from stdin";
        return false;
    }
    if (!LoadKeyToKeyring(keyring_id, keyname, content.c_str(), content.size())) {
        LOG(ERROR) << "Failed to load key from stdin";
        return false;
    }
    return true;
}

void LoadKeyFromFile(key_serial_t keyring_id, const char* keyname, const std::string& path) {
    LOG(INFO) << "LoadKeyFromFile path=" << path << " keyname=" << keyname;
    std::string content;
    if (!android::base::ReadFileToString(path, &content)) {
        LOG(ERROR) << "Failed to read key from " << path;
        return;
    }
    if (!LoadKeyToKeyring(keyring_id, keyname, content.c_str(), content.size())) {
        LOG(ERROR) << "Failed to load key from " << path;
    }
}

void LoadKeyFromDirectory(key_serial_t keyring_id, const char* keyname_prefix, const char* dir) {
    if (!std::filesystem::exists(dir)) {
        return;
    }
    int counter = 0;
    for (const auto& entry : std::filesystem::directory_iterator(dir)) {
        if (!android::base::EndsWithIgnoreCase(entry.path().c_str(), ".der")) continue;
        std::string keyname = keyname_prefix + std::to_string(counter);
        counter++;
        LoadKeyFromFile(keyring_id, keyname.c_str(), entry.path());
    }
}

void LoadKeyFromVerifiedPartitions(key_serial_t keyring_id) {
    // NB: Directories need to be synced with FileIntegrityService.java in
    // frameworks/base.
    LoadKeyFromDirectory(keyring_id, "fsv_system_", "/system/etc/security/fsverity");
    LoadKeyFromDirectory(keyring_id, "fsv_product_", "/product/etc/security/fsverity");
}

int main(int argc, const char** argv) {
    if (argc < 2) {
        LOG(ERROR) << "Not enough arguments";
        return -1;
    }

    key_serial_t keyring_id = android::GetKeyringId(".fs-verity");
    if (keyring_id < 0) {
        // This is expected on newer kernels.  See comment at the beginning of this file.
        LOG(DEBUG) << "no initialization required";
        return 0;
    }

    const std::string_view command = argv[1];

    if (command == "--load-verified-keys") {
        LoadKeyFromVerifiedPartitions(keyring_id);
    } else if (command == "--load-extra-key") {
        if (argc != 3) {
            LOG(ERROR) << "--load-extra-key requires <key_name> argument.";
            return -1;
        }
        if (!LoadKeyFromStdin(keyring_id, argv[2])) {
            return -1;
        }
    } else if (command == "--lock") {
        if (!android::base::GetBoolProperty("ro.debuggable", false)) {
            if (keyctl_restrict_keyring(keyring_id, nullptr, nullptr) < 0) {
                PLOG(ERROR) << "Cannot restrict .fs-verity keyring";
            }
        }
    } else {
        LOG(ERROR) << "Unknown argument(s).";
        return -1;
    }

    return 0;
}
