/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <filesystem>
#include <map>
#include <span>
#include <string>

#include <fcntl.h>
#include <linux/fs.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <asm/byteorder.h>
#include <libfsverity.h>
#include <linux/fsverity.h>

#include "CertUtils.h"
#include "SigningKey.h"
#include "compos_signature.pb.h"

#define FS_VERITY_MAX_DIGEST_SIZE 64

using android::base::ErrnoError;
using android::base::Error;
using android::base::Result;
using android::base::unique_fd;

using compos::proto::Signature;

static const char* kFsVerityInitPath = "/system/bin/fsverity_init";
static const char* kSignatureExtension = ".signature";

static bool isSignatureFile(const std::filesystem::path& path) {
    return path.extension().native() == kSignatureExtension;
}

static std::string toHex(std::span<const uint8_t> data) {
    std::stringstream ss;
    for (auto it = data.begin(); it != data.end(); ++it) {
        ss << std::setfill('0') << std::setw(2) << std::hex << static_cast<unsigned>(*it);
    }
    return ss.str();
}

static int read_callback(void* file, void* buf, size_t count) {
    int* fd = (int*)file;
    if (TEMP_FAILURE_RETRY(read(*fd, buf, count)) < 0) return errno ? -errno : -EIO;
    return 0;
}

Result<std::vector<uint8_t>> createDigest(int fd) {
    struct stat filestat;
    int ret = fstat(fd, &filestat);
    if (ret < 0) {
        return ErrnoError() << "Failed to fstat";
    }
    struct libfsverity_merkle_tree_params params = {
        .version = 1,
        .hash_algorithm = FS_VERITY_HASH_ALG_SHA256,
        .file_size = static_cast<uint64_t>(filestat.st_size),
        .block_size = 4096,
    };

    struct libfsverity_digest* digest;
    ret = libfsverity_compute_digest(&fd, &read_callback, &params, &digest);
    if (ret < 0) {
        return ErrnoError() << "Failed to compute fs-verity digest";
    }
    std::vector<uint8_t> digestVector(&digest->digest[0], &digest->digest[32]);
    free(digest);
    return digestVector;
}

Result<std::vector<uint8_t>> createDigest(const std::string& path) {
    unique_fd fd(TEMP_FAILURE_RETRY(open(path.c_str(), O_RDONLY | O_CLOEXEC)));
    if (!fd.ok()) {
        return ErrnoError() << "Unable to open";
    }
    return createDigest(fd.get());
}

namespace {
template <typename T> struct DeleteAsPODArray {
    void operator()(T* x) {
        if (x) {
            x->~T();
            delete[](uint8_t*) x;
        }
    }
};
}  // namespace

template <typename T> using trailing_unique_ptr = std::unique_ptr<T, DeleteAsPODArray<T>>;

template <typename T>
static trailing_unique_ptr<T> makeUniqueWithTrailingData(size_t trailing_data_size) {
    uint8_t* memory = new uint8_t[sizeof(T*) + trailing_data_size];
    T* ptr = new (memory) T;
    return trailing_unique_ptr<T>{ptr};
}

static Result<std::vector<uint8_t>> signDigest(const SigningKey& key,
                                               const std::vector<uint8_t>& digest) {
    auto d = makeUniqueWithTrailingData<fsverity_formatted_digest>(digest.size());

    memcpy(d->magic, "FSVerity", 8);
    d->digest_algorithm = __cpu_to_le16(FS_VERITY_HASH_ALG_SHA256);
    d->digest_size = __cpu_to_le16(digest.size());
    memcpy(d->digest, digest.data(), digest.size());

    auto signed_digest = key.sign(std::string((char*)d.get(), sizeof(*d) + digest.size()));
    if (!signed_digest.ok()) {
        return signed_digest.error();
    }

    return std::vector<uint8_t>(signed_digest->begin(), signed_digest->end());
}

Result<void> enableFsVerity(int fd, std::span<uint8_t> pkcs7) {
    struct fsverity_enable_arg arg = {.version = 1};

    arg.sig_ptr = reinterpret_cast<uint64_t>(pkcs7.data());
    arg.sig_size = pkcs7.size();
    arg.hash_algorithm = FS_VERITY_HASH_ALG_SHA256;
    arg.block_size = 4096;

    int ret = ioctl(fd, FS_IOC_ENABLE_VERITY, &arg);

    if (ret != 0) {
        return ErrnoError() << "Failed to call FS_IOC_ENABLE_VERITY";
    }

    return {};
}

Result<std::string> enableFsVerity(const std::string& path, const SigningKey& key) {
    unique_fd fd(TEMP_FAILURE_RETRY(open(path.c_str(), O_RDONLY | O_CLOEXEC)));
    if (!fd.ok()) {
        return ErrnoError() << "Failed to open " << path;
    }

    auto digest = createDigest(fd.get());
    if (!digest.ok()) {
        return Error() << digest.error() << ": " << path;
    }

    auto signed_digest = signDigest(key, digest.value());
    if (!signed_digest.ok()) {
        return signed_digest.error();
    }

    auto pkcs7_data = createPkcs7(signed_digest.value(), kRootSubject);
    if (!pkcs7_data.ok()) {
        return pkcs7_data.error();
    }

    auto enabled = enableFsVerity(fd.get(), pkcs7_data.value());
    if (!enabled.ok()) {
        return Error() << enabled.error() << ": " << path;
    }

    // Return the root hash as a hex string
    return toHex(digest.value());
}

Result<std::map<std::string, std::string>> addFilesToVerityRecursive(const std::string& path,
                                                                     const SigningKey& key) {
    std::map<std::string, std::string> digests;

    std::error_code ec;
    auto it = std::filesystem::recursive_directory_iterator(path, ec);
    for (auto end = std::filesystem::recursive_directory_iterator(); it != end; it.increment(ec)) {
        if (it->is_regular_file()) {
            LOG(INFO) << "Adding " << it->path() << " to fs-verity...";
            auto result = enableFsVerity(it->path(), key);
            if (!result.ok()) {
                return result.error();
            }
            digests[it->path()] = *result;
        }
    }
    if (ec) {
        return Error() << "Failed to iterate " << path << ": " << ec.message();
    }

    return digests;
}

Result<std::string> isFileInVerity(int fd) {
    auto d = makeUniqueWithTrailingData<fsverity_digest>(FS_VERITY_MAX_DIGEST_SIZE);
    d->digest_size = FS_VERITY_MAX_DIGEST_SIZE;
    auto ret = ioctl(fd, FS_IOC_MEASURE_VERITY, d.get());
    if (ret < 0) {
        if (errno == ENODATA) {
            return Error() << "File is not in fs-verity";
        } else {
            return ErrnoError() << "Failed to FS_IOC_MEASURE_VERITY";
        }
    }
    return toHex({&d->digest[0], &d->digest[d->digest_size]});
}

Result<std::string> isFileInVerity(const std::string& path) {
    unique_fd fd(TEMP_FAILURE_RETRY(open(path.c_str(), O_RDONLY | O_CLOEXEC)));
    if (!fd.ok()) {
        return ErrnoError() << "Failed to open " << path;
    }

    auto digest = isFileInVerity(fd);
    if (!digest.ok()) {
        return Error() << digest.error() << ": " << path;
    }

    return digest;
}

Result<std::map<std::string, std::string>> verifyAllFilesInVerity(const std::string& path) {
    std::map<std::string, std::string> digests;
    std::error_code ec;

    auto it = std::filesystem::recursive_directory_iterator(path, ec);
    auto end = std::filesystem::recursive_directory_iterator();

    while (!ec && it != end) {
        if (it->is_regular_file()) {
            // Verify the file is in fs-verity
            auto result = isFileInVerity(it->path());
            if (!result.ok()) {
                return result.error();
            }
            digests[it->path()] = *result;
        } else if (it->is_directory()) {
            // These are fine to ignore
        } else if (it->is_symlink()) {
            return Error() << "Rejecting artifacts, symlink at " << it->path();
        } else {
            return Error() << "Rejecting artifacts, unexpected file type for " << it->path();
        }
        ++it;
    }
    if (ec) {
        return Error() << "Failed to iterate " << path << ": " << ec;
    }

    return digests;
}

Result<Signature> readSignature(const std::filesystem::path& signature_path) {
    unique_fd fd(TEMP_FAILURE_RETRY(open(signature_path.c_str(), O_RDONLY | O_CLOEXEC)));
    if (fd == -1) {
        return ErrnoError();
    }
    Signature signature;
    if (!signature.ParseFromFileDescriptor(fd.get())) {
        return Error() << "Failed to parse";
    }
    return signature;
}

Result<std::map<std::string, std::string>>
verifyAllFilesUsingCompOs(const std::string& directory_path,
                          const std::vector<uint8_t>& compos_key) {
    std::map<std::string, std::string> new_digests;
    std::vector<std::filesystem::path> signature_files;

    std::error_code ec;
    auto it = std::filesystem::recursive_directory_iterator(directory_path, ec);
    for (auto end = std::filesystem::recursive_directory_iterator(); it != end; it.increment(ec)) {
        auto& path = it->path();
        if (it->is_regular_file()) {
            if (isSignatureFile(path)) {
                continue;
            }

            unique_fd fd(TEMP_FAILURE_RETRY(open(path.c_str(), O_RDONLY | O_CLOEXEC)));
            if (!fd.ok()) {
                return ErrnoError() << "Can't open " << path;
            }

            auto signature_path = path;
            signature_path += kSignatureExtension;
            auto signature = readSignature(signature_path);
            if (!signature.ok()) {
                return Error() << "Invalid signature " << signature_path << ": "
                               << signature.error();
            }
            signature_files.push_back(signature_path);

            // Note that these values are not yet trusted.
            auto& raw_digest = signature->digest();
            auto& raw_signature = signature->signature();

            // Re-construct the fsverity_formatted_digest that was signed, so we
            // can verify the signature.
            std::vector<uint8_t> buffer(sizeof(fsverity_formatted_digest) + raw_digest.size());
            auto signed_data = new (buffer.data()) fsverity_formatted_digest;
            memcpy(signed_data->magic, "FSVerity", sizeof signed_data->magic);
            signed_data->digest_algorithm = __cpu_to_le16(FS_VERITY_HASH_ALG_SHA256);
            signed_data->digest_size = __cpu_to_le16(raw_digest.size());
            memcpy(signed_data->digest, raw_digest.data(), raw_digest.size());

            // Make sure the signature matches the CompOs public key, and not some other
            // fs-verity trusted key.
            std::string to_verify(reinterpret_cast<char*>(buffer.data()), buffer.size());

            auto verified = verifyRsaPublicKeySignature(to_verify, raw_signature, compos_key);
            if (!verified.ok()) {
                return Error() << verified.error() << ": " << path;
            }

            std::span<const uint8_t> digest_bytes(
                reinterpret_cast<const uint8_t*>(raw_digest.data()), raw_digest.size());
            std::string compos_digest = toHex(digest_bytes);

            auto verity_digest = isFileInVerity(fd);
            if (verity_digest.ok()) {
                // The file is already in fs-verity. We need to make sure it was signed
                // by CompOs, so we just check that it has the digest we expect.
                if (verity_digest.value() != compos_digest) {
                    return Error() << "fs-verity digest does not match signature file: " << path;
                }
            } else {
                // Not in fs-verity yet. But we have a valid signature of some
                // digest. If it's not the correct digest for the file then
                // enabling fs-verity will fail, so we don't need to check it
                // explicitly ourselves. Otherwise we should be good.
                std::vector<uint8_t> signature_bytes(raw_signature.begin(), raw_signature.end());
                auto pkcs7 = createPkcs7(signature_bytes, kCompOsSubject);
                if (!pkcs7.ok()) {
                    return Error() << pkcs7.error() << ": " << path;
                }

                LOG(INFO) << "Adding " << path << " to fs-verity...";
                auto enabled = enableFsVerity(fd, pkcs7.value());
                if (!enabled.ok()) {
                    return Error() << enabled.error() << ": " << path;
                }
            }

            new_digests[path] = compos_digest;
        } else if (it->is_directory()) {
            // These are fine to ignore
        } else if (it->is_symlink()) {
            return Error() << "Rejecting artifacts, symlink at " << path;
        } else {
            return Error() << "Rejecting artifacts, unexpected file type for " << path;
        }
    }
    if (ec) {
        return Error() << "Failed to iterate " << directory_path << ": " << ec.message();
    }

    // Delete the signature files now that they have served their purpose.  (ART
    // has no use for them, and their presence could cause verification to fail
    // on subsequent boots.)
    for (auto& signature_path : signature_files) {
        std::filesystem::remove(signature_path, ec);
        if (ec) {
            return Error() << "Failed to delete " << signature_path << ": " << ec.message();
        }
    }

    return new_digests;
}

Result<void> addCertToFsVerityKeyring(const std::string& path, const char* keyName) {
    const char* const argv[] = {kFsVerityInitPath, "--load-extra-key", keyName};

    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
        return ErrnoError() << "Failed to open " << path;
    }
    pid_t pid = fork();
    if (pid == 0) {
        dup2(fd, STDIN_FILENO);
        close(fd);
        int argc = arraysize(argv);
        char* argv_child[argc + 1];
        memcpy(argv_child, argv, argc * sizeof(char*));
        argv_child[argc] = nullptr;
        execvp(argv_child[0], argv_child);
        PLOG(ERROR) << "exec in ForkExecvp";
        _exit(EXIT_FAILURE);
    } else {
        close(fd);
    }
    if (pid == -1) {
        return ErrnoError() << "Failed to fork.";
    }
    int status;
    if (waitpid(pid, &status, 0) == -1) {
        return ErrnoError() << "waitpid() failed.";
    }
    if (!WIFEXITED(status)) {
        return Error() << kFsVerityInitPath << ": abnormal process exit";
    }
    if (WEXITSTATUS(status) != 0) {
        return Error() << kFsVerityInitPath << " exited with " << WEXITSTATUS(status);
    }

    return {};
}
