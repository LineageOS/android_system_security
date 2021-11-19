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

#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/scopeguard.h>
#include <logwrap/logwrap.h>
#include <odrefresh/odrefresh.h>

#include "CertUtils.h"
#include "KeystoreKey.h"
#include "VerityUtils.h"

#include "odsign_info.pb.h"

using android::base::ErrnoError;
using android::base::Error;
using android::base::Result;
using android::base::SetProperty;

using OdsignInfo = ::odsign::proto::OdsignInfo;

const std::string kSigningKeyCert = "/data/misc/odsign/key.cert";
const std::string kOdsignInfo = "/data/misc/odsign/odsign.info";
const std::string kOdsignInfoSignature = "/data/misc/odsign/odsign.info.signature";

const std::string kArtArtifactsDir = "/data/misc/apexdata/com.android.art/dalvik-cache";

constexpr const char* kOdrefreshPath = "/apex/com.android.art/bin/odrefresh";
constexpr const char* kCompOsVerifyPath = "/apex/com.android.compos/bin/compos_verify_key";
constexpr const char* kFsVerityProcPath = "/proc/sys/fs/verity";
constexpr const char* kKvmDevicePath = "/dev/kvm";

constexpr bool kForceCompilation = false;
constexpr bool kUseCompOs = true;

const std::string kCompOsCert = "/data/misc/odsign/compos_key.cert";

const std::string kCompOsCurrentPublicKey =
    "/data/misc/apexdata/com.android.compos/current/key.pubkey";
const std::string kCompOsPendingPublicKey =
    "/data/misc/apexdata/com.android.compos/pending/key.pubkey";
const std::string kCompOsPendingArtifactsDir = "/data/misc/apexdata/com.android.art/compos-pending";
const std::string kCompOsInfo = kArtArtifactsDir + "/compos.info";
const std::string kCompOsInfoSignature = kCompOsInfo + ".signature";

constexpr const char* kCompOsPendingInfoPath =
    "/data/misc/apexdata/com.android.art/compos-pending/compos.info";
constexpr const char* kCompOsPendingInfoSignaturePath =
    "/data/misc/apexdata/com.android.art/compos-pending/compos.info.signature";

constexpr const char* kOdsignVerificationDoneProp = "odsign.verification.done";
constexpr const char* kOdsignKeyDoneProp = "odsign.key.done";

constexpr const char* kOdsignVerificationStatusProp = "odsign.verification.success";
constexpr const char* kOdsignVerificationStatusValid = "1";
constexpr const char* kOdsignVerificationStatusError = "0";

constexpr const char* kStopServiceProp = "ctl.stop";

enum class CompOsInstance { kCurrent, kPending };

namespace {

std::vector<uint8_t> readBytesFromFile(const std::string& path) {
    std::string str;
    android::base::ReadFileToString(path, &str);
    return std::vector<uint8_t>(str.begin(), str.end());
}

bool rename(const std::string& from, const std::string& to) {
    std::error_code ec;
    std::filesystem::rename(from, to, ec);
    if (ec) {
        LOG(ERROR) << "Can't rename " << from << " to " << to << ": " << ec.message();
        return false;
    }
    return true;
}

int removeDirectory(const std::string& directory) {
    std::error_code ec;
    auto num_removed = std::filesystem::remove_all(directory, ec);
    if (ec) {
        LOG(ERROR) << "Can't remove " << directory << ": " << ec.message();
        return 0;
    } else {
        if (num_removed > 0) {
            LOG(INFO) << "Removed " << num_removed << " entries from " << directory;
        }
        return num_removed;
    }
}

bool directoryHasContent(const std::string& directory) {
    std::error_code ec;
    return std::filesystem::is_directory(directory, ec) &&
           !std::filesystem::is_empty(directory, ec);
}

art::odrefresh::ExitCode compileArtifacts(bool force) {
    const char* const argv[] = {kOdrefreshPath, force ? "--force-compile" : "--compile"};
    const int exit_code =
        logwrap_fork_execvp(arraysize(argv), argv, nullptr, false, LOG_ALOG, false, nullptr);
    return static_cast<art::odrefresh::ExitCode>(exit_code);
}

art::odrefresh::ExitCode checkArtifacts() {
    const char* const argv[] = {kOdrefreshPath, "--check"};
    const int exit_code =
        logwrap_fork_execvp(arraysize(argv), argv, nullptr, false, LOG_ALOG, false, nullptr);
    return static_cast<art::odrefresh::ExitCode>(exit_code);
}

std::string toHex(const std::vector<uint8_t>& digest) {
    std::stringstream ss;
    for (auto it = digest.begin(); it != digest.end(); ++it) {
        ss << std::setfill('0') << std::setw(2) << std::hex << static_cast<unsigned>(*it);
    }
    return ss.str();
}

bool compOsPresent() {
    return access(kCompOsVerifyPath, X_OK) == 0 && access(kKvmDevicePath, F_OK) == 0;
}

Result<void> verifyExistingRootCert(const SigningKey& key) {
    if (access(kSigningKeyCert.c_str(), F_OK) < 0) {
        return ErrnoError() << "Key certificate not found: " << kSigningKeyCert;
    }
    auto trustedPublicKey = key.getPublicKey();
    if (!trustedPublicKey.ok()) {
        return Error() << "Failed to retrieve signing public key: " << trustedPublicKey.error();
    }

    auto publicKeyFromExistingCert = extractPublicKeyFromX509(kSigningKeyCert);
    if (!publicKeyFromExistingCert.ok()) {
        return publicKeyFromExistingCert.error();
    }
    if (publicKeyFromExistingCert.value() != trustedPublicKey.value()) {
        return Error() << "Public key of existing certificate at " << kSigningKeyCert
                       << " does not match signing public key.";
    }

    // At this point, we know the cert is for our key; it's unimportant whether it's
    // actually self-signed.
    return {};
}

Result<void> createX509RootCert(const SigningKey& key, const std::string& outPath) {
    auto publicKey = key.getPublicKey();

    if (!publicKey.ok()) {
        return publicKey.error();
    }

    auto keySignFunction = [&](const std::string& to_be_signed) { return key.sign(to_be_signed); };
    return createSelfSignedCertificate(*publicKey, keySignFunction, outPath);
}

Result<std::vector<uint8_t>> extractRsaPublicKeyFromLeafCert(const SigningKey& key,
                                                             const std::string& certPath,
                                                             const std::string& expectedCn) {
    if (access(certPath.c_str(), F_OK) < 0) {
        return ErrnoError() << "Certificate not found: " << certPath;
    }
    auto trustedPublicKey = key.getPublicKey();
    if (!trustedPublicKey.ok()) {
        return Error() << "Failed to retrieve signing public key: " << trustedPublicKey.error();
    }

    auto existingCertInfo = verifyAndExtractCertInfoFromX509(certPath, trustedPublicKey.value());
    if (!existingCertInfo.ok()) {
        return Error() << "Failed to verify certificate at " << certPath << ": "
                       << existingCertInfo.error();
    }

    auto& actualCn = existingCertInfo.value().subjectCn;
    if (actualCn != expectedCn) {
        return Error() << "CN of existing certificate at " << certPath << " is " << actualCn
                       << ", should be " << expectedCn;
    }

    return existingCertInfo.value().subjectRsaPublicKey;
}

// Attempt to start a CompOS VM for the specified instance to get it to
// verify ita public key & key blob.
bool startCompOsAndVerifyKey(CompOsInstance instance) {
    bool isCurrent = instance == CompOsInstance::kCurrent;
    const std::string& keyPath = isCurrent ? kCompOsCurrentPublicKey : kCompOsPendingPublicKey;
    if (access(keyPath.c_str(), R_OK) != 0) {
        return false;
    }

    const char* const argv[] = {kCompOsVerifyPath, "--instance", isCurrent ? "current" : "pending"};
    int result =
        logwrap_fork_execvp(arraysize(argv), argv, nullptr, false, LOG_ALOG, false, nullptr);
    if (result == 0) {
        return true;
    }

    LOG(ERROR) << kCompOsVerifyPath << " returned " << result;
    return false;
}

Result<std::vector<uint8_t>> verifyCompOsKey(const SigningKey& signingKey) {
    bool verified = false;

    // If a pending key has been generated we don't know if it is the correct
    // one for the pending CompOS VM, so we need to start it and ask it.
    if (startCompOsAndVerifyKey(CompOsInstance::kPending)) {
        verified = true;
    }

    if (!verified) {
        // Alternatively if we signed a cert for the key on a previous boot, then we
        // can use that straight away.
        auto existing_key =
            extractRsaPublicKeyFromLeafCert(signingKey, kCompOsCert, kCompOsSubject.commonName);
        if (existing_key.ok()) {
            LOG(INFO) << "Found and verified existing CompOS public key certificate: "
                      << kCompOsCert;
            return existing_key.value();
        }
    }

    // Otherwise, if there is an existing key that we haven't signed yet, then we can sign
    // it now if CompOS confirms it's OK.
    if (!verified && startCompOsAndVerifyKey(CompOsInstance::kCurrent)) {
        verified = true;
    }

    if (!verified) {
        return Error() << "No valid CompOS key present.";
    }

    // If the pending key was verified it will have been promoted to current, so
    // at this stage if there is a key it will be the current one.
    auto publicKey = readBytesFromFile(kCompOsCurrentPublicKey);
    if (publicKey.empty()) {
        // This shouldn`t really happen.
        return Error() << "Failed to read CompOS key.";
    }

    // One way or another we now have a valid public key. Persist a certificate so
    // we can simplify the checks on subsequent boots.

    auto signFunction = [&](const std::string& to_be_signed) {
        return signingKey.sign(to_be_signed);
    };
    auto certStatus = createLeafCertificate(kCompOsSubject, publicKey, signFunction,
                                            kSigningKeyCert, kCompOsCert);
    if (!certStatus.ok()) {
        return Error() << "Failed to create CompOS cert: " << certStatus.error();
    }

    LOG(INFO) << "Verified key, wrote new CompOS cert";

    return publicKey;
}

Result<std::map<std::string, std::string>> computeDigests(const std::string& path) {
    std::error_code ec;
    std::map<std::string, std::string> digests;

    auto it = std::filesystem::recursive_directory_iterator(path, ec);
    auto end = std::filesystem::recursive_directory_iterator();

    while (!ec && it != end) {
        if (it->is_regular_file()) {
            auto digest = createDigest(it->path());
            if (!digest.ok()) {
                return Error() << "Failed to compute digest for " << it->path() << ": "
                               << digest.error();
            }
            digests[it->path()] = toHex(*digest);
        }
        ++it;
    }
    if (ec) {
        return Error() << "Failed to iterate " << path << ": " << ec;
    }

    return digests;
}

Result<void> verifyDigests(const std::map<std::string, std::string>& digests,
                           const std::map<std::string, std::string>& trusted_digests) {
    for (const auto& path_digest : digests) {
        auto path = path_digest.first;
        auto digest = path_digest.second;
        if (trusted_digests.count(path) == 0) {
            return Error() << "Couldn't find digest for " << path;
        }
        if (trusted_digests.at(path) != digest) {
            return Error() << "Digest mismatch for " << path;
        }
    }

    // All digests matched!
    if (digests.size() > 0) {
        LOG(INFO) << "All root hashes match.";
    }
    return {};
}

Result<void> verifyIntegrityFsVerity(const std::map<std::string, std::string>& trusted_digests) {
    // Just verify that the files are in verity, and get their digests
    auto result = verifyAllFilesInVerity(kArtArtifactsDir);
    if (!result.ok()) {
        return result.error();
    }

    return verifyDigests(*result, trusted_digests);
}

Result<void> verifyIntegrityNoFsVerity(const std::map<std::string, std::string>& trusted_digests) {
    // On these devices, just compute the digests, and verify they match the ones we trust
    auto result = computeDigests(kArtArtifactsDir);
    if (!result.ok()) {
        return result.error();
    }

    return verifyDigests(*result, trusted_digests);
}

Result<OdsignInfo> getAndVerifyOdsignInfo(const SigningKey& key) {
    std::string persistedSignature;
    OdsignInfo odsignInfo;

    if (!android::base::ReadFileToString(kOdsignInfoSignature, &persistedSignature)) {
        return ErrnoError() << "Failed to read " << kOdsignInfoSignature;
    }

    std::fstream odsign_info(kOdsignInfo, std::ios::in | std::ios::binary);
    if (!odsign_info) {
        return Error() << "Failed to open " << kOdsignInfo;
    }
    odsign_info.seekg(0);
    // Verify the hash
    std::string odsign_info_str((std::istreambuf_iterator<char>(odsign_info)),
                                std::istreambuf_iterator<char>());

    auto publicKey = key.getPublicKey();
    auto signResult = verifySignature(odsign_info_str, persistedSignature, *publicKey);
    if (!signResult.ok()) {
        return Error() << kOdsignInfoSignature << " does not match.";
    } else {
        LOG(INFO) << kOdsignInfoSignature << " matches.";
    }

    odsign_info.seekg(0);
    if (!odsignInfo.ParseFromIstream(&odsign_info)) {
        return Error() << "Failed to parse " << kOdsignInfo;
    }

    LOG(INFO) << "Loaded " << kOdsignInfo;
    return odsignInfo;
}

std::map<std::string, std::string> getTrustedDigests(const SigningKey& key) {
    std::map<std::string, std::string> trusted_digests;

    if (access(kOdsignInfo.c_str(), F_OK) != 0) {
        // no odsign info file, which is not necessarily an error - just return
        // an empty list of digests.
        LOG(INFO) << kOdsignInfo << " not found.";
        return trusted_digests;
    }
    auto signInfo = getAndVerifyOdsignInfo(key);

    if (signInfo.ok()) {
        trusted_digests.insert(signInfo->file_hashes().begin(), signInfo->file_hashes().end());
    } else {
        // This is not expected, since the file did exist. Log an error and
        // return an empty list of digests.
        LOG(ERROR) << "Couldn't load trusted digests: " << signInfo.error();
    }

    return trusted_digests;
}

Result<void> persistDigests(const std::map<std::string, std::string>& digests,
                            const SigningKey& key) {
    OdsignInfo signInfo;
    google::protobuf::Map<std::string, std::string> proto_hashes(digests.begin(), digests.end());
    auto map = signInfo.mutable_file_hashes();
    *map = proto_hashes;

    std::fstream odsign_info(kOdsignInfo,
                             std::ios::in | std::ios::out | std::ios::trunc | std::ios::binary);
    if (!signInfo.SerializeToOstream(&odsign_info)) {
        return Error() << "Failed to persist root hashes in " << kOdsignInfo;
    }

    // Sign the signatures with our key itself, and write that to storage
    odsign_info.seekg(0, std::ios::beg);
    std::string odsign_info_str((std::istreambuf_iterator<char>(odsign_info)),
                                std::istreambuf_iterator<char>());
    auto signResult = key.sign(odsign_info_str);
    if (!signResult.ok()) {
        return Error() << "Failed to sign " << kOdsignInfo;
    }
    android::base::WriteStringToFile(*signResult, kOdsignInfoSignature);
    return {};
}

Result<void>
verifyArtifactsIntegrity(const std::map<std::string, std::string>& trusted_digests,
                         bool supportsFsVerity) {
    Result<void> integrityStatus;

    if (supportsFsVerity) {
        integrityStatus = verifyIntegrityFsVerity(trusted_digests);
    } else {
        integrityStatus = verifyIntegrityNoFsVerity(trusted_digests);
    }
    if (!integrityStatus.ok()) {
        return integrityStatus.error();
    }

    return {};
}

Result<std::vector<uint8_t>> addCompOsCertToFsVerityKeyring(const SigningKey& signingKey) {
    auto publicKey = verifyCompOsKey(signingKey);
    if (!publicKey.ok()) {
        return publicKey.error();
    }

    auto cert_add_result = addCertToFsVerityKeyring(kCompOsCert, "fsv_compos");
    if (!cert_add_result.ok()) {
        // Best efforts only - nothing we can do if deletion fails.
        unlink(kCompOsCert.c_str());
        return Error() << "Failed to add CompOS certificate to fs-verity keyring: "
                       << cert_add_result.error();
    }

    return publicKey;
}

Result<OdsignInfo> getComposInfo(const std::vector<uint8_t>& compos_key) {
    std::string compos_signature;
    if (!android::base::ReadFileToString(kCompOsInfoSignature, &compos_signature)) {
        return ErrnoError() << "Failed to read " << kCompOsInfoSignature;
    }

    std::string compos_info_str;
    if (!android::base::ReadFileToString(kCompOsInfo, &compos_info_str)) {
        return ErrnoError() << "Failed to read " << kCompOsInfo;
    }

    // Delete the files - if they're valid we don't need them any more, and
    // they'd confuse artifact verification; if they're not we never need to
    // look at them again.
    if (unlink(kCompOsInfo.c_str()) != 0 || unlink(kCompOsInfoSignature.c_str()) != 0) {
        return ErrnoError() << "Unable to delete CompOS info/signature file";
    }

    // Verify the signature
    auto verified = verifyRsaPublicKeySignature(compos_info_str, compos_signature, compos_key);
    if (!verified.ok()) {
        return Error() << kCompOsInfoSignature << " does not match.";
    } else {
        LOG(INFO) << kCompOsInfoSignature << " matches.";
    }

    OdsignInfo compos_info;
    if (!compos_info.ParseFromString(compos_info_str)) {
        return Error() << "Failed to parse " << kCompOsInfo;
    }

    LOG(INFO) << "Loaded " << kCompOsInfo;
    return compos_info;
}

art::odrefresh::ExitCode checkCompOsPendingArtifacts(const std::vector<uint8_t>& compos_key,
                                                     const SigningKey& signing_key,
                                                     bool* digests_verified) {
    if (!directoryHasContent(kCompOsPendingArtifactsDir)) {
        return art::odrefresh::ExitCode::kCompilationRequired;
    }

    // CompOS has generated some artifacts that may, or may not, match the
    // current state.  But if there are already valid artifacts present the
    // CompOS ones are redundant.
    art::odrefresh::ExitCode odrefresh_status = checkArtifacts();
    if (odrefresh_status != art::odrefresh::ExitCode::kCompilationRequired) {
        if (odrefresh_status == art::odrefresh::ExitCode::kOkay) {
            LOG(INFO) << "Current artifacts are OK, deleting pending artifacts";
            removeDirectory(kCompOsPendingArtifactsDir);
        }
        return odrefresh_status;
    }

    // No useful current artifacts, lets see if the CompOS ones are ok
    if (access(kCompOsPendingInfoPath, R_OK) != 0 ||
        access(kCompOsPendingInfoSignaturePath, R_OK) != 0) {
        LOG(INFO) << "Missing CompOS info/signature, deleting pending artifacts";
        removeDirectory(kCompOsPendingArtifactsDir);
        return art::odrefresh::ExitCode::kCompilationRequired;
    }

    LOG(INFO) << "Current artifacts are out of date, switching to pending artifacts";
    removeDirectory(kArtArtifactsDir);
    if (!rename(kCompOsPendingArtifactsDir, kArtArtifactsDir)) {
        removeDirectory(kCompOsPendingArtifactsDir);
        return art::odrefresh::ExitCode::kCompilationRequired;
    }

    // Make sure the artifacts we have are genuinely produced by the current
    // instance of CompOS.
    auto compos_info = getComposInfo(compos_key);
    if (!compos_info.ok()) {
        LOG(WARNING) << compos_info.error();
    } else {
        std::map<std::string, std::string> compos_digests(compos_info->file_hashes().begin(),
                                                          compos_info->file_hashes().end());

        auto status = verifyAllFilesUsingCompOs(kArtArtifactsDir, compos_digests, signing_key);
        if (!status.ok()) {
            LOG(WARNING) << "Faild to verify CompOS artifacts: " << status.error();
        } else {
            LOG(INFO) << "CompOS artifacts successfully verified.";
            odrefresh_status = checkArtifacts();
            switch (odrefresh_status) {
            case art::odrefresh::ExitCode::kCompilationRequired:
                // We have verified all the files, and we need to make sure
                // we don't check them against odsign.info which will be out
                // of date.
                *digests_verified = true;
                return odrefresh_status;
            case art::odrefresh::ExitCode::kOkay: {
                // We have digests of all the files, so we can just sign them & save them now.
                // We need to make sure we don't check them against odsign.info which will
                // be out of date.
                auto persisted = persistDigests(compos_digests, signing_key);
                if (!persisted.ok()) {
                    LOG(ERROR) << persisted.error();
                    // Don't try to compile again - if we can't write the digests, things
                    // are pretty bad.
                    return art::odrefresh::ExitCode::kCleanupFailed;
                }
                LOG(INFO) << "Persisted CompOS digests.";
                *digests_verified = true;
                return odrefresh_status;
            }
            default:
                return odrefresh_status;
            }
        }
    }

    // We can't use the existing artifacts, so we will need to generate new
    // ones.
    if (removeDirectory(kArtArtifactsDir) == 0) {
        // We have unsigned artifacts that we can't delete, so it's not safe to continue.
        LOG(ERROR) << "Unable to delete invalid CompOS artifacts";
        return art::odrefresh::ExitCode::kCleanupFailed;
    }

    return art::odrefresh::ExitCode::kCompilationRequired;
}
}  // namespace

int main(int /* argc */, char** argv) {
    android::base::InitLogging(argv, android::base::LogdLogger(android::base::SYSTEM));

    auto errorScopeGuard = []() {
        // In case we hit any error, remove the artifacts and tell Zygote not to use
        // anything
        removeDirectory(kArtArtifactsDir);
        removeDirectory(kCompOsPendingArtifactsDir);
        // Tell init we don't need to use our key anymore
        SetProperty(kOdsignKeyDoneProp, "1");
        // Tell init we're done with verification, and that it was an error
        SetProperty(kOdsignVerificationStatusProp, kOdsignVerificationStatusError);
        SetProperty(kOdsignVerificationDoneProp, "1");
        // Tell init it shouldn't try to restart us - see odsign.rc
        SetProperty(kStopServiceProp, "odsign");
    };
    auto scope_guard = android::base::make_scope_guard(errorScopeGuard);

    if (!android::base::GetBoolProperty("ro.apex.updatable", false)) {
        LOG(INFO) << "Device doesn't support updatable APEX, exiting.";
        return 0;
    }

    auto keystoreResult = KeystoreKey::getInstance();
    if (!keystoreResult.ok()) {
        LOG(ERROR) << "Could not create keystore key: " << keystoreResult.error();
        return -1;
    }
    SigningKey* key = keystoreResult.value();

    bool supportsFsVerity = access(kFsVerityProcPath, F_OK) == 0;
    if (!supportsFsVerity) {
        LOG(INFO) << "Device doesn't support fsverity. Falling back to full verification.";
    }

    bool useCompOs = kUseCompOs && supportsFsVerity && compOsPresent();

    if (supportsFsVerity) {
        auto existing_cert = verifyExistingRootCert(*key);
        if (!existing_cert.ok()) {
            LOG(WARNING) << existing_cert.error();

            // Try to create a new cert
            auto new_cert = createX509RootCert(*key, kSigningKeyCert);
            if (!new_cert.ok()) {
                LOG(ERROR) << "Failed to create X509 certificate: " << new_cert.error();
                // TODO apparently the key become invalid - delete the blob / cert
                return -1;
            }
        } else {
            LOG(INFO) << "Found and verified existing public key certificate: " << kSigningKeyCert;
        }
        auto cert_add_result = addCertToFsVerityKeyring(kSigningKeyCert, "fsv_ods");
        if (!cert_add_result.ok()) {
            LOG(ERROR) << "Failed to add certificate to fs-verity keyring: "
                       << cert_add_result.error();
            return -1;
        }
    }

    art::odrefresh::ExitCode odrefresh_status = art::odrefresh::ExitCode::kCompilationRequired;
    bool digests_verified = false;

    if (useCompOs) {
        auto compos_key = addCompOsCertToFsVerityKeyring(*key);
        if (!compos_key.ok()) {
            odrefresh_status = art::odrefresh::ExitCode::kCompilationRequired;
            LOG(WARNING) << compos_key.error();
        } else {
            odrefresh_status =
                checkCompOsPendingArtifacts(compos_key.value(), *key, &digests_verified);
        }
    } else {
        odrefresh_status = checkArtifacts();
    }

    // The artifacts dir doesn't necessarily need to exist; if the existing
    // artifacts on the system partition are valid, those can be used.
    int err = access(kArtArtifactsDir.c_str(), F_OK);
    // If we receive any error other than ENOENT, be suspicious
    bool artifactsPresent = (err == 0) || (err < 0 && errno != ENOENT);

    if (artifactsPresent && !digests_verified &&
        (odrefresh_status == art::odrefresh::ExitCode::kOkay ||
         odrefresh_status == art::odrefresh::ExitCode::kCompilationRequired)) {
        // If we haven't verified the digests yet, we need to validate them. We
        // need to do this both in case the existing artifacts are okay, but
        // also if odrefresh said that a recompile is required. In the latter
        // case, odrefresh may use partial compilation, and leave some
        // artifacts unchanged.
        auto trusted_digests = getTrustedDigests(*key);

        if (odrefresh_status == art::odrefresh::ExitCode::kOkay) {
            // Tell init we're done with the key; this is a boot time optimization
            // in particular for the no fs-verity case, where we need to do a
            // costly verification. If the files haven't been tampered with, which
            // should be the common path, the verification will succeed, and we won't
            // need the key anymore. If it turns out the artifacts are invalid (eg not
            // in fs-verity) or the hash doesn't match, we won't be able to generate
            // new artifacts without the key, so in those cases, remove the artifacts,
            // and use JIT zygote for the current boot. We should recover automatically
            // by the next boot.
            SetProperty(kOdsignKeyDoneProp, "1");
        }

        auto verificationResult = verifyArtifactsIntegrity(trusted_digests, supportsFsVerity);
        if (!verificationResult.ok()) {
            int num_removed = removeDirectory(kArtArtifactsDir);
            if (num_removed == 0) {
                // If we can't remove the bad artifacts, we shouldn't continue, and
                // instead prevent Zygote from using them (which is taken care of
                // in the exit handler).
                LOG(ERROR) << "Failed to remove unknown artifacts.";
                return -1;
            }
        }
    }

    // Now that we verified existing artifacts, compile if we need to.
    if (odrefresh_status == art::odrefresh::ExitCode::kCompilationRequired) {
        odrefresh_status = compileArtifacts(kForceCompilation);
    }

    if (odrefresh_status == art::odrefresh::ExitCode::kOkay) {
        // No new artifacts generated, and we verified existing ones above, nothing left to do.
        LOG(INFO) << "odrefresh said artifacts are VALID";
    } else if (odrefresh_status == art::odrefresh::ExitCode::kCompilationSuccess ||
               odrefresh_status == art::odrefresh::ExitCode::kCompilationFailed) {
        const bool compiled_all = odrefresh_status == art::odrefresh::ExitCode::kCompilationSuccess;
        LOG(INFO) << "odrefresh compiled " << (compiled_all ? "all" : "partial")
                  << " artifacts, returned " << odrefresh_status;
        Result<std::map<std::string, std::string>> digests;
        if (supportsFsVerity) {
            digests = addFilesToVerityRecursive(kArtArtifactsDir, *key);
        } else {
            // If we can't use verity, just compute the root hashes and store
            // those, so we can reverify them at the next boot.
            digests = computeDigests(kArtArtifactsDir);
        }
        if (!digests.ok()) {
            LOG(ERROR) << digests.error();
            return -1;
        }
        auto persistStatus = persistDigests(*digests, *key);
        if (!persistStatus.ok()) {
            LOG(ERROR) << persistStatus.error();
            return -1;
        }
    } else if (odrefresh_status == art::odrefresh::ExitCode::kCleanupFailed) {
        LOG(ERROR) << "odrefresh failed cleaning up existing artifacts";
        return -1;
    } else {
        LOG(ERROR) << "odrefresh exited unexpectedly, returned " << odrefresh_status;
        return -1;
    }

    LOG(INFO) << "On-device signing done.";

    scope_guard.Disable();
    // At this point, we're done with the key for sure
    SetProperty(kOdsignKeyDoneProp, "1");
    // And we did a successful verification
    SetProperty(kOdsignVerificationStatusProp, kOdsignVerificationStatusValid);
    SetProperty(kOdsignVerificationDoneProp, "1");

    // Tell init it shouldn't try to restart us - see odsign.rc
    SetProperty(kStopServiceProp, "odsign");
    return 0;
}
