#include "ffi_test_utils.hpp"

#include <iostream>

#include <KeyMintAidlTestBase.h>
#include <aidl/android/hardware/security/keymint/ErrorCode.h>

#include <vector>

using aidl::android::hardware::security::keymint::ErrorCode;

#define TAG_SEQUENCE 0x30
#define LENGTH_MASK 0x80
#define LENGTH_VALUE_MASK 0x7F

/* This function extracts a certificate from the certs_chain_buffer at the given
 * offset. Each DER encoded certificate starts with TAG_SEQUENCE followed by the
 * total length of the certificate. The length of the certificate is determined
 * as per ASN.1 encoding rules for the length octets.
 *
 * @param certs_chain_buffer: buffer containing DER encoded X.509 certificates
 *                            arranged sequentially.
 * @data_size: Length of the DER encoded X.509 certificates buffer.
 * @index: DER encoded X.509 certificates buffer offset.
 * @cert: Encoded certificate to be extracted from buffer as outcome.
 * @return: ErrorCode::OK on success, otherwise ErrorCode::UNKNOWN_ERROR.
 */
ErrorCode
extractCertFromCertChainBuffer(uint8_t* certs_chain_buffer, int certs_chain_buffer_size, int& index,
                               aidl::android::hardware::security::keymint::Certificate& cert) {
    if (index >= certs_chain_buffer_size) {
        return ErrorCode::UNKNOWN_ERROR;
    }

    uint32_t length = 0;
    std::vector<uint8_t> cert_bytes;
    if (certs_chain_buffer[index] == TAG_SEQUENCE) {
        // Short form. One octet. Bit 8 has value "0" and bits 7-1 give the length.
        if (0 == (certs_chain_buffer[index + 1] & LENGTH_MASK)) {
            length = (uint32_t)certs_chain_buffer[index];
            // Add SEQ and Length fields
            length += 2;
        } else {
            // Long form. Two to 127 octets. Bit 8 of first octet has value "1" and
            // bits 7-1 give the number of additional length octets. Second and following
            // octets give the actual length.
            int additionalBytes = certs_chain_buffer[index + 1] & LENGTH_VALUE_MASK;
            if (additionalBytes == 0x01) {
                length = certs_chain_buffer[index + 2];
                // Add SEQ and Length fields
                length += 3;
            } else if (additionalBytes == 0x02) {
                length = (certs_chain_buffer[index + 2] << 8 | certs_chain_buffer[index + 3]);
                // Add SEQ and Length fields
                length += 4;
            } else if (additionalBytes == 0x04) {
                length = certs_chain_buffer[index + 2] << 24;
                length |= certs_chain_buffer[index + 3] << 16;
                length |= certs_chain_buffer[index + 4] << 8;
                length |= certs_chain_buffer[index + 5];
                // Add SEQ and Length fields
                length += 6;
            } else {
                // Length is larger than uint32_t max limit.
                return ErrorCode::UNKNOWN_ERROR;
            }
        }
        cert_bytes.insert(cert_bytes.end(), (certs_chain_buffer + index),
                          (certs_chain_buffer + index + length));
        index += length;

        for (int i = 0; i < cert_bytes.size(); i++) {
            cert.encodedCertificate = std::move(cert_bytes);
        }
    } else {
        // SEQUENCE TAG MISSING.
        return ErrorCode::UNKNOWN_ERROR;
    }

    return ErrorCode::OK;
}

ErrorCode getCertificateChain(
    rust::Vec<rust::u8>& chainBuffer,
    std::vector<aidl::android::hardware::security::keymint::Certificate>& certChain) {
    uint8_t* data = chainBuffer.data();
    int index = 0;
    int data_size = chainBuffer.size();

    while (index < data_size) {
        aidl::android::hardware::security::keymint::Certificate cert =
            aidl::android::hardware::security::keymint::Certificate();
        if (extractCertFromCertChainBuffer(data, data_size, index, cert) != ErrorCode::OK) {
            return ErrorCode::UNKNOWN_ERROR;
        }
        certChain.push_back(std::move(cert));
    }
    return ErrorCode::OK;
}

bool validateCertChain(rust::Vec<rust::u8> cert_buf, uint32_t cert_len, bool strict_issuer_check) {
    std::vector<aidl::android::hardware::security::keymint::Certificate> cert_chain =
        std::vector<aidl::android::hardware::security::keymint::Certificate>();
    if (cert_len <= 0) {
        return false;
    }
    if (getCertificateChain(cert_buf, cert_chain) != ErrorCode::OK) {
        return false;
    }

    for (int i = 0; i < cert_chain.size(); i++) {
        std::cout << cert_chain[i].toString() << "\n";
    }
    auto result = aidl::android::hardware::security::keymint::test::ChainSignaturesAreValid(
        cert_chain, strict_issuer_check);

    if (result == testing::AssertionSuccess()) return true;

    return false;
}
