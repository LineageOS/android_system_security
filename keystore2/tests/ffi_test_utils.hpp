#pragma once

#include "rust/cxx.h"

bool validateCertChain(rust::Vec<rust::u8> cert_buf, uint32_t cert_len, bool strict_issuer_check);
