#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "core/result.h"

namespace gatehouse::core {

// AES-128-CBC encrypt with PKCS7 padding.
// Generates a random 16-byte IV internally.
// Returns IV (16 bytes) || ciphertext.
// key16 must be exactly 16 bytes.
[[nodiscard]] Result<std::vector<std::uint8_t>> Aes128CbcEncrypt(
    const std::vector<std::uint8_t>& key16,
    const std::vector<std::uint8_t>& plaintext);

// Standard Base64 encode (with = padding).
[[nodiscard]] std::string Base64Encode(const std::vector<std::uint8_t>& data);

// URL-safe Base64 encode: + → -, / → _, no = padding.
// Used for Guacamole Encrypted JSON data parameter.
[[nodiscard]] std::string Base64UrlEncode(const std::vector<std::uint8_t>& data);

}  // namespace gatehouse::core
