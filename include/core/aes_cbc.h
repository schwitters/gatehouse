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

// AES-128-CBC encrypt with PKCS7 padding and caller-supplied IV.
// Returns ciphertext only (IV is NOT prepended to the output).
// key16 must be exactly 16 bytes; iv16 must be exactly 16 bytes.
[[nodiscard]] Result<std::vector<std::uint8_t>> Aes128CbcEncryptWithIv(
    const std::vector<std::uint8_t>& key16,
    const std::vector<std::uint8_t>& iv16,
    const std::vector<std::uint8_t>& plaintext);

// AES-CBC encrypt, key-size-agnostic (16 → AES-128, 24 → AES-192, 32 → AES-256).
// Generates a random 16-byte IV internally.
// Returns IV (16 bytes) || ciphertext.
// Mirrors Java: new SecretKeySpec(keyBytes, "AES") — key length determines cipher.
[[nodiscard]] Result<std::vector<std::uint8_t>> AesCbcEncrypt(
    const std::vector<std::uint8_t>& key,
    const std::vector<std::uint8_t>& plaintext);

// AES-CBC encrypt, key-size-agnostic, with caller-supplied IV.
// Returns ciphertext only — IV is NOT prepended.
// key must be 16, 24, or 32 bytes; iv must be exactly 16 bytes.
// Used for Guacamole: AES/CBC/PKCS5Padding with a fixed null IV, no IV in output.
[[nodiscard]] Result<std::vector<std::uint8_t>> AesCbcEncryptWithIv(
    const std::vector<std::uint8_t>& key,
    const std::vector<std::uint8_t>& iv16,
    const std::vector<std::uint8_t>& plaintext);

// Standard Base64 encode (with = padding).
[[nodiscard]] std::string Base64Encode(const std::vector<std::uint8_t>& data);

// URL-safe Base64 encode: + → -, / → _, no = padding.
// Used for Guacamole Encrypted JSON data parameter.
[[nodiscard]] std::string Base64UrlEncode(const std::vector<std::uint8_t>& data);

}  // namespace gatehouse::core
