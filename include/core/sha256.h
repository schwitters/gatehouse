#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "core/result.h"

namespace gatehouse::core {

// SHA-256 digest.
[[nodiscard]] Result<std::vector<std::uint8_t>> Sha256(const std::vector<std::uint8_t>& data);

// HMAC-SHA256: returns 32-byte MAC.
[[nodiscard]] Result<std::vector<std::uint8_t>> HmacSha256(
    const std::vector<std::uint8_t>& key,
    const std::vector<std::uint8_t>& data);

// URL-safe base64 without padding for bytes (for tokens). (Not needed for hashing, only for display.)
[[nodiscard]] std::string Base64UrlNoPad(const std::vector<std::uint8_t>& data);

}  // namespace gatehouse::core
