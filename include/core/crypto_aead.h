#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "core/result.h"

namespace gatehouse::core {

[[nodiscard]] Result<std::vector<std::uint8_t>> HexDecode(std::string_view hex);

// AES-256-GCM: Encrypt -> ciphertext || tag(16)
[[nodiscard]] Result<std::vector<std::uint8_t>> Aes256GcmEncrypt(
    const std::vector<std::uint8_t>& key32,
    const std::vector<std::uint8_t>& nonce12,
    std::string_view aad,
    const std::vector<std::uint8_t>& plaintext);

// AES-256-GCM: Decrypt expects ciphertext||tag(16)
[[nodiscard]] Result<std::vector<std::uint8_t>> Aes256GcmDecrypt(
    const std::vector<std::uint8_t>& key32,
    const std::vector<std::uint8_t>& nonce12,
    std::string_view aad,
    const std::vector<std::uint8_t>& ciphertext_and_tag);

}  // namespace gatehouse::core
