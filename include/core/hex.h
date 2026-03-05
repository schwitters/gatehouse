#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace gatehouse::core {

// Encodes bytes to lowercase hex.
[[nodiscard]] std::string HexEncode(const std::vector<std::uint8_t>& bytes);

}  // namespace gatehouse::core
