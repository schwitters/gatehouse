#include "core/hex.h"

#include <cstdint>
#include <string>
#include <vector>

namespace gatehouse::core {

std::string HexEncode(const std::vector<std::uint8_t>& bytes) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.resize(bytes.size() * 2);
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    const std::uint8_t b = bytes[i];
    out[i * 2 + 0] = kHex[(b >> 4) & 0x0F];
    out[i * 2 + 1] = kHex[(b >> 0) & 0x0F];
  }
  return out;
}

}  // namespace gatehouse::core
