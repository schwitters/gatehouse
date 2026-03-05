#pragma once

#include <cstdint>
#include <vector>

#include "core/result.h"

namespace gatehouse::core {

// Reads cryptographically strong random bytes from the OS.
[[nodiscard]] Result<std::vector<std::uint8_t>> RandomBytes(std::size_t n);

}  // namespace gatehouse::core
