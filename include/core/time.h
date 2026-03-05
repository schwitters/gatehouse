#pragma once

#include <cstdint>

namespace gatehouse::core {

// Unix epoch seconds (UTC).
[[nodiscard]] std::int64_t UnixNow();

}  // namespace gatehouse::core
