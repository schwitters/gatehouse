#include "core/status.h"

#include <cstdint>
#include <string>

namespace gatehouse::core {

std::string Status::ToString() const {
  if (ok()) return "OK";
  return "ERR(" + std::to_string(static_cast<std::uint32_t>(code_)) + "): " + message_;
}

}  // namespace gatehouse::core
