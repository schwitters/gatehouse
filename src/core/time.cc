#include "core/time.h"

#include <chrono>
#include <cstdint>

namespace gatehouse::core {

std::int64_t UnixNow() {
  using namespace std::chrono;
  return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

}  // namespace gatehouse::core
