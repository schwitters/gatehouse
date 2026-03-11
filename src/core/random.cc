#include "core/random.h"

#include <cstdint>
#include <string>
#include <vector>

#include <openssl/rand.h>
#include <openssl/err.h>

namespace gatehouse::core {

Result<std::vector<std::uint8_t>> RandomBytes(std::size_t n) {
  if (n == 0) {
    return Result<std::vector<std::uint8_t>>::Ok({});
  }

  std::vector<std::uint8_t> out(n);
  if (RAND_bytes(out.data(), static_cast<int>(n)) != 1) {
    return Result<std::vector<std::uint8_t>>::Err(
        Status::Error(StatusCode::kUnavailable,
                      "RAND_bytes failed: OpenSSL PRNG not seeded or error"));
  }
  return Result<std::vector<std::uint8_t>>::Ok(std::move(out));
}

}  // namespace gatehouse::core
