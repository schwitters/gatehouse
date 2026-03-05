#include "core/random.h"

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include <fcntl.h>
#include <unistd.h>

namespace gatehouse::core {

Result<std::vector<std::uint8_t>> RandomBytes(std::size_t n) {
  std::vector<std::uint8_t> out;
  out.resize(n);

  const int fd = ::open("/dev/urandom", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return Result<std::vector<std::uint8_t>>::Err(
        Status::Error(StatusCode::kUnavailable,
                      std::string("open(/dev/urandom) failed: ") + std::strerror(errno)));
  }

  std::size_t off = 0;
  while (off < n) {
    const ssize_t got = ::read(fd, out.data() + off, n - off);
    if (got < 0) {
      const int e = errno;
      ::close(fd);
      return Result<std::vector<std::uint8_t>>::Err(
          Status::Error(StatusCode::kUnavailable,
                        std::string("read(/dev/urandom) failed: ") + std::strerror(e)));
    }
    if (got == 0) {
      ::close(fd);
      return Result<std::vector<std::uint8_t>>::Err(
          Status::Error(StatusCode::kUnavailable, "read(/dev/urandom) returned EOF"));
    }
    off += static_cast<std::size_t>(got);
  }

  ::close(fd);
  return Result<std::vector<std::uint8_t>>::Ok(std::move(out));
}

}  // namespace gatehouse::core
