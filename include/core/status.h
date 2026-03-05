#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace gatehouse::core {

enum class StatusCode : std::uint32_t {
  kOk = 0,
  kCancelled = 1,
  kInvalidArgument = 2,
  kNotFound = 3,
  kAlreadyExists = 4,
  kUnauthenticated = 5,
  kPermissionDenied = 6,
  kResourceExhausted = 7,
  kFailedPrecondition = 8,
  kOutOfRange = 9,
  kUnimplemented = 10,
  kInternal = 11,
  kUnavailable = 12,
  kDataLoss = 13,
};

class Status final {
 public:
  constexpr Status() = default;

  static Status Ok() { return Status(StatusCode::kOk, {}); }

  static Status Error(StatusCode code, std::string message) {
    return Status(code, std::move(message));
  }

  [[nodiscard]] constexpr bool ok() const { return code_ == StatusCode::kOk; }
  [[nodiscard]] constexpr StatusCode code() const { return code_; }
  [[nodiscard]] const std::string& message() const { return message_; }

  [[nodiscard]] std::string ToString() const;

 private:
  Status(StatusCode code, std::string message) : code_(code), message_(std::move(message)) {}

  StatusCode code_{StatusCode::kOk};
  std::string message_;
};

}  // namespace gatehouse::core
