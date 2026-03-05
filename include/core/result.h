#pragma once

#include <utility>

#include "core/status.h"

namespace gatehouse::core {

// Minimal Result<T> (no exceptions). Move-only friendly.
template <typename T>
class Result final {
 public:
  static Result Ok(T value) { return Result(Status::Ok(), std::move(value)); }
  static Result Err(Status status) { return Result(std::move(status)); }

  Result(const Result&) = delete;
  Result& operator=(const Result&) = delete;

  Result(Result&&) noexcept = default;
  Result& operator=(Result&&) noexcept = default;

  [[nodiscard]] bool ok() const { return status_.ok(); }
  [[nodiscard]] const Status& status() const { return status_; }

  // Precondition: ok()
  [[nodiscard]] T& value() & { return value_; }
  [[nodiscard]] const T& value() const& { return value_; }
  [[nodiscard]] T&& value() && { return std::move(value_); }

 private:
  explicit Result(Status status) : status_(std::move(status)) {}
  Result(Status status, T value) : status_(std::move(status)), value_(std::move(value)) {}

  Status status_;
  T value_{};
};

// Specialization for void
template <>
class Result<void> final {
 public:
  static Result Ok() { return Result(Status::Ok()); }
  static Result Err(Status status) { return Result(std::move(status)); }

  Result(const Result&) = delete;
  Result& operator=(const Result&) = delete;

  Result(Result&&) noexcept = default;
  Result& operator=(Result&&) noexcept = default;

  [[nodiscard]] bool ok() const { return status_.ok(); }
  [[nodiscard]] const Status& status() const { return status_; }

 private:
  explicit Result(Status status) : status_(std::move(status)) {}

  Status status_;
};

}  // namespace gatehouse::core
