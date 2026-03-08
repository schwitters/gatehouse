#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "core/result.h"
#include "infra/sqlite_db.h"

namespace gatehouse::infra {

struct InviteOtpRow {
  std::string otp_id;
  std::string sid;
  std::vector<std::uint8_t> otp_hash;
  std::int64_t issued_at{0};
  std::int64_t expires_at{0};
  std::int32_t attempts{0};
  std::int32_t max_attempts{5};
  std::int64_t consumed_at{0};
};

class InviteOtpRepo final {
 public:
  explicit InviteOtpRepo(SqliteDb& db);

  [[nodiscard]] core::Result<void> Insert(const InviteOtpRow& row);

  // Returns true if otp verified+consumed.
  [[nodiscard]] core::Result<bool> VerifyAndConsume(const std::string& sid,
                                                    const std::vector<std::uint8_t>& otp_hash,
                                                    std::int64_t now);

  // Cleanup previous OTPs for sid (optional best-effort).
  [[nodiscard]] core::Result<void> DeleteBySid(const std::string& sid);

  // Checks if there is a consumed OTP for sid (i.e., step-up verified)
  [[nodiscard]] core::Result<std::optional<std::int64_t>> GetLastIssuedAt(const std::string& sid);

  [[nodiscard]] core::Result<bool> IsVerified(const std::string& sid);

 private:
  SqliteDb& db_;
};

}  // namespace gatehouse::infra
