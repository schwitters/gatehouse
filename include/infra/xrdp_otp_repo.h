#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "core/result.h"
#include "infra/sqlite_db.h"

namespace gatehouse::infra {

struct XrdpOtpRow {
  std::string xrdp_otp_id;
  std::string uid;
  std::string tenant_id{"default"};
  std::string host_id;

  std::vector<std::uint8_t> otp_hash;  // currently raw random bytes; later HMAC
  std::int64_t issued_at{0};
  std::int64_t expires_at{0};
  std::int64_t consumed_at{0};

  std::int32_t max_attempts{3};
  std::int32_t attempts{0};

  std::string issued_by_sid;
  std::string ticket_id;
};

class XrdpOtpRepo final {
 public:
  explicit XrdpOtpRepo(SqliteDb& db);

  [[nodiscard]] core::Result<void> Insert(const XrdpOtpRow& row);

  // Verify+consume atomically. Returns true on success.
  [[nodiscard]] core::Result<bool> VerifyAndConsume(const std::string& uid, const std::string& host_id,
                                                    const std::vector<std::uint8_t>& otp_hash,
                                                    std::int64_t now);

 private:
  SqliteDb& db_;
};

}  // namespace gatehouse::infra
