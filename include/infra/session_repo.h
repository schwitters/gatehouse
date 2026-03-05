#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "core/result.h"
#include "infra/sqlite_db.h"

namespace gatehouse::infra {

struct SessionRow {
  std::string sid;
  std::string uid;
  std::string tenant_id;
  std::int64_t created_at{0};
  std::int64_t expires_at{0};
  std::int32_t mfa_state{0};

  // New in schema v2
  std::string ticket_id;  // may be empty (demo mode)
};

class SessionRepo final {
 public:
  explicit SessionRepo(SqliteDb& db);

  [[nodiscard]] core::Result<void> Insert(const SessionRow& row,
                                         const std::vector<std::uint8_t>& csrf_secret);

  [[nodiscard]] core::Result<std::optional<SessionRow>> GetBySid(const std::string& sid);

  [[nodiscard]] core::Result<void> DeleteBySid(const std::string& sid);

  [[nodiscard]] core::Result<void> DeleteExpired(std::int64_t now);

 private:
  SqliteDb& db_;
};

}  // namespace gatehouse::infra
