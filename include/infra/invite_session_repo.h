#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "core/result.h"
#include "infra/sqlite_db.h"

namespace gatehouse::infra {

struct InviteSessionRow {
  std::string sid;
  std::string invite_id;
  std::int64_t created_at{0};
  std::int64_t expires_at{0};
  std::int64_t consumed_at{0};
};

class InviteSessionRepo final {
 public:
  explicit InviteSessionRepo(SqliteDb& db);

  [[nodiscard]] core::Result<void> Insert(const InviteSessionRow& row);

  [[nodiscard]] core::Result<std::optional<InviteSessionRow>> GetBySid(const std::string& sid);

  [[nodiscard]] core::Result<void> Consume(const std::string& sid, std::int64_t now);

  [[nodiscard]] core::Result<void> DeleteExpired(std::int64_t now);

 private:
  SqliteDb& db_;
};

struct InviteProfileRow {
  std::string invite_id;
  std::string display_name;
  std::int64_t created_at{0};
  std::int64_t updated_at{0};
};

class InviteProfileRepo final {
 public:
  explicit InviteProfileRepo(SqliteDb& db);

  [[nodiscard]] core::Result<void> Upsert(const InviteProfileRow& row);

  [[nodiscard]] core::Result<std::optional<InviteProfileRow>> GetByInviteId(const std::string& invite_id);

 private:
  SqliteDb& db_;
};

}  // namespace gatehouse::infra
