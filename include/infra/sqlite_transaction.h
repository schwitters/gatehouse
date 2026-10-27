#pragma once

#include "infra/sqlite_db.h"

namespace gatehouse::infra {

// Destruction rolls back unfinished transactions; failures are reported to
// stderr.
class SqliteTransaction final {
 public:
  explicit SqliteTransaction(SqliteDb& db) : db_(db) {}
  ~SqliteTransaction();
  SqliteTransaction(const SqliteTransaction&) = delete;
  SqliteTransaction& operator=(const SqliteTransaction&) = delete;
  [[nodiscard]] core::Result<void> Begin();
  [[nodiscard]] core::Result<void> Commit();

 private:
  SqliteDb& db_;
  bool active_{false};
};

}  // namespace gatehouse::infra
