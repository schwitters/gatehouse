#pragma once

#include <sqlite3.h>

#include <cstdint>
#include <string>

#include "core/result.h"
#include "core/status.h"

namespace gatehouse::infra {

class SqliteDb final {
 public:
  SqliteDb() = default;
  ~SqliteDb();

  SqliteDb(const SqliteDb&) = delete;
  SqliteDb& operator=(const SqliteDb&) = delete;

  SqliteDb(SqliteDb&&) = delete;
  SqliteDb& operator=(SqliteDb&&) = delete;

  [[nodiscard]] core::Result<void> Open(std::string path);
  void Close();

  [[nodiscard]] bool is_open() const { return db_ != nullptr; }
  [[nodiscard]] sqlite3* handle() const { return db_; }
  [[nodiscard]] const std::string& path() const { return path_; }

  [[nodiscard]] core::Result<void> Exec(std::string_view sql);

  [[nodiscard]] core::Result<std::int64_t> GetPragmaUserVersion();
  [[nodiscard]] core::Result<void> SetPragmaUserVersion(std::int64_t v);

 private:
  static core::Status MakeSqliteStatus(int rc, sqlite3* db, std::string_view what);

  sqlite3* db_{nullptr};
  std::string path_;
};

}  // namespace gatehouse::infra
