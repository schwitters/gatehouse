#pragma once

#include <sqlite3.h>

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

#include "core/result.h"
#include "core/status.h"

namespace gatehouse::infra {

class SqliteDb final {
 public:
  SqliteDb() = default;

  // Each HTTP worker owns a connection; external I/O never holds a database
  // lock.
  [[nodiscard]] core::Result<void> ConnectForThread();
  ~SqliteDb();

  SqliteDb(const SqliteDb&) = delete;
  SqliteDb& operator=(const SqliteDb&) = delete;

  SqliteDb(SqliteDb&&) = delete;
  SqliteDb& operator=(SqliteDb&&) = delete;

  [[nodiscard]] core::Result<void> Open(std::string path);
  void Close();

  [[nodiscard]] bool is_open() const { return db_ != nullptr; }
  [[nodiscard]] sqlite3* handle() const;
  [[nodiscard]] const std::string& path() const { return path_; }

  [[nodiscard]] core::Result<void> Exec(std::string_view sql);

  [[nodiscard]] core::Result<std::int64_t> GetPragmaUserVersion();
  [[nodiscard]] core::Result<void> SetPragmaUserVersion(std::int64_t v);

 private:
  static core::Status MakeSqliteStatus(int rc, sqlite3* db,
                                       std::string_view what);

  std::thread::id owner_thread_;
  mutable std::mutex connections_mutex_;
  std::unordered_map<std::thread::id, std::unique_ptr<SqliteDb>> connections_;
  sqlite3* db_{nullptr};
  std::string path_;
};

}  // namespace gatehouse::infra
