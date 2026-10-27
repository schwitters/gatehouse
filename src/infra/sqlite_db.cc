#include "infra/sqlite_db.h"

#include <cassert>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

#include "infra/logging.h"

namespace gatehouse::infra {

SqliteDb::~SqliteDb() { Close(); }

core::Status SqliteDb::MakeSqliteStatus(int rc, sqlite3* db,
                                        std::string_view what) {
  const char* msg = (db != nullptr) ? sqlite3_errmsg(db) : "sqlite error";
  return core::Status::Error(
      core::StatusCode::kInternal,
      std::string(what) + " (rc=" + std::to_string(rc) + "): " + msg);
}

core::Result<void> SqliteDb::Open(std::string path) {
  if (db_ != nullptr) {
    return core::Result<void>::Err(core::Status::Error(
        core::StatusCode::kFailedPrecondition, "DB already open"));
  }

  sqlite3* db = nullptr;
  const int rc = sqlite3_open_v2(
      path.c_str(), &db,
      SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
      nullptr);
  if (rc != SQLITE_OK) {
    core::Status st = MakeSqliteStatus(rc, db, "sqlite3_open_v2");
    if (db != nullptr) sqlite3_close(db);
    return core::Result<void>::Err(std::move(st));
  }

  db_ = db;
  path_ = std::move(path);
  owner_thread_ = std::this_thread::get_id();

  constexpr int kBusyTimeoutMilliseconds = 5000;
  if (sqlite3_busy_timeout(db_, kBusyTimeoutMilliseconds) != SQLITE_OK) {
    auto error = MakeSqliteStatus(sqlite3_errcode(db_), db_, "busy timeout");
    Close();
    return core::Result<void>::Err(error);
  }
  for (const auto* pragma :
       {"PRAGMA foreign_keys=ON;", "PRAGMA journal_mode=WAL;",
        "PRAGMA synchronous=NORMAL;"}) {
    auto configured = Exec(pragma);
    if (!configured.ok()) {
      auto error = configured.status();
      Close();
      return core::Result<void>::Err(error);
    }
  }
  return core::Result<void>::Ok();
}

sqlite3* SqliteDb::handle() const {
  std::lock_guard<std::mutex> lock(connections_mutex_);
  auto it = connections_.find(std::this_thread::get_id());
  if (it != connections_.end()) return it->second->db_;
  return std::this_thread::get_id() == owner_thread_ ? db_ : nullptr;
}

core::Result<void> SqliteDb::ConnectForThread() {
  std::lock_guard<std::mutex> lock(connections_mutex_);
  auto id = std::this_thread::get_id();
  if (db_ == nullptr)
    return core::Result<void>::Err(core::Status::Error(
        core::StatusCode::kFailedPrecondition, "Database is closed"));
  if (id == owner_thread_ || connections_.contains(id))
    return core::Result<void>::Ok();
  if (path_.empty() || path_ == ":memory:") {
    return core::Result<void>::Err(
        core::Status::Error(core::StatusCode::kFailedPrecondition,
                            "Worker connections require a file database"));
  }
  auto connection = std::make_unique<SqliteDb>();
  auto opened = connection->Open(path_);
  if (!opened.ok()) return opened;
  connections_.emplace(id, std::move(connection));
  return core::Result<void>::Ok();
}

void SqliteDb::Close() {
  // The server must join its workers before destroying the connection owner.
  connections_.clear();
  if (db_ == nullptr) return;
  if (sqlite3_close_v2(db_) != SQLITE_OK) LogOperationFailure("database close");
  db_ = nullptr;
  path_.clear();
}

core::Result<void> SqliteDb::Exec(std::string_view sql) {
  sqlite3* connection = handle();
  if (connection == nullptr) {
    return core::Result<void>::Err(core::Status::Error(
        core::StatusCode::kFailedPrecondition, "DB not open"));
  }

  char* err = nullptr;
  const int rc = sqlite3_exec(connection, std::string(sql).c_str(), nullptr,
                              nullptr, &err);
  if (rc != SQLITE_OK) {
    std::string msg = (err != nullptr) ? err : "sqlite exec error";
    sqlite3_free(err);
    return core::Result<void>::Err(core::Status::Error(
        core::StatusCode::kInternal, "sqlite3_exec failed: " + msg));
  }
  return core::Result<void>::Ok();
}

core::Result<std::int64_t> SqliteDb::GetPragmaUserVersion() {
  sqlite3* connection = handle();
  if (connection == nullptr) {
    return core::Result<std::int64_t>::Err(core::Status::Error(
        core::StatusCode::kFailedPrecondition, "DB not open"));
  }

  sqlite3_stmt* stmt = nullptr;
  const int rc = sqlite3_prepare_v2(connection, "PRAGMA user_version;", -1,
                                    &stmt, nullptr);
  if (rc != SQLITE_OK) {
    return core::Result<std::int64_t>::Err(
        MakeSqliteStatus(rc, connection, "sqlite3_prepare_v2"));
  }

  std::int64_t v = 0;
  const int step_rc = sqlite3_step(stmt);
  if (step_rc == SQLITE_ROW) {
    v = sqlite3_column_int64(stmt, 0);
  } else if (step_rc != SQLITE_DONE) {
    sqlite3_finalize(stmt);
    return core::Result<std::int64_t>::Err(
        MakeSqliteStatus(step_rc, connection, "sqlite3_step"));
  }

  sqlite3_finalize(stmt);
  return core::Result<std::int64_t>::Ok(v);
}

core::Result<void> SqliteDb::SetPragmaUserVersion(std::int64_t v) {
  return Exec("PRAGMA user_version=" + std::to_string(v) + ";");
}

}  // namespace gatehouse::infra
