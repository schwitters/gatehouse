#include "infra/sqlite_db.h"

#include <cassert>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

namespace gatehouse::infra {

SqliteDb::~SqliteDb() { Close(); }

core::Status SqliteDb::MakeSqliteStatus(int rc, sqlite3* db, std::string_view what) {
  const char* msg = (db != nullptr) ? sqlite3_errmsg(db) : "sqlite error";
  return core::Status::Error(core::StatusCode::kInternal,
                            std::string(what) + " (rc=" + std::to_string(rc) + "): " + msg);
}

core::Result<void> SqliteDb::Open(std::string path) {
  if (db_ != nullptr) {
    return core::Result<void>::Err(
        core::Status::Error(core::StatusCode::kFailedPrecondition, "DB already open"));
  }

  sqlite3* db = nullptr;
  const int rc = sqlite3_open_v2(path.c_str(), &db,
                                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                                nullptr);
  if (rc != SQLITE_OK) {
    core::Status st = MakeSqliteStatus(rc, db, "sqlite3_open_v2");
    if (db != nullptr) sqlite3_close(db);
    return core::Result<void>::Err(std::move(st));
  }

  db_ = db;
  path_ = std::move(path);

  // Reasonable safety defaults.
  (void)Exec("PRAGMA foreign_keys=ON;");
  (void)Exec("PRAGMA journal_mode=WAL;");
  (void)Exec("PRAGMA synchronous=NORMAL;");
  return core::Result<void>::Ok();
}

void SqliteDb::Close() {
  if (db_ == nullptr) return;
  sqlite3_close(db_);
  db_ = nullptr;
  path_.clear();
}

core::Result<void> SqliteDb::Exec(std::string_view sql) {
  if (db_ == nullptr) {
    return core::Result<void>::Err(
        core::Status::Error(core::StatusCode::kFailedPrecondition, "DB not open"));
  }

  char* err = nullptr;
  const int rc = sqlite3_exec(db_, std::string(sql).c_str(), nullptr, nullptr, &err);
  if (rc != SQLITE_OK) {
    std::string msg = (err != nullptr) ? err : "sqlite exec error";
    sqlite3_free(err);
    return core::Result<void>::Err(core::Status::Error(
        core::StatusCode::kInternal,
        "sqlite3_exec failed: " + msg));
  }
  return core::Result<void>::Ok();
}

core::Result<std::int64_t> SqliteDb::GetPragmaUserVersion() {
  if (db_ == nullptr) {
    return core::Result<std::int64_t>::Err(
        core::Status::Error(core::StatusCode::kFailedPrecondition, "DB not open"));
  }

  sqlite3_stmt* stmt = nullptr;
  const int rc = sqlite3_prepare_v2(db_, "PRAGMA user_version;", -1, &stmt, nullptr);
  if (rc != SQLITE_OK) {
    return core::Result<std::int64_t>::Err(MakeSqliteStatus(rc, db_, "sqlite3_prepare_v2"));
  }

  std::int64_t v = 0;
  const int step_rc = sqlite3_step(stmt);
  if (step_rc == SQLITE_ROW) {
    v = sqlite3_column_int64(stmt, 0);
  } else if (step_rc != SQLITE_DONE) {
    sqlite3_finalize(stmt);
    return core::Result<std::int64_t>::Err(MakeSqliteStatus(step_rc, db_, "sqlite3_step"));
  }

  sqlite3_finalize(stmt);
  return core::Result<std::int64_t>::Ok(v);
}

core::Result<void> SqliteDb::SetPragmaUserVersion(std::int64_t v) {
  return Exec("PRAGMA user_version=" + std::to_string(v) + ";");
}

}  // namespace gatehouse::infra
