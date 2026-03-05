#include "infra/invite_session_repo.h"

#include <optional>
#include <string>
#include <utility>

#include <sqlite3.h>

namespace gatehouse::infra {
namespace {

core::Status StmtErr(int rc, sqlite3* db, const char* what) {
  const char* msg = (db != nullptr) ? sqlite3_errmsg(db) : "sqlite error";
  return core::Status::Error(core::StatusCode::kInternal,
                            std::string(what) + " (rc=" + std::to_string(rc) + "): " + msg);
}

}  // namespace

InviteSessionRepo::InviteSessionRepo(SqliteDb& db) : db_(db) {}

core::Result<void> InviteSessionRepo::Insert(const InviteSessionRow& row) {
  sqlite3* dbh = db_.handle();
  if (!dbh) return core::Result<void>::Err(core::Status::Error(core::StatusCode::kFailedPrecondition, "DB not open"));

  sqlite3_stmt* stmt = nullptr;
  const char* sql =
      "INSERT INTO invite_session(sid,invite_id,created_at,expires_at,consumed_at) VALUES(?,?,?,?,NULL);";
  int rc = sqlite3_prepare_v2(dbh, sql, -1, &stmt, nullptr);
  if (rc != SQLITE_OK) return core::Result<void>::Err(StmtErr(rc, dbh, "prepare(insert invite_session)"));

  (void)sqlite3_bind_text(stmt, 1, row.sid.c_str(), -1, SQLITE_TRANSIENT);
  (void)sqlite3_bind_text(stmt, 2, row.invite_id.c_str(), -1, SQLITE_TRANSIENT);
  (void)sqlite3_bind_int64(stmt, 3, row.created_at);
  (void)sqlite3_bind_int64(stmt, 4, row.expires_at);

  rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  if (rc != SQLITE_DONE) return core::Result<void>::Err(StmtErr(rc, dbh, "step(insert invite_session)"));
  return core::Result<void>::Ok();
}

core::Result<std::optional<InviteSessionRow>> InviteSessionRepo::GetBySid(const std::string& sid) {
  sqlite3* dbh = db_.handle();
  if (!dbh) return core::Result<std::optional<InviteSessionRow>>::Err(
      core::Status::Error(core::StatusCode::kFailedPrecondition, "DB not open"));

  sqlite3_stmt* stmt = nullptr;
  const char* sql =
      "SELECT sid,invite_id,created_at,expires_at,consumed_at FROM invite_session WHERE sid=? LIMIT 1;";
  int rc = sqlite3_prepare_v2(dbh, sql, -1, &stmt, nullptr);
  if (rc != SQLITE_OK) return core::Result<std::optional<InviteSessionRow>>::Err(StmtErr(rc, dbh, "prepare(get invite_session)"));

  (void)sqlite3_bind_text(stmt, 1, sid.c_str(), -1, SQLITE_TRANSIENT);

  rc = sqlite3_step(stmt);
  if (rc == SQLITE_DONE) {
    sqlite3_finalize(stmt);
    return core::Result<std::optional<InviteSessionRow>>::Ok(std::nullopt);
  }
  if (rc != SQLITE_ROW) {
    sqlite3_finalize(stmt);
    return core::Result<std::optional<InviteSessionRow>>::Err(StmtErr(rc, dbh, "step(get invite_session)"));
  }

  InviteSessionRow row;
  row.sid = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
  row.invite_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
  row.created_at = sqlite3_column_int64(stmt, 2);
  row.expires_at = sqlite3_column_int64(stmt, 3);
  row.consumed_at = sqlite3_column_type(stmt, 4) == SQLITE_NULL ? 0 : sqlite3_column_int64(stmt, 4);

  sqlite3_finalize(stmt);
  return core::Result<std::optional<InviteSessionRow>>::Ok(std::optional<InviteSessionRow>(std::move(row)));
}

core::Result<void> InviteSessionRepo::Consume(const std::string& sid, std::int64_t now) {
  sqlite3* dbh = db_.handle();
  if (!dbh) return core::Result<void>::Err(core::Status::Error(core::StatusCode::kFailedPrecondition, "DB not open"));

  sqlite3_stmt* stmt = nullptr;
  const char* sql = "UPDATE invite_session SET consumed_at=? WHERE sid=? AND consumed_at IS NULL;";
  int rc = sqlite3_prepare_v2(dbh, sql, -1, &stmt, nullptr);
  if (rc != SQLITE_OK) return core::Result<void>::Err(StmtErr(rc, dbh, "prepare(consume invite_session)"));

  (void)sqlite3_bind_int64(stmt, 1, now);
  (void)sqlite3_bind_text(stmt, 2, sid.c_str(), -1, SQLITE_TRANSIENT);

  rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  if (rc != SQLITE_DONE) return core::Result<void>::Err(StmtErr(rc, dbh, "step(consume invite_session)"));
  return core::Result<void>::Ok();
}

core::Result<void> InviteSessionRepo::DeleteExpired(std::int64_t now) {
  sqlite3* dbh = db_.handle();
  if (!dbh) return core::Result<void>::Err(core::Status::Error(core::StatusCode::kFailedPrecondition, "DB not open"));

  sqlite3_stmt* stmt = nullptr;
  const char* sql = "DELETE FROM invite_session WHERE expires_at <= ?;";
  int rc = sqlite3_prepare_v2(dbh, sql, -1, &stmt, nullptr);
  if (rc != SQLITE_OK) return core::Result<void>::Err(StmtErr(rc, dbh, "prepare(delete expired invite_session)"));

  (void)sqlite3_bind_int64(stmt, 1, now);

  rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  if (rc != SQLITE_DONE) return core::Result<void>::Err(StmtErr(rc, dbh, "step(delete expired invite_session)"));
  return core::Result<void>::Ok();
}

// ---- profile ----
InviteProfileRepo::InviteProfileRepo(SqliteDb& db) : db_(db) {}

core::Result<void> InviteProfileRepo::Upsert(const InviteProfileRow& row) {
  sqlite3* dbh = db_.handle();
  if (!dbh) return core::Result<void>::Err(core::Status::Error(core::StatusCode::kFailedPrecondition, "DB not open"));

  sqlite3_stmt* stmt = nullptr;
  const char* sql =
      "INSERT INTO invite_profile(invite_id,display_name,created_at,updated_at) VALUES(?,?,?,?) "
      "ON CONFLICT(invite_id) DO UPDATE SET display_name=excluded.display_name, updated_at=excluded.updated_at;";
  int rc = sqlite3_prepare_v2(dbh, sql, -1, &stmt, nullptr);
  if (rc != SQLITE_OK) return core::Result<void>::Err(StmtErr(rc, dbh, "prepare(upsert invite_profile)"));

  (void)sqlite3_bind_text(stmt, 1, row.invite_id.c_str(), -1, SQLITE_TRANSIENT);
  (void)sqlite3_bind_text(stmt, 2, row.display_name.c_str(), -1, SQLITE_TRANSIENT);
  (void)sqlite3_bind_int64(stmt, 3, row.created_at);
  (void)sqlite3_bind_int64(stmt, 4, row.updated_at);

  rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  if (rc != SQLITE_DONE) return core::Result<void>::Err(StmtErr(rc, dbh, "step(upsert invite_profile)"));
  return core::Result<void>::Ok();
}

core::Result<std::optional<InviteProfileRow>> InviteProfileRepo::GetByInviteId(const std::string& invite_id) {
  sqlite3* dbh = db_.handle();
  if (!dbh) return core::Result<std::optional<InviteProfileRow>>::Err(
      core::Status::Error(core::StatusCode::kFailedPrecondition, "DB not open"));

  sqlite3_stmt* stmt = nullptr;
  const char* sql = "SELECT invite_id,COALESCE(display_name,''),created_at,updated_at FROM invite_profile WHERE invite_id=? LIMIT 1;";
  int rc = sqlite3_prepare_v2(dbh, sql, -1, &stmt, nullptr);
  if (rc != SQLITE_OK) return core::Result<std::optional<InviteProfileRow>>::Err(StmtErr(rc, dbh, "prepare(get invite_profile)"));

  (void)sqlite3_bind_text(stmt, 1, invite_id.c_str(), -1, SQLITE_TRANSIENT);

  rc = sqlite3_step(stmt);
  if (rc == SQLITE_DONE) {
    sqlite3_finalize(stmt);
    return core::Result<std::optional<InviteProfileRow>>::Ok(std::nullopt);
  }
  if (rc != SQLITE_ROW) {
    sqlite3_finalize(stmt);
    return core::Result<std::optional<InviteProfileRow>>::Err(StmtErr(rc, dbh, "step(get invite_profile)"));
  }

  InviteProfileRow row;
  row.invite_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
  row.display_name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
  row.created_at = sqlite3_column_int64(stmt, 2);
  row.updated_at = sqlite3_column_int64(stmt, 3);

  sqlite3_finalize(stmt);
  return core::Result<std::optional<InviteProfileRow>>::Ok(std::optional<InviteProfileRow>(std::move(row)));
}

}  // namespace gatehouse::infra
