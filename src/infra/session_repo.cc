#include "infra/session_repo.h"

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <sqlite3.h>

namespace gatehouse::infra {
namespace {

core::Status MakeStmtStatus(int rc, sqlite3* db, const char* what) {
  const char* msg = (db != nullptr) ? sqlite3_errmsg(db) : "sqlite error";
  return core::Status::Error(core::StatusCode::kInternal,
                            std::string(what) + " (rc=" + std::to_string(rc) + "): " + msg);
}

std::string BlobToHex(const void* data, int size) {
  const auto* bytes = static_cast<const std::uint8_t*>(data);
  static const char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(static_cast<std::size_t>(size) * 2);
  for (int i = 0; i < size; ++i) {
    out += kHex[bytes[i] >> 4];
    out += kHex[bytes[i] & 0xf];
  }
  return out;
}

}  // namespace

SessionRepo::SessionRepo(SqliteDb& db) : db_(db) {}

core::Result<void> SessionRepo::Insert(const SessionRow& row,
                                      const std::vector<std::uint8_t>& csrf_secret,
                                      const std::vector<std::uint8_t>& ip_hash) {
  sqlite3* dbh = db_.handle();
  if (dbh == nullptr) {
    return core::Result<void>::Err(
        core::Status::Error(core::StatusCode::kFailedPrecondition, "DB not open"));
  }

  sqlite3_stmt* stmt = nullptr;
  const char* sql =
      "INSERT INTO auth_session(sid,uid,tenant_id,created_at,expires_at,mfa_state,csrf_secret,ticket_id,ip_hash)"
      " VALUES(?,?,?,?,?,?,?,?,?);";
  int rc = sqlite3_prepare_v2(dbh, sql, -1, &stmt, nullptr);
  if (rc != SQLITE_OK) return core::Result<void>::Err(MakeStmtStatus(rc, dbh, "prepare(insert)"));

  (void)sqlite3_bind_text(stmt, 1, row.sid.c_str(), -1, SQLITE_TRANSIENT);
  (void)sqlite3_bind_text(stmt, 2, row.uid.c_str(), -1, SQLITE_TRANSIENT);
  (void)sqlite3_bind_text(stmt, 3, row.tenant_id.c_str(), -1, SQLITE_TRANSIENT);
  (void)sqlite3_bind_int64(stmt, 4, row.created_at);
  (void)sqlite3_bind_int64(stmt, 5, row.expires_at);
  (void)sqlite3_bind_int(stmt, 6, row.mfa_state);
  (void)sqlite3_bind_blob(stmt, 7, csrf_secret.data(),
                          static_cast<int>(csrf_secret.size()), SQLITE_TRANSIENT);
  if (row.ticket_id.empty()) {
    (void)sqlite3_bind_null(stmt, 8);
  } else {
    (void)sqlite3_bind_text(stmt, 8, row.ticket_id.c_str(), -1, SQLITE_TRANSIENT);
  }
  if (ip_hash.empty()) {
    (void)sqlite3_bind_null(stmt, 9);
  } else {
    (void)sqlite3_bind_blob(stmt, 9, ip_hash.data(),
                            static_cast<int>(ip_hash.size()), SQLITE_TRANSIENT);
  }

  rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  if (rc != SQLITE_DONE) return core::Result<void>::Err(MakeStmtStatus(rc, dbh, "step(insert)"));

  return core::Result<void>::Ok();
}

core::Result<std::optional<SessionRow>> SessionRepo::GetBySid(const std::string& sid) {
  sqlite3* dbh = db_.handle();
  if (dbh == nullptr) {
    return core::Result<std::optional<SessionRow>>::Err(
        core::Status::Error(core::StatusCode::kFailedPrecondition, "DB not open"));
  }

  sqlite3_stmt* stmt = nullptr;
  const char* sql =
      "SELECT sid,uid,tenant_id,created_at,expires_at,mfa_state,COALESCE(ticket_id,''),"
      "csrf_secret,ip_hash "
      "FROM auth_session WHERE sid=?";
  int rc = sqlite3_prepare_v2(dbh, sql, -1, &stmt, nullptr);
  if (rc != SQLITE_OK) {
    return core::Result<std::optional<SessionRow>>::Err(MakeStmtStatus(rc, dbh, "prepare(get)"));
  }

  (void)sqlite3_bind_text(stmt, 1, sid.c_str(), -1, SQLITE_TRANSIENT);

  auto safe_col_text = [](sqlite3_stmt* s, int col) -> std::string {
    const auto* t = sqlite3_column_text(s, col);
    return t ? reinterpret_cast<const char*>(t) : "";
  };

  rc = sqlite3_step(stmt);
  if (rc == SQLITE_ROW) {
    SessionRow row;
    row.sid       = safe_col_text(stmt, 0);
    row.uid       = safe_col_text(stmt, 1);
    row.tenant_id = safe_col_text(stmt, 2);
    row.created_at = sqlite3_column_int64(stmt, 3);
    row.expires_at = sqlite3_column_int64(stmt, 4);
    row.mfa_state  = sqlite3_column_int(stmt, 5);
    row.ticket_id  = safe_col_text(stmt, 6);
    const void* csrf_blob = sqlite3_column_blob(stmt, 7);
    const int csrf_size = sqlite3_column_bytes(stmt, 7);
    if (csrf_blob != nullptr && csrf_size > 0) {
      row.csrf_secret_hex = BlobToHex(csrf_blob, csrf_size);
    }
    const void* ip_blob = sqlite3_column_blob(stmt, 8);
    const int ip_size = sqlite3_column_bytes(stmt, 8);
    if (ip_blob != nullptr && ip_size > 0) {
      row.ip_hash_hex = BlobToHex(ip_blob, ip_size);
    }
    sqlite3_finalize(stmt);
    return core::Result<std::optional<SessionRow>>::Ok(std::optional<SessionRow>(std::move(row)));
  }

  sqlite3_finalize(stmt);
  if (rc == SQLITE_DONE) {
    return core::Result<std::optional<SessionRow>>::Ok(std::nullopt);
  }

  return core::Result<std::optional<SessionRow>>::Err(MakeStmtStatus(rc, dbh, "step(get)"));
}

core::Result<void> SessionRepo::DeleteBySid(const std::string& sid) {
  sqlite3* dbh = db_.handle();
  if (dbh == nullptr) {
    return core::Result<void>::Err(
        core::Status::Error(core::StatusCode::kFailedPrecondition, "DB not open"));
  }

  sqlite3_stmt* stmt = nullptr;
  const char* sql = "DELETE FROM auth_session WHERE sid=?;";
  int rc = sqlite3_prepare_v2(dbh, sql, -1, &stmt, nullptr);
  if (rc != SQLITE_OK) return core::Result<void>::Err(MakeStmtStatus(rc, dbh, "prepare(del)"));

  (void)sqlite3_bind_text(stmt, 1, sid.c_str(), -1, SQLITE_TRANSIENT);

  rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  if (rc != SQLITE_DONE) return core::Result<void>::Err(MakeStmtStatus(rc, dbh, "step(del)"));

  return core::Result<void>::Ok();
}

core::Result<void> SessionRepo::DeleteExpired(std::int64_t now) {
  sqlite3* dbh = db_.handle();
  if (dbh == nullptr) {
    return core::Result<void>::Err(
        core::Status::Error(core::StatusCode::kFailedPrecondition, "DB not open"));
  }

  sqlite3_stmt* stmt = nullptr;
  const char* sql = "DELETE FROM auth_session WHERE expires_at <= ?;";
  int rc = sqlite3_prepare_v2(dbh, sql, -1, &stmt, nullptr);
  if (rc != SQLITE_OK) return core::Result<void>::Err(MakeStmtStatus(rc, dbh, "prepare(gc)"));

  (void)sqlite3_bind_int64(stmt, 1, now);

  rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  if (rc != SQLITE_DONE) return core::Result<void>::Err(MakeStmtStatus(rc, dbh, "step(gc)"));

  return core::Result<void>::Ok();
}

}  // namespace gatehouse::infra
