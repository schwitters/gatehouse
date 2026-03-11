#include "infra/xrdp_otp_repo.h"

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <openssl/crypto.h>
#include <sqlite3.h>

namespace gatehouse::infra {
namespace {

core::Status StmtErr(int rc, sqlite3* db, const char* what) {
  const char* msg = (db != nullptr) ? sqlite3_errmsg(db) : "sqlite error";
  return core::Status::Error(core::StatusCode::kInternal,
                            std::string(what) + " (rc=" + std::to_string(rc) + "): " + msg);
}

}  // namespace

XrdpOtpRepo::XrdpOtpRepo(SqliteDb& db) : db_(db) {}

core::Result<void> XrdpOtpRepo::Insert(const XrdpOtpRow& row) {
  sqlite3* dbh = db_.handle();
  if (dbh == nullptr) {
    return core::Result<void>::Err(
        core::Status::Error(core::StatusCode::kFailedPrecondition, "DB not open"));
  }

  sqlite3_stmt* stmt = nullptr;
  const char* sql =
      "INSERT INTO xrdp_otp(xrdp_otp_id,uid,tenant_id,host_id,otp_hash,attempts,max_attempts,"
      "issued_at,expires_at,consumed_at,issued_by_sid,ticket_id)"
      " VALUES(?,?,?,?,?,?,?,?,?,?,?,?);";
  int rc = sqlite3_prepare_v2(dbh, sql, -1, &stmt, nullptr);
  if (rc != SQLITE_OK) return core::Result<void>::Err(StmtErr(rc, dbh, "prepare(insert)"));

  (void)sqlite3_bind_text(stmt, 1, row.xrdp_otp_id.c_str(), -1, SQLITE_TRANSIENT);
  (void)sqlite3_bind_text(stmt, 2, row.uid.c_str(), -1, SQLITE_TRANSIENT);
  (void)sqlite3_bind_text(stmt, 3, row.tenant_id.c_str(), -1, SQLITE_TRANSIENT);
  (void)sqlite3_bind_text(stmt, 4, row.host_id.c_str(), -1, SQLITE_TRANSIENT);
  (void)sqlite3_bind_blob(stmt, 5, row.otp_hash.data(),
                          static_cast<int>(row.otp_hash.size()), SQLITE_TRANSIENT);
  (void)sqlite3_bind_int(stmt, 6, row.attempts);
  (void)sqlite3_bind_int(stmt, 7, row.max_attempts);
  (void)sqlite3_bind_int64(stmt, 8, row.issued_at);
  (void)sqlite3_bind_int64(stmt, 9, row.expires_at);
  (void)sqlite3_bind_null(stmt, 10);
  if (row.issued_by_sid.empty()) {
    (void)sqlite3_bind_null(stmt, 11);
  } else {
    (void)sqlite3_bind_text(stmt, 11, row.issued_by_sid.c_str(), -1, SQLITE_TRANSIENT);
  }
  (void)sqlite3_bind_text(stmt, 12, row.ticket_id.c_str(), -1, SQLITE_TRANSIENT);

  rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  if (rc != SQLITE_DONE) return core::Result<void>::Err(StmtErr(rc, dbh, "step(insert)"));
  return core::Result<void>::Ok();
}

core::Result<bool> XrdpOtpRepo::VerifyAndConsume(const std::string& uid, const std::string& host_id,
                                                const std::vector<std::uint8_t>& otp_hash,
                                                std::int64_t now) {
  sqlite3* dbh = db_.handle();
  if (dbh == nullptr) {
    return core::Result<bool>::Err(
        core::Status::Error(core::StatusCode::kFailedPrecondition, "DB not open"));
  }

  auto tx = db_.Exec("BEGIN IMMEDIATE;");
  if (!tx.ok()) return core::Result<bool>::Err(tx.status());

  sqlite3_stmt* sel = nullptr;
  // Auch hier: Kein Filter mehr nach otp_hash
  const char* sel_sql =
      "SELECT xrdp_otp_id, attempts, max_attempts, expires_at, otp_hash FROM xrdp_otp "
      "WHERE uid=? AND host_id=? AND consumed_at IS NULL "
      "ORDER BY issued_at DESC LIMIT 1;";
  int rc = sqlite3_prepare_v2(dbh, sel_sql, -1, &sel, nullptr);
  if (rc != SQLITE_OK) {
    (void)db_.Exec("ROLLBACK;");
    return core::Result<bool>::Err(StmtErr(rc, dbh, "prepare(select)"));
  }

  (void)sqlite3_bind_text(sel, 1, uid.c_str(), -1, SQLITE_TRANSIENT);
  (void)sqlite3_bind_text(sel, 2, host_id.c_str(), -1, SQLITE_TRANSIENT);

  rc = sqlite3_step(sel);
  if (rc != SQLITE_ROW) {
    sqlite3_finalize(sel);
    (void)db_.Exec("ROLLBACK;");
    if (rc == SQLITE_DONE) return core::Result<bool>::Ok(false);
    return core::Result<bool>::Err(StmtErr(rc, dbh, "step(select)"));
  }

  const std::string otp_id = reinterpret_cast<const char*>(sqlite3_column_text(sel, 0));
  const int attempts = sqlite3_column_int(sel, 1);
  const int max_attempts = sqlite3_column_int(sel, 2);
  const std::int64_t expires_at = sqlite3_column_int64(sel, 3);
  
  const void* blob_ptr = sqlite3_column_blob(sel, 4);
  const int blob_bytes = sqlite3_column_bytes(sel, 4);
  std::vector<std::uint8_t> db_hash;
  if (blob_ptr && blob_bytes > 0) {
    const auto* b = static_cast<const std::uint8_t*>(blob_ptr);
    db_hash.assign(b, b + blob_bytes);
  }
  sqlite3_finalize(sel);

  if (expires_at <= now || attempts >= max_attempts) {
    (void)db_.Exec("ROLLBACK;");
    return core::Result<bool>::Ok(false);
  }

  // Constant-time comparison to prevent timing attacks.
  const bool matched = (db_hash.size() == otp_hash.size() && !db_hash.empty() &&
                        CRYPTO_memcmp(db_hash.data(), otp_hash.data(), db_hash.size()) == 0);

  sqlite3_stmt* upd = nullptr;
  const char* upd_sql =
      "UPDATE xrdp_otp SET attempts = attempts + 1, "
      "consumed_at = CASE WHEN ? THEN ? ELSE consumed_at END "
      "WHERE xrdp_otp_id = ?;";
  rc = sqlite3_prepare_v2(dbh, upd_sql, -1, &upd, nullptr);
  if (rc != SQLITE_OK) {
    (void)db_.Exec("ROLLBACK;");
    return core::Result<bool>::Err(StmtErr(rc, dbh, "prepare(update)"));
  }
  (void)sqlite3_bind_int(upd, 1, matched ? 1 : 0);
  (void)sqlite3_bind_int64(upd, 2, now);
  (void)sqlite3_bind_text(upd, 3, otp_id.c_str(), -1, SQLITE_TRANSIENT);

  rc = sqlite3_step(upd);
  sqlite3_finalize(upd);
  if (rc != SQLITE_DONE) {
    (void)db_.Exec("ROLLBACK;");
    return core::Result<bool>::Err(StmtErr(rc, dbh, "step(update)"));
  }

  auto cm = db_.Exec("COMMIT;");
  if (!cm.ok()) return core::Result<bool>::Err(cm.status());

  return core::Result<bool>::Ok(matched);
}

}  // namespace gatehouse::infra
