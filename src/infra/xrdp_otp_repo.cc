#include "infra/xrdp_otp_repo.h"

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

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

  // 1) Find matching, unconsumed, unexpired OTP, attempts < max_attempts
  sqlite3_stmt* sel = nullptr;
  const char* sel_sql =
      "SELECT xrdp_otp_id, attempts, max_attempts FROM xrdp_otp "
      "WHERE uid=? AND host_id=? AND otp_hash=? AND consumed_at IS NULL AND expires_at>? "
      "LIMIT 1;";
  int rc = sqlite3_prepare_v2(dbh, sel_sql, -1, &sel, nullptr);
  if (rc != SQLITE_OK) {
    (void)db_.Exec("ROLLBACK;");
    return core::Result<bool>::Err(StmtErr(rc, dbh, "prepare(select)"));
  }

  (void)sqlite3_bind_text(sel, 1, uid.c_str(), -1, SQLITE_TRANSIENT);
  (void)sqlite3_bind_text(sel, 2, host_id.c_str(), -1, SQLITE_TRANSIENT);
  (void)sqlite3_bind_blob(sel, 3, otp_hash.data(),
                          static_cast<int>(otp_hash.size()), SQLITE_TRANSIENT);
  (void)sqlite3_bind_int64(sel, 4, now);

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
  sqlite3_finalize(sel);

  if (attempts >= max_attempts) {
    (void)db_.Exec("ROLLBACK;");
    return core::Result<bool>::Ok(false);
  }

  // 2) Consume it (and increment attempts just for tracking).
  sqlite3_stmt* upd = nullptr;
  const char* upd_sql =
      "UPDATE xrdp_otp SET consumed_at=?, attempts=attempts+1 "
      "WHERE xrdp_otp_id=? AND consumed_at IS NULL;";
  rc = sqlite3_prepare_v2(dbh, upd_sql, -1, &upd, nullptr);
  if (rc != SQLITE_OK) {
    (void)db_.Exec("ROLLBACK;");
    return core::Result<bool>::Err(StmtErr(rc, dbh, "prepare(update)"));
  }
  (void)sqlite3_bind_int64(upd, 1, now);
  (void)sqlite3_bind_text(upd, 2, otp_id.c_str(), -1, SQLITE_TRANSIENT);

  rc = sqlite3_step(upd);
  sqlite3_finalize(upd);
  if (rc != SQLITE_DONE) {
    (void)db_.Exec("ROLLBACK;");
    return core::Result<bool>::Err(StmtErr(rc, dbh, "step(update)"));
  }

  auto cm = db_.Exec("COMMIT;");
  if (!cm.ok()) return core::Result<bool>::Err(cm.status());

  return core::Result<bool>::Ok(true);
}

}  // namespace gatehouse::infra
