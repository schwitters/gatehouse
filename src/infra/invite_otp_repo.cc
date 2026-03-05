#include "infra/invite_otp_repo.h"

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

InviteOtpRepo::InviteOtpRepo(SqliteDb& db) : db_(db) {}

core::Result<void> InviteOtpRepo::Insert(const InviteOtpRow& row) {
  sqlite3* dbh = db_.handle();
  if (!dbh) return core::Result<void>::Err(core::Status::Error(core::StatusCode::kFailedPrecondition, "DB not open"));

  sqlite3_stmt* stmt = nullptr;
  const char* sql =
      "INSERT INTO invite_otp(otp_id,sid,otp_hash,issued_at,expires_at,attempts,max_attempts,consumed_at) "
      "VALUES(?,?,?,?,?,?,?,NULL);";
  int rc = sqlite3_prepare_v2(dbh, sql, -1, &stmt, nullptr);
  if (rc != SQLITE_OK) return core::Result<void>::Err(StmtErr(rc, dbh, "prepare(insert invite_otp)"));

  (void)sqlite3_bind_text(stmt, 1, row.otp_id.c_str(), -1, SQLITE_TRANSIENT);
  (void)sqlite3_bind_text(stmt, 2, row.sid.c_str(), -1, SQLITE_TRANSIENT);
  (void)sqlite3_bind_blob(stmt, 3, row.otp_hash.data(), static_cast<int>(row.otp_hash.size()), SQLITE_TRANSIENT);
  (void)sqlite3_bind_int64(stmt, 4, row.issued_at);
  (void)sqlite3_bind_int64(stmt, 5, row.expires_at);
  (void)sqlite3_bind_int(stmt, 6, row.attempts);
  (void)sqlite3_bind_int(stmt, 7, row.max_attempts);

  rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  if (rc != SQLITE_DONE) return core::Result<void>::Err(StmtErr(rc, dbh, "step(insert invite_otp)"));
  return core::Result<void>::Ok();
}

core::Result<void> InviteOtpRepo::DeleteBySid(const std::string& sid) {
  sqlite3* dbh = db_.handle();
  if (!dbh) return core::Result<void>::Err(core::Status::Error(core::StatusCode::kFailedPrecondition, "DB not open"));

  sqlite3_stmt* stmt = nullptr;
  const char* sql = "DELETE FROM invite_otp WHERE sid=?;";
  int rc = sqlite3_prepare_v2(dbh, sql, -1, &stmt, nullptr);
  if (rc != SQLITE_OK) return core::Result<void>::Err(StmtErr(rc, dbh, "prepare(delete invite_otp)"));

  (void)sqlite3_bind_text(stmt, 1, sid.c_str(), -1, SQLITE_TRANSIENT);
  rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  if (rc != SQLITE_DONE) return core::Result<void>::Err(StmtErr(rc, dbh, "step(delete invite_otp)"));
  return core::Result<void>::Ok();
}

core::Result<bool> InviteOtpRepo::IsVerified(const std::string& sid) {
  sqlite3* dbh = db_.handle();
  if (!dbh) return core::Result<bool>::Err(core::Status::Error(core::StatusCode::kFailedPrecondition, "DB not open"));

  sqlite3_stmt* stmt = nullptr;
  const char* sql =
      "SELECT 1 FROM invite_otp WHERE sid=? AND consumed_at IS NOT NULL LIMIT 1;";
  int rc = sqlite3_prepare_v2(dbh, sql, -1, &stmt, nullptr);
  if (rc != SQLITE_OK) return core::Result<bool>::Err(StmtErr(rc, dbh, "prepare(is_verified invite_otp)"));

  (void)sqlite3_bind_text(stmt, 1, sid.c_str(), -1, SQLITE_TRANSIENT);
  rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  if (rc == SQLITE_ROW) return core::Result<bool>::Ok(true);
  if (rc == SQLITE_DONE) return core::Result<bool>::Ok(false);
  return core::Result<bool>::Err(StmtErr(rc, dbh, "step(is_verified invite_otp)"));
}

core::Result<bool> InviteOtpRepo::VerifyAndConsume(const std::string& sid,
                                                   const std::vector<std::uint8_t>& otp_hash,
                                                   std::int64_t now) {
  sqlite3* dbh = db_.handle();
  if (!dbh) return core::Result<bool>::Err(core::Status::Error(core::StatusCode::kFailedPrecondition, "DB not open"));

  auto tx = db_.Exec("BEGIN IMMEDIATE;");
  if (!tx.ok()) return core::Result<bool>::Err(tx.status());

  sqlite3_stmt* sel = nullptr;
  const char* sel_sql =
      "SELECT otp_id, attempts, max_attempts FROM invite_otp "
      "WHERE sid=? AND otp_hash=? AND consumed_at IS NULL AND expires_at>? "
      "ORDER BY issued_at DESC LIMIT 1;";
  int rc = sqlite3_prepare_v2(dbh, sel_sql, -1, &sel, nullptr);
  if (rc != SQLITE_OK) {
    (void)db_.Exec("ROLLBACK;");
    return core::Result<bool>::Err(StmtErr(rc, dbh, "prepare(select invite_otp)"));
  }

  (void)sqlite3_bind_text(sel, 1, sid.c_str(), -1, SQLITE_TRANSIENT);
  (void)sqlite3_bind_blob(sel, 2, otp_hash.data(), static_cast<int>(otp_hash.size()), SQLITE_TRANSIENT);
  (void)sqlite3_bind_int64(sel, 3, now);

  rc = sqlite3_step(sel);
  if (rc != SQLITE_ROW) {
    sqlite3_finalize(sel);
    (void)db_.Exec("ROLLBACK;");
    if (rc == SQLITE_DONE) return core::Result<bool>::Ok(false);
    return core::Result<bool>::Err(StmtErr(rc, dbh, "step(select invite_otp)"));
  }

  const std::string otp_id = reinterpret_cast<const char*>(sqlite3_column_text(sel, 0));
  const int attempts = sqlite3_column_int(sel, 1);
  const int max_attempts = sqlite3_column_int(sel, 2);
  sqlite3_finalize(sel);

  if (attempts >= max_attempts) {
    (void)db_.Exec("ROLLBACK;");
    return core::Result<bool>::Ok(false);
  }

  sqlite3_stmt* upd = nullptr;
  const char* upd_sql =
      "UPDATE invite_otp SET consumed_at=?, attempts=attempts+1 "
      "WHERE otp_id=? AND consumed_at IS NULL;";
  rc = sqlite3_prepare_v2(dbh, upd_sql, -1, &upd, nullptr);
  if (rc != SQLITE_OK) {
    (void)db_.Exec("ROLLBACK;");
    return core::Result<bool>::Err(StmtErr(rc, dbh, "prepare(update invite_otp)"));
  }

  (void)sqlite3_bind_int64(upd, 1, now);
  (void)sqlite3_bind_text(upd, 2, otp_id.c_str(), -1, SQLITE_TRANSIENT);
  rc = sqlite3_step(upd);
  sqlite3_finalize(upd);

  if (rc != SQLITE_DONE) {
    (void)db_.Exec("ROLLBACK;");
    return core::Result<bool>::Err(StmtErr(rc, dbh, "step(update invite_otp)"));
  }

  auto cm = db_.Exec("COMMIT;");
  if (!cm.ok()) return core::Result<bool>::Err(cm.status());

  return core::Result<bool>::Ok(true);
}

}  // namespace gatehouse::infra
