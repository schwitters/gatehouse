#include "infra/invite_otp_repo.h"

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
  // Wir filtern NICHT mehr nach otp_hash, um falsche Eingaben mitzählen zu können.
  const char* sel_sql =
      "SELECT otp_id, attempts, max_attempts, expires_at, otp_hash FROM invite_otp "
      "WHERE sid=? AND consumed_at IS NULL "
      "ORDER BY issued_at DESC LIMIT 1;";
  int rc = sqlite3_prepare_v2(dbh, sel_sql, -1, &sel, nullptr);
  if (rc != SQLITE_OK) {
    (void)db_.Exec("ROLLBACK;");
    return core::Result<bool>::Err(StmtErr(rc, dbh, "prepare(select invite_otp)"));
  }

  (void)sqlite3_bind_text(sel, 1, sid.c_str(), -1, SQLITE_TRANSIENT);

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
  const std::int64_t expires_at = sqlite3_column_int64(sel, 3);
  
  const void* blob_ptr = sqlite3_column_blob(sel, 4);
  const int blob_bytes = sqlite3_column_bytes(sel, 4);
  std::vector<std::uint8_t> db_hash;
  if (blob_ptr && blob_bytes > 0) {
    const auto* b = static_cast<const std::uint8_t*>(blob_ptr);
    db_hash.assign(b, b + blob_bytes);
  }
  sqlite3_finalize(sel);

  // Abbruch, wenn bereits abgelaufen oder zu viele Versuche.
  if (expires_at <= now || attempts >= max_attempts) {
    (void)db_.Exec("ROLLBACK;");
    return core::Result<bool>::Ok(false);
  }

  // Constant-time comparison to prevent timing attacks.
  const bool matched = (db_hash.size() == otp_hash.size() && !db_hash.empty() &&
                        CRYPTO_memcmp(db_hash.data(), otp_hash.data(), db_hash.size()) == 0);

  sqlite3_stmt* upd = nullptr;
  const char* upd_sql =
      "UPDATE invite_otp SET attempts = attempts + 1, "
      "consumed_at = CASE WHEN ? THEN ? ELSE consumed_at END "
      "WHERE otp_id = ?;";
  rc = sqlite3_prepare_v2(dbh, upd_sql, -1, &upd, nullptr);
  if (rc != SQLITE_OK) {
    (void)db_.Exec("ROLLBACK;");
    return core::Result<bool>::Err(StmtErr(rc, dbh, "prepare(update invite_otp)"));
  }

  (void)sqlite3_bind_int(upd, 1, matched ? 1 : 0);
  (void)sqlite3_bind_int64(upd, 2, now);
  (void)sqlite3_bind_text(upd, 3, otp_id.c_str(), -1, SQLITE_TRANSIENT);

  rc = sqlite3_step(upd);
  sqlite3_finalize(upd);

  if (rc != SQLITE_DONE) {
    (void)db_.Exec("ROLLBACK;");
    return core::Result<bool>::Err(StmtErr(rc, dbh, "step(update invite_otp)"));
  }

  auto cm = db_.Exec("COMMIT;");
  if (!cm.ok()) return core::Result<bool>::Err(cm.status());

  return core::Result<bool>::Ok(matched);
}


core::Result<std::optional<std::int64_t>> InviteOtpRepo::GetLastIssuedAt(const std::string& sid) {
  sqlite3* dbh = db_.handle();
  if (!dbh) return core::Result<std::optional<std::int64_t>>::Err(core::Status::Error(core::StatusCode::kFailedPrecondition, "DB not open"));

  sqlite3_stmt* stmt = nullptr;
  const char* sql = "SELECT issued_at FROM invite_otp WHERE sid=? ORDER BY issued_at DESC LIMIT 1;";
  int rc = sqlite3_prepare_v2(dbh, sql, -1, &stmt, nullptr);
  if (rc != SQLITE_OK) return core::Result<std::optional<std::int64_t>>::Err(StmtErr(rc, dbh, "prepare(get_last_issued)"));

  (void)sqlite3_bind_text(stmt, 1, sid.c_str(), -1, SQLITE_TRANSIENT);
  rc = sqlite3_step(stmt);
  
  std::optional<std::int64_t> res;
  if (rc == SQLITE_ROW) {
    res = sqlite3_column_int64(stmt, 0);
  } else if (rc != SQLITE_DONE) {
    sqlite3_finalize(stmt);
    return core::Result<std::optional<std::int64_t>>::Err(StmtErr(rc, dbh, "step(get_last_issued)"));
  }
  
  sqlite3_finalize(stmt);
  return core::Result<std::optional<std::int64_t>>::Ok(res);
}

}  // namespace gatehouse::infra
