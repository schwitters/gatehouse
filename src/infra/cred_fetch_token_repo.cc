#include "infra/cred_fetch_token_repo.h"

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

CredFetchTokenRepo::CredFetchTokenRepo(SqliteDb& db) : db_(db) {}

core::Result<void> CredFetchTokenRepo::Insert(const CredFetchTokenRow& row) {
  sqlite3* dbh = db_.handle();
  if (dbh == nullptr) {
    return core::Result<void>::Err(
        core::Status::Error(core::StatusCode::kFailedPrecondition, "DB not open"));
  }

  sqlite3_stmt* stmt = nullptr;
  const char* sql =
      "INSERT INTO cred_fetch_token(cft_id,uid,tenant_id,host_id,token_hash,issued_at,expires_at,consumed_at,ticket_id)"
      " VALUES(?,?,?,?,?,?,?,?,?);";
  int rc = sqlite3_prepare_v2(dbh, sql, -1, &stmt, nullptr);
  if (rc != SQLITE_OK) return core::Result<void>::Err(StmtErr(rc, dbh, "prepare(insert)"));

  (void)sqlite3_bind_text(stmt, 1, row.cft_id.c_str(), -1, SQLITE_TRANSIENT);
  (void)sqlite3_bind_text(stmt, 2, row.uid.c_str(), -1, SQLITE_TRANSIENT);
  (void)sqlite3_bind_text(stmt, 3, row.tenant_id.c_str(), -1, SQLITE_TRANSIENT);
  (void)sqlite3_bind_text(stmt, 4, row.host_id.c_str(), -1, SQLITE_TRANSIENT);
  (void)sqlite3_bind_blob(stmt, 5, row.token_hash.data(),
                          static_cast<int>(row.token_hash.size()), SQLITE_TRANSIENT);
  (void)sqlite3_bind_int64(stmt, 6, row.issued_at);
  (void)sqlite3_bind_int64(stmt, 7, row.expires_at);
  (void)sqlite3_bind_null(stmt, 8);
  (void)sqlite3_bind_text(stmt, 9, row.ticket_id.c_str(), -1, SQLITE_TRANSIENT);

  rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  if (rc != SQLITE_DONE) return core::Result<void>::Err(StmtErr(rc, dbh, "step(insert)"));
  return core::Result<void>::Ok();
}

core::Result<std::optional<std::string>> CredFetchTokenRepo::VerifyAndConsume(
    const std::string& uid, const std::string& host_id,
    const std::vector<std::uint8_t>& token_hash, std::int64_t now) {
  sqlite3* dbh = db_.handle();
  if (dbh == nullptr) {
    return core::Result<std::optional<std::string>>::Err(
        core::Status::Error(core::StatusCode::kFailedPrecondition, "DB not open"));
  }

  // Do it in a transaction to be atomic.
  auto tx = db_.Exec("BEGIN IMMEDIATE;");
  if (!tx.ok()) return core::Result<std::optional<std::string>>::Err(tx.status());

  // Find matching unconsumed, unexpired token.
  sqlite3_stmt* sel = nullptr;
  const char* sel_sql =
      "SELECT cft_id, ticket_id FROM cred_fetch_token "
      "WHERE uid=? AND host_id=? AND token_hash=? AND consumed_at IS NULL AND expires_at>? "
      "LIMIT 1;";
  int rc = sqlite3_prepare_v2(dbh, sel_sql, -1, &sel, nullptr);
  if (rc != SQLITE_OK) {
    (void)db_.Exec("ROLLBACK;");
    return core::Result<std::optional<std::string>>::Err(StmtErr(rc, dbh, "prepare(select)"));
  }

  (void)sqlite3_bind_text(sel, 1, uid.c_str(), -1, SQLITE_TRANSIENT);
  (void)sqlite3_bind_text(sel, 2, host_id.c_str(), -1, SQLITE_TRANSIENT);
  (void)sqlite3_bind_blob(sel, 3, token_hash.data(),
                          static_cast<int>(token_hash.size()), SQLITE_TRANSIENT);
  (void)sqlite3_bind_int64(sel, 4, now);

  rc = sqlite3_step(sel);
  if (rc != SQLITE_ROW) {
    sqlite3_finalize(sel);
    (void)db_.Exec("ROLLBACK;");
    if (rc == SQLITE_DONE) {
      return core::Result<std::optional<std::string>>::Ok(std::nullopt);
    }
    return core::Result<std::optional<std::string>>::Err(StmtErr(rc, dbh, "step(select)"));
  }

  auto safe_col_text = [](sqlite3_stmt* s, int col) -> std::string {
    const auto* t = sqlite3_column_text(s, col);
    return t ? reinterpret_cast<const char*>(t) : "";
  };
  const std::string cft_id = safe_col_text(sel, 0);
  const std::string ticket_id = safe_col_text(sel, 1);
  sqlite3_finalize(sel);

  sqlite3_stmt* upd = nullptr;
  const char* upd_sql = "UPDATE cred_fetch_token SET consumed_at=? WHERE cft_id=? AND consumed_at IS NULL;";
  rc = sqlite3_prepare_v2(dbh, upd_sql, -1, &upd, nullptr);
  if (rc != SQLITE_OK) {
    (void)db_.Exec("ROLLBACK;");
    return core::Result<std::optional<std::string>>::Err(StmtErr(rc, dbh, "prepare(update)"));
  }
  (void)sqlite3_bind_int64(upd, 1, now);
  (void)sqlite3_bind_text(upd, 2, cft_id.c_str(), -1, SQLITE_TRANSIENT);

  rc = sqlite3_step(upd);
  sqlite3_finalize(upd);
  if (rc != SQLITE_DONE) {
    (void)db_.Exec("ROLLBACK;");
    return core::Result<std::optional<std::string>>::Err(StmtErr(rc, dbh, "step(update)"));
  }

  auto cm = db_.Exec("COMMIT;");
  if (!cm.ok()) return core::Result<std::optional<std::string>>::Err(cm.status());

  return core::Result<std::optional<std::string>>::Ok(std::optional<std::string>(ticket_id));
}

}  // namespace gatehouse::infra
