#include "infra/ticket_vault_repo.h"

#include <string>
#include <utility>

#include <sqlite3.h>

namespace gatehouse::infra {
namespace {

core::Status MakeStmtStatus(int rc, sqlite3* db, const char* what) {
  const char* msg = (db != nullptr) ? sqlite3_errmsg(db) : "sqlite error";
  return core::Status::Error(core::StatusCode::kInternal,
                            std::string(what) + " (rc=" + std::to_string(rc) + "): " + msg);
}

}  // namespace

TicketVaultRepo::TicketVaultRepo(SqliteDb& db) : db_(db) {}

core::Result<void> TicketVaultRepo::Insert(const TicketVaultRow& row) {
  sqlite3* dbh = db_.handle();
  if (dbh == nullptr) {
    return core::Result<void>::Err(
        core::Status::Error(core::StatusCode::kFailedPrecondition, "DB not open"));
  }

  sqlite3_stmt* stmt = nullptr;
  const char* sql =
      "INSERT INTO ticket_vault(ticket_id,uid,tenant_id,created_at,expires_at,enc_alg,enc_key_id,"
      " nonce,aad,ccache_blob_enc) VALUES(?,?,?,?,?,?,?,?,?,?);";
  int rc = sqlite3_prepare_v2(dbh, sql, -1, &stmt, nullptr);
  if (rc != SQLITE_OK) return core::Result<void>::Err(MakeStmtStatus(rc, dbh, "prepare(insert)"));

  (void)sqlite3_bind_text(stmt, 1, row.ticket_id.c_str(), -1, SQLITE_TRANSIENT);
  (void)sqlite3_bind_text(stmt, 2, row.uid.c_str(), -1, SQLITE_TRANSIENT);
  (void)sqlite3_bind_text(stmt, 3, row.tenant_id.c_str(), -1, SQLITE_TRANSIENT);
  (void)sqlite3_bind_int64(stmt, 4, row.created_at);
  (void)sqlite3_bind_int64(stmt, 5, row.expires_at);
  (void)sqlite3_bind_text(stmt, 6, row.enc_alg.c_str(), -1, SQLITE_TRANSIENT);
  (void)sqlite3_bind_text(stmt, 7, row.enc_key_id.c_str(), -1, SQLITE_TRANSIENT);

  (void)sqlite3_bind_blob(stmt, 8, row.nonce.data(),
                          static_cast<int>(row.nonce.size()), SQLITE_TRANSIENT);

  if (row.aad.empty()) {
    (void)sqlite3_bind_null(stmt, 9);
  } else {
    (void)sqlite3_bind_blob(stmt, 9, row.aad.data(),
                            static_cast<int>(row.aad.size()), SQLITE_TRANSIENT);
  }

  (void)sqlite3_bind_blob(stmt, 10, row.ccache_blob_enc.data(),
                          static_cast<int>(row.ccache_blob_enc.size()), SQLITE_TRANSIENT);

  rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  if (rc != SQLITE_DONE) return core::Result<void>::Err(MakeStmtStatus(rc, dbh, "step(insert)"));

  return core::Result<void>::Ok();
}

}  // namespace gatehouse::infra
