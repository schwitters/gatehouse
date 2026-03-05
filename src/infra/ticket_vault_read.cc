#include "infra/ticket_vault_read.h"

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

std::vector<std::uint8_t> Blob(sqlite3_stmt* stmt, int col) {
  const void* p = sqlite3_column_blob(stmt, col);
  const int n = sqlite3_column_bytes(stmt, col);
  if (p == nullptr || n <= 0) return {};
  const auto* b = static_cast<const std::uint8_t*>(p);
  return std::vector<std::uint8_t>(b, b + n);
}

}  // namespace

TicketVaultReadRepo::TicketVaultReadRepo(SqliteDb& db) : db_(db) {}

core::Result<std::optional<TicketVaultReadRow>> TicketVaultReadRepo::GetById(const std::string& ticket_id) {
  sqlite3* dbh = db_.handle();
  if (dbh == nullptr) {
    return core::Result<std::optional<TicketVaultReadRow>>::Err(
        core::Status::Error(core::StatusCode::kFailedPrecondition, "DB not open"));
  }

  sqlite3_stmt* stmt = nullptr;
  const char* sql =
      "SELECT ticket_id,uid,tenant_id,expires_at,enc_alg,enc_key_id,nonce,COALESCE(aad,zeroblob(0)),ccache_blob_enc "
      "FROM ticket_vault WHERE ticket_id=? LIMIT 1;";
  int rc = sqlite3_prepare_v2(dbh, sql, -1, &stmt, nullptr);
  if (rc != SQLITE_OK) return core::Result<std::optional<TicketVaultReadRow>>::Err(StmtErr(rc, dbh, "prepare(get)"));

  (void)sqlite3_bind_text(stmt, 1, ticket_id.c_str(), -1, SQLITE_TRANSIENT);

  rc = sqlite3_step(stmt);
  if (rc == SQLITE_DONE) {
    sqlite3_finalize(stmt);
    return core::Result<std::optional<TicketVaultReadRow>>::Ok(std::nullopt);
  }
  if (rc != SQLITE_ROW) {
    sqlite3_finalize(stmt);
    return core::Result<std::optional<TicketVaultReadRow>>::Err(StmtErr(rc, dbh, "step(get)"));
  }

  TicketVaultReadRow row;
  row.ticket_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
  row.uid = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
  row.tenant_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
  row.expires_at = sqlite3_column_int64(stmt, 3);
  row.enc_alg = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
  row.enc_key_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
  row.nonce = Blob(stmt, 6);
  row.aad = Blob(stmt, 7);
  row.ccache_blob_enc = Blob(stmt, 8);

  sqlite3_finalize(stmt);
  return core::Result<std::optional<TicketVaultReadRow>>::Ok(std::optional<TicketVaultReadRow>(std::move(row)));
}

}  // namespace gatehouse::infra
