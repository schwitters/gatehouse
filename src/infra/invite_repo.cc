#include "infra/invite_repo.h"

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

InviteRow ReadInvite(sqlite3_stmt* stmt) {
  InviteRow row;
  row.invite_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
  row.tenant_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
  row.invited_email = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
  row.invited_uid = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
  row.token_hash = Blob(stmt, 4);
  row.status = static_cast<InviteStatus>(sqlite3_column_int(stmt, 5));
  row.created_at = sqlite3_column_int64(stmt, 6);
  row.expires_at = sqlite3_column_int64(stmt, 7);
  row.consumed_at = sqlite3_column_type(stmt, 8) == SQLITE_NULL ? 0 : sqlite3_column_int64(stmt, 8);
  row.revoked_at = sqlite3_column_type(stmt, 9) == SQLITE_NULL ? 0 : sqlite3_column_int64(stmt, 9);
  row.created_by = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 10));
  return row;
}

}  // namespace

InviteRepo::InviteRepo(SqliteDb& db) : db_(db) {}

core::Result<void> InviteRepo::Insert(const InviteRow& row) {
  sqlite3* dbh = db_.handle();
  if (dbh == nullptr) {
    return core::Result<void>::Err(core::Status::Error(core::StatusCode::kFailedPrecondition, "DB not open"));
  }

  sqlite3_stmt* stmt = nullptr;
  const char* sql =
      "INSERT INTO invite(invite_id,tenant_id,invited_email,invited_uid,roles_json,token_hash,status,"
      "created_at,expires_at,consumed_at,revoked_at,created_by)"
      " VALUES(?,?,?,?,?,?,?,?,?,?,?,?);";
  int rc = sqlite3_prepare_v2(dbh, sql, -1, &stmt, nullptr);
  if (rc != SQLITE_OK) return core::Result<void>::Err(StmtErr(rc, dbh, "prepare(insert)"));

  (void)sqlite3_bind_text(stmt, 1, row.invite_id.c_str(), -1, SQLITE_TRANSIENT);
  (void)sqlite3_bind_text(stmt, 2, row.tenant_id.c_str(), -1, SQLITE_TRANSIENT);
  (void)sqlite3_bind_text(stmt, 3, row.invited_email.c_str(), -1, SQLITE_TRANSIENT);
  if (row.invited_uid.empty()) (void)sqlite3_bind_null(stmt, 4);
  else (void)sqlite3_bind_text(stmt, 4, row.invited_uid.c_str(), -1, SQLITE_TRANSIENT);

  (void)sqlite3_bind_text(stmt, 5, "[]", -1, SQLITE_TRANSIENT);
  (void)sqlite3_bind_blob(stmt, 6, row.token_hash.data(),
                          static_cast<int>(row.token_hash.size()), SQLITE_TRANSIENT);
  (void)sqlite3_bind_int(stmt, 7, static_cast<int>(row.status));
  (void)sqlite3_bind_int64(stmt, 8, row.created_at);
  (void)sqlite3_bind_int64(stmt, 9, row.expires_at);
  (void)sqlite3_bind_null(stmt, 10);
  (void)sqlite3_bind_null(stmt, 11);
  (void)sqlite3_bind_text(stmt, 12, row.created_by.c_str(), -1, SQLITE_TRANSIENT);

  rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  if (rc != SQLITE_DONE) return core::Result<void>::Err(StmtErr(rc, dbh, "step(insert)"));
  return core::Result<void>::Ok();
}

core::Result<std::optional<InviteRow>> InviteRepo::GetByTokenHash(const std::vector<std::uint8_t>& token_hash) {
  sqlite3* dbh = db_.handle();
  if (dbh == nullptr) {
    return core::Result<std::optional<InviteRow>>::Err(
        core::Status::Error(core::StatusCode::kFailedPrecondition, "DB not open"));
  }

  sqlite3_stmt* stmt = nullptr;
  const char* sql =
      "SELECT invite_id,tenant_id,invited_email,COALESCE(invited_uid,''),token_hash,status,created_at,expires_at,"
      "consumed_at,revoked_at,COALESCE(created_by,'') "
      "FROM invite WHERE token_hash=? LIMIT 1;";
  int rc = sqlite3_prepare_v2(dbh, sql, -1, &stmt, nullptr);
  if (rc != SQLITE_OK) return core::Result<std::optional<InviteRow>>::Err(StmtErr(rc, dbh, "prepare(get_by_hash)"));

  (void)sqlite3_bind_blob(stmt, 1, token_hash.data(),
                          static_cast<int>(token_hash.size()), SQLITE_TRANSIENT);

  rc = sqlite3_step(stmt);
  if (rc == SQLITE_DONE) {
    sqlite3_finalize(stmt);
    return core::Result<std::optional<InviteRow>>::Ok(std::nullopt);
  }
  if (rc != SQLITE_ROW) {
    sqlite3_finalize(stmt);
    return core::Result<std::optional<InviteRow>>::Err(StmtErr(rc, dbh, "step(get_by_hash)"));
  }

  auto row = ReadInvite(stmt);
  sqlite3_finalize(stmt);
  return core::Result<std::optional<InviteRow>>::Ok(std::optional<InviteRow>(std::move(row)));
}

core::Result<std::optional<InviteRow>> InviteRepo::GetById(const std::string& invite_id) {
  sqlite3* dbh = db_.handle();
  if (dbh == nullptr) {
    return core::Result<std::optional<InviteRow>>::Err(
        core::Status::Error(core::StatusCode::kFailedPrecondition, "DB not open"));
  }

  sqlite3_stmt* stmt = nullptr;
  const char* sql =
      "SELECT invite_id,tenant_id,invited_email,COALESCE(invited_uid,''),token_hash,status,created_at,expires_at,"
      "consumed_at,revoked_at,COALESCE(created_by,'') "
      "FROM invite WHERE invite_id=? LIMIT 1;";
  int rc = sqlite3_prepare_v2(dbh, sql, -1, &stmt, nullptr);
  if (rc != SQLITE_OK) return core::Result<std::optional<InviteRow>>::Err(StmtErr(rc, dbh, "prepare(get_by_id)"));

  (void)sqlite3_bind_text(stmt, 1, invite_id.c_str(), -1, SQLITE_TRANSIENT);

  rc = sqlite3_step(stmt);
  if (rc == SQLITE_DONE) {
    sqlite3_finalize(stmt);
    return core::Result<std::optional<InviteRow>>::Ok(std::nullopt);
  }
  if (rc != SQLITE_ROW) {
    sqlite3_finalize(stmt);
    return core::Result<std::optional<InviteRow>>::Err(StmtErr(rc, dbh, "step(get_by_id)"));
  }

  auto row = ReadInvite(stmt);
  sqlite3_finalize(stmt);
  return core::Result<std::optional<InviteRow>>::Ok(std::optional<InviteRow>(std::move(row)));
}

core::Result<void> InviteRepo::UpdateStatus(const std::string& invite_id, InviteStatus st, std::int64_t now) {
  sqlite3* dbh = db_.handle();
  if (dbh == nullptr) {
    return core::Result<void>::Err(core::Status::Error(core::StatusCode::kFailedPrecondition, "DB not open"));
  }

  sqlite3_stmt* stmt = nullptr;
  const char* sql =
      "UPDATE invite SET status=?, consumed_at=CASE WHEN ? THEN ? ELSE consumed_at END "
      "WHERE invite_id=?;";
  int rc = sqlite3_prepare_v2(dbh, sql, -1, &stmt, nullptr);
  if (rc != SQLITE_OK) return core::Result<void>::Err(StmtErr(rc, dbh, "prepare(update_status)"));

  (void)sqlite3_bind_int(stmt, 1, static_cast<int>(st));
  const int set_consumed = (st == InviteStatus::kCompleted) ? 1 : 0;
  (void)sqlite3_bind_int(stmt, 2, set_consumed);
  (void)sqlite3_bind_int64(stmt, 3, now);
  (void)sqlite3_bind_text(stmt, 4, invite_id.c_str(), -1, SQLITE_TRANSIENT);

  rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  if (rc != SQLITE_DONE) return core::Result<void>::Err(StmtErr(rc, dbh, "step(update_status)"));
  return core::Result<void>::Ok();
}

core::Result<void> InviteRepo::UpdateEmail(const std::string& invite_id, const std::string& email) {
  sqlite3* dbh = db_.handle();
  if (dbh == nullptr) {
    return core::Result<void>::Err(core::Status::Error(core::StatusCode::kFailedPrecondition, "DB not open"));
  }
  sqlite3_stmt* stmt = nullptr;
  const char* sql = "UPDATE invite SET invited_email=? WHERE invite_id=?;";
  int rc = sqlite3_prepare_v2(dbh, sql, -1, &stmt, nullptr);
  if (rc != SQLITE_OK) return core::Result<void>::Err(StmtErr(rc, dbh, "prepare(update_email)"));
  (void)sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_TRANSIENT);
  (void)sqlite3_bind_text(stmt, 2, invite_id.c_str(), -1, SQLITE_TRANSIENT);
  rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  if (rc != SQLITE_DONE) return core::Result<void>::Err(StmtErr(rc, dbh, "step(update_email)"));
  return core::Result<void>::Ok();
}

core::Result<void> InviteRepo::Revoke(const std::string& invite_id, std::int64_t now) {
  sqlite3* dbh = db_.handle();
  if (dbh == nullptr) {
    return core::Result<void>::Err(core::Status::Error(core::StatusCode::kFailedPrecondition, "DB not open"));
  }

  sqlite3_stmt* stmt = nullptr;
  const char* sql =
      "UPDATE invite SET status=?, revoked_at=? WHERE invite_id=?;";
  int rc = sqlite3_prepare_v2(dbh, sql, -1, &stmt, nullptr);
  if (rc != SQLITE_OK) return core::Result<void>::Err(StmtErr(rc, dbh, "prepare(revoke)"));

  (void)sqlite3_bind_int(stmt, 1, static_cast<int>(InviteStatus::kRevoked));
  (void)sqlite3_bind_int64(stmt, 2, now);
  (void)sqlite3_bind_text(stmt, 3, invite_id.c_str(), -1, SQLITE_TRANSIENT);

  rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  if (rc != SQLITE_DONE) return core::Result<void>::Err(StmtErr(rc, dbh, "step(revoke)"));
  return core::Result<void>::Ok();
}

core::Result<std::vector<InviteRow>> InviteRepo::ListLatest(std::int32_t limit,
                                                            const std::string& tenant_id,
                                                            const std::string& invited_uid) {
  sqlite3* dbh = db_.handle();
  if (dbh == nullptr) {
    return core::Result<std::vector<InviteRow>>::Err(
        core::Status::Error(core::StatusCode::kFailedPrecondition, "DB not open"));
  }
  if (limit <= 0) limit = 50;
  if (limit > 200) limit = 200;

  std::string sql =
      "SELECT invite_id,tenant_id,invited_email,COALESCE(invited_uid,''),token_hash,status,created_at,expires_at,"
      "consumed_at,revoked_at,COALESCE(created_by,'') "
      "FROM invite WHERE 1=1 ";

  if (!tenant_id.empty()) sql += "AND tenant_id=? ";
  if (!invited_uid.empty()) sql += "AND invited_uid=? ";
  sql += "ORDER BY created_at DESC LIMIT ?;";

  sqlite3_stmt* stmt = nullptr;
  int rc = sqlite3_prepare_v2(dbh, sql.c_str(), -1, &stmt, nullptr);
  if (rc != SQLITE_OK) return core::Result<std::vector<InviteRow>>::Err(StmtErr(rc, dbh, "prepare(list)"));

  int bi = 1;
  if (!tenant_id.empty()) (void)sqlite3_bind_text(stmt, bi++, tenant_id.c_str(), -1, SQLITE_TRANSIENT);
  if (!invited_uid.empty()) (void)sqlite3_bind_text(stmt, bi++, invited_uid.c_str(), -1, SQLITE_TRANSIENT);
  (void)sqlite3_bind_int(stmt, bi++, limit);

  std::vector<InviteRow> out;
  while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
    out.push_back(ReadInvite(stmt));
  }
  sqlite3_finalize(stmt);

  if (rc != SQLITE_DONE) return core::Result<std::vector<InviteRow>>::Err(StmtErr(rc, dbh, "step(list)"));
  return core::Result<std::vector<InviteRow>>::Ok(std::move(out));
}


core::Result<std::vector<std::string>> InviteRepo::GetInvitedUids(const std::string& tenant_id,
                                                                     std::int64_t now) {
  sqlite3* dbh = db_.handle();
  if (dbh == nullptr) return core::Result<std::vector<std::string>>::Err(core::Status::Error(core::StatusCode::kFailedPrecondition, "DB not open"));

  // A user counts as "already invited" if they have a completed invite (status=4)
  // or a non-revoked invite that has not yet expired.
  const char* sql =
      "SELECT DISTINCT invited_uid FROM invite "
      "WHERE tenant_id=? AND invited_uid IS NOT NULL AND status != 6 "
      "AND (status = 4 OR expires_at > ?);";
  sqlite3_stmt* stmt = nullptr;
  int rc = sqlite3_prepare_v2(dbh, sql, -1, &stmt, nullptr);
  if (rc != SQLITE_OK) return core::Result<std::vector<std::string>>::Err(StmtErr(rc, dbh, "prepare(get_invited_uids)"));

  (void)sqlite3_bind_text(stmt, 1, tenant_id.c_str(), -1, SQLITE_TRANSIENT);
  (void)sqlite3_bind_int64(stmt, 2, now);

  std::vector<std::string> out;
  while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
    out.push_back(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0)));
  }
  sqlite3_finalize(stmt);

  if (rc != SQLITE_DONE) return core::Result<std::vector<std::string>>::Err(StmtErr(rc, dbh, "step(get_invited_uids)"));
  return core::Result<std::vector<std::string>>::Ok(std::move(out));
}

core::Result<void> InviteRepo::RevokePending(const std::string& tenant_id,
                                             const std::string& uid,
                                             std::int64_t now) {
  sqlite3* dbh = db_.handle();
  if (dbh == nullptr) return core::Result<void>::Err(core::Status::Error(core::StatusCode::kFailedPrecondition, "DB not open"));

  sqlite3_stmt* stmt = nullptr;
  const char* sql =
      "UPDATE invite SET status=6, revoked_at=? "
      "WHERE tenant_id=? AND invited_uid=? AND status NOT IN (4, 6);";
  int rc = sqlite3_prepare_v2(dbh, sql, -1, &stmt, nullptr);
  if (rc != SQLITE_OK) return core::Result<void>::Err(StmtErr(rc, dbh, "prepare(revoke_pending)"));

  (void)sqlite3_bind_int64(stmt, 1, now);
  (void)sqlite3_bind_text(stmt, 2, tenant_id.c_str(), -1, SQLITE_TRANSIENT);
  (void)sqlite3_bind_text(stmt, 3, uid.c_str(), -1, SQLITE_TRANSIENT);

  rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  if (rc != SQLITE_DONE) return core::Result<void>::Err(StmtErr(rc, dbh, "step(revoke_pending)"));
  return core::Result<void>::Ok();
}


core::Result<std::vector<InviteRow>> InviteRepo::GetLatestPerUid(const std::string& tenant_id) {
  sqlite3* dbh = db_.handle();
  if (dbh == nullptr) return core::Result<std::vector<InviteRow>>::Err(
      core::Status::Error(core::StatusCode::kFailedPrecondition, "DB not open"));

  // For each uid in the tenant, return the most recently created invite.
  const char* sql =
      "SELECT i.invite_id,i.tenant_id,i.invited_email,COALESCE(i.invited_uid,''),"
      "i.token_hash,i.status,i.created_at,i.expires_at,"
      "i.consumed_at,i.revoked_at,COALESCE(i.created_by,'') "
      "FROM invite i "
      "INNER JOIN ("
      "  SELECT invited_uid, MAX(created_at) AS max_at "
      "  FROM invite WHERE tenant_id=? AND invited_uid IS NOT NULL "
      "  GROUP BY invited_uid"
      ") latest ON i.invited_uid = latest.invited_uid AND i.created_at = latest.max_at "
      "WHERE i.tenant_id=?;";

  sqlite3_stmt* stmt = nullptr;
  int rc = sqlite3_prepare_v2(dbh, sql, -1, &stmt, nullptr);
  if (rc != SQLITE_OK) return core::Result<std::vector<InviteRow>>::Err(
      StmtErr(rc, dbh, "prepare(get_latest_per_uid)"));

  (void)sqlite3_bind_text(stmt, 1, tenant_id.c_str(), -1, SQLITE_TRANSIENT);
  (void)sqlite3_bind_text(stmt, 2, tenant_id.c_str(), -1, SQLITE_TRANSIENT);

  std::vector<InviteRow> out;
  while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
    out.push_back(ReadInvite(stmt));
  }
  sqlite3_finalize(stmt);

  if (rc != SQLITE_DONE) return core::Result<std::vector<InviteRow>>::Err(
      StmtErr(rc, dbh, "step(get_latest_per_uid)"));
  return core::Result<std::vector<InviteRow>>::Ok(std::move(out));
}
}  // namespace gatehouse::infra
