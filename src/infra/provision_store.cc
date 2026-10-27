#include "infra/provision_store.h"

#include <memory>
#include <string>

#include "core/time.h"
#include "infra/invite_session_repo.h"
#include "infra/sqlite_transaction.h"

namespace gatehouse::infra {
namespace {
struct FinalizeStatement {
  void operator()(sqlite3_stmt* statement) const {
    sqlite3_finalize(statement);
  }
};
using Statement = std::unique_ptr<sqlite3_stmt, FinalizeStatement>;

core::Status DatabaseError() {
  return core::Status::Error(
      core::StatusCode::kFailedPrecondition,
      "Provisioning state changed, is invalid, or storage failed");
}

core::Result<Statement> Prepare(SqliteDb& db, const char* sql,
                                const core::ProvisionRequest& request) {
  sqlite3_stmt* raw = nullptr;
  const int result = sqlite3_prepare_v2(db.handle(), sql, -1, &raw, nullptr);
  Statement statement(raw);
  if (result != SQLITE_OK ||
      sqlite3_bind_text(raw, 1, request.invite_id.c_str(), -1,
                        SQLITE_TRANSIENT) != SQLITE_OK ||
      sqlite3_bind_text(raw, 2, request.session_id.c_str(), -1,
                        SQLITE_TRANSIENT) != SQLITE_OK ||
      sqlite3_bind_int64(raw, 3, core::UnixNow()) != SQLITE_OK) {
    return core::Result<Statement>::Err(DatabaseError());
  }
  return core::Result<Statement>::Ok(std::move(statement));
}
}  // namespace

core::Result<core::ProvisionStage> SqliteProvisionStore::Load(
    const core::ProvisionRequest& request) {
  SqliteTransaction transaction(db_);
  auto begun = transaction.Begin();
  if (!begun.ok())
    return core::Result<core::ProvisionStage>::Err(begun.status());
  auto insert = Prepare(db_, R"SQL(
    INSERT INTO provisioning_job(invite_id, session_id, tenant_id, uid, stage, updated_at)
    SELECT i.invite_id, s.sid, i.tenant_id, i.invited_uid, 0, ?3
    FROM invite AS i JOIN invite_session AS s ON s.invite_id = i.invite_id
    WHERE i.invite_id = ?1 AND s.sid = ?2
      AND i.status NOT IN (4, 5, 6) AND COALESCE(i.revoked_at, 0) = 0 AND i.expires_at > ?3
      AND s.consumed_at IS NULL AND s.expires_at > ?3
      AND EXISTS (SELECT 1 FROM invite_otp WHERE sid = ?2 AND consumed_at IS NOT NULL)
    ON CONFLICT(invite_id) DO UPDATE SET session_id = excluded.session_id
    WHERE provisioning_job.stage IN (0, 2, 4)
  )SQL",
                        request);
  if (!insert.ok())
    return core::Result<core::ProvisionStage>::Err(insert.status());
  if (sqlite3_step(insert.value().get()) != SQLITE_DONE) {
    return core::Result<core::ProvisionStage>::Err(DatabaseError());
  }
  auto select = Prepare(db_, R"SQL(
    SELECT p.stage FROM provisioning_job AS p
    JOIN invite AS i ON i.invite_id = p.invite_id
    JOIN invite_session AS s ON s.sid = p.session_id
    WHERE p.invite_id = ?1 AND p.session_id = ?2 AND COALESCE(i.revoked_at, 0) = 0
      AND i.status NOT IN (5, 6) AND i.expires_at > ?3 AND s.expires_at > ?3
  )SQL",
                        request);
  if (!select.ok())
    return core::Result<core::ProvisionStage>::Err(select.status());
  if (sqlite3_step(select.value().get()) != SQLITE_ROW) {
    return core::Result<core::ProvisionStage>::Err(DatabaseError());
  }
  auto stage = static_cast<core::ProvisionStage>(
      sqlite3_column_int(select.value().get(), 0));
  select.value().reset();
  auto committed = transaction.Commit();
  if (!committed.ok())
    return core::Result<core::ProvisionStage>::Err(committed.status());
  return core::Result<core::ProvisionStage>::Ok(stage);
}

core::Result<void> SqliteProvisionStore::Transition(
    const core::ProvisionRequest& request, core::ProvisionStage from,
    core::ProvisionStage to) {
  auto statement = Prepare(db_, R"SQL(
    UPDATE provisioning_job SET stage = ?5, updated_at = ?3
    WHERE invite_id = ?1 AND session_id = ?2 AND stage = ?4
      AND EXISTS (
        SELECT 1 FROM invite WHERE invite_id = ?1 AND status NOT IN (4, 5, 6)
          AND COALESCE(revoked_at, 0) = 0 AND expires_at > ?3
      )
  )SQL",
                           request);
  if (!statement.ok()) return core::Result<void>::Err(statement.status());
  if (sqlite3_bind_int(statement.value().get(), 4, static_cast<int>(from)) !=
          SQLITE_OK ||
      sqlite3_bind_int(statement.value().get(), 5, static_cast<int>(to)) !=
          SQLITE_OK ||
      sqlite3_step(statement.value().get()) != SQLITE_DONE ||
      sqlite3_changes(db_.handle()) != 1) {
    return core::Result<void>::Err(DatabaseError());
  }
  return core::Result<void>::Ok();
}

core::Result<void> SqliteProvisionStore::Complete(
    const core::ProvisionRequest& request) {
  SqliteTransaction transaction(db_);
  auto result = transaction.Begin();
  if (!result.ok()) return result;
  result = Transition(request, core::ProvisionStage::kActivated,
                      core::ProvisionStage::kCompleted);
  if (!result.ok()) return result;
  InviteProfileRepo profiles(db_);
  auto now = core::UnixNow();
  result = profiles.Upsert({request.invite_id, request.display_name, now, now});
  if (!result.ok()) return result;
  for (const auto* sql : {
           R"SQL(
        UPDATE invite SET status = 4, consumed_at = ?3
        WHERE invite_id = ?1 AND status NOT IN (4, 5, 6) AND COALESCE(revoked_at, 0) = 0
          AND expires_at > ?3 AND EXISTS (
            SELECT 1 FROM invite_session WHERE sid = ?2 AND consumed_at IS NULL AND expires_at > ?3
          )
      )SQL",
           R"SQL(
        UPDATE invite_session SET consumed_at = ?3
        WHERE invite_id = ?1 AND sid = ?2 AND consumed_at IS NULL AND expires_at > ?3
      )SQL"}) {
    auto statement = Prepare(db_, sql, request);
    if (!statement.ok()) return core::Result<void>::Err(statement.status());
    if (sqlite3_step(statement.value().get()) != SQLITE_DONE ||
        sqlite3_changes(db_.handle()) != 1) {
      return core::Result<void>::Err(DatabaseError());
    }
  }
  return transaction.Commit();
}

}  // namespace gatehouse::infra
