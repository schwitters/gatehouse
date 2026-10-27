#include "infra/sqlite_transaction.h"

#include "infra/logging.h"

namespace gatehouse::infra {

SqliteTransaction::~SqliteTransaction() {
  if (!active_) return;
  const auto result = db_.Exec("ROLLBACK;");
  if (!result.ok()) LogOperationFailure("transaction rollback");
}

core::Result<void> SqliteTransaction::Begin() {
  if (active_)
    return core::Result<void>::Err(core::Status::Error(
        core::StatusCode::kFailedPrecondition, "Transaction already active"));
  auto result = db_.Exec("BEGIN IMMEDIATE;");
  if (result.ok()) active_ = true;
  return result;
}

core::Result<void> SqliteTransaction::Commit() {
  auto result = db_.Exec("COMMIT;");
  if (result.ok()) active_ = false;
  return result;
}

}  // namespace gatehouse::infra
