#pragma once

#include "core/provisioning.h"
#include "infra/sqlite_db.h"

namespace gatehouse::infra {

class SqliteProvisionStore final : public core::ProvisionStore {
 public:
  explicit SqliteProvisionStore(SqliteDb& db) : db_(db) {}
  [[nodiscard]] core::Result<core::ProvisionStage> Load(
      const core::ProvisionRequest& request) override;
  [[nodiscard]] core::Result<void> Transition(
      const core::ProvisionRequest& request, core::ProvisionStage from,
      core::ProvisionStage to) override;
  [[nodiscard]] core::Result<void> Complete(
      const core::ProvisionRequest& request) override;

 private:
  SqliteDb& db_;
};

}  // namespace gatehouse::infra
