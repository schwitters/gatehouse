#pragma once

#include <cstdint>
#include <string>

#include "core/result.h"

namespace gatehouse::core {

// Persist intent before external effects. An interrupted create requires
// reconciliation.
enum class ProvisionStage : std::int32_t {
  kReady = 0,
  kCreating = 1,
  kPrincipalCreated = 2,
  kActivating = 3,
  kActivated = 4,
  kCompleted = 5,
};

struct ProvisionRequest {
  std::string invite_id;
  std::string session_id;
  std::string display_name;
  std::string password;
};

class ProvisionStore {
 public:
  virtual ~ProvisionStore() = default;
  [[nodiscard]] virtual Result<ProvisionStage> Load(
      const ProvisionRequest& request) = 0;
  [[nodiscard]] virtual Result<void> Transition(const ProvisionRequest& request,
                                                ProvisionStage from,
                                                ProvisionStage to) = 0;
  [[nodiscard]] virtual Result<void> Complete(
      const ProvisionRequest& request) = 0;
};

class AccountProvisioner {
 public:
  virtual ~AccountProvisioner() = default;
  [[nodiscard]] virtual Result<void> Prepare(
      const ProvisionRequest& request) = 0;
  [[nodiscard]] virtual Result<void> CreatePrincipal(
      const std::string& password) = 0;
  [[nodiscard]] virtual Result<void> ConfirmPrincipal(
      const std::string& password) = 0;
  // Reapplying the same activation must be safe.
  [[nodiscard]] virtual Result<void> Activate() = 0;
};

[[nodiscard]] Result<void> ProvisionAccount(const ProvisionRequest& request,
                                            ProvisionStore& store,
                                            AccountProvisioner& accounts);

}  // namespace gatehouse::core
