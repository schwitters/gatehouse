#include "core/provisioning.h"

namespace gatehouse::core {

Result<void> ProvisionAccount(const ProvisionRequest& request,
                              ProvisionStore& store,
                              AccountProvisioner& accounts) {
  constexpr std::size_t kMinimumPasswordLength = 8;
  if (request.password.size() < kMinimumPasswordLength ||
      request.invite_id.empty() || request.session_id.empty()) {
    return Result<void>::Err(Status::Error(StatusCode::kInvalidArgument,
                                           "Invalid provisioning request"));
  }
  auto loaded = store.Load(request);
  if (!loaded.ok()) return Result<void>::Err(loaded.status());
  auto stage = loaded.value();
  if (stage == ProvisionStage::kCompleted) return Result<void>::Ok();
  if (stage == ProvisionStage::kCreating ||
      stage == ProvisionStage::kActivating) {
    return Result<void>::Err(Status::Error(
        StatusCode::kFailedPrecondition,
        "Provisioning is in progress or requires operator reconciliation"));
  }
  auto prepared = accounts.Prepare(request);
  if (!prepared.ok()) return prepared;
  if (stage == ProvisionStage::kPrincipalCreated ||
      stage == ProvisionStage::kActivated) {
    auto confirmed = accounts.ConfirmPrincipal(request.password);
    if (!confirmed.ok()) return confirmed;
  }
  if (stage == ProvisionStage::kReady) {
    auto claimed = store.Transition(request, stage, ProvisionStage::kCreating);
    if (!claimed.ok()) return claimed;
    auto created = accounts.CreatePrincipal(request.password);
    // Failure may mean the remote side committed before the connection failed.
    // Keep kCreating; never automatically repeat an uncertain creation.
    if (!created.ok()) return created;
    auto saved = store.Transition(request, ProvisionStage::kCreating,
                                  ProvisionStage::kPrincipalCreated);
    if (!saved.ok()) return saved;
    stage = ProvisionStage::kPrincipalCreated;
  }
  if (stage == ProvisionStage::kPrincipalCreated) {
    auto claimed =
        store.Transition(request, stage, ProvisionStage::kActivating);
    if (!claimed.ok()) return claimed;
    auto activated = accounts.Activate();
    if (!activated.ok()) {
      auto reset = store.Transition(request, ProvisionStage::kActivating,
                                    ProvisionStage::kPrincipalCreated);
      if (!reset.ok()) return reset;
      return activated;
    }
    auto saved = store.Transition(request, ProvisionStage::kActivating,
                                  ProvisionStage::kActivated);
    if (!saved.ok()) return saved;
  }
  return store.Complete(request);
}

}  // namespace gatehouse::core
