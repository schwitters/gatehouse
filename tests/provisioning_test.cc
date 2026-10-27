#include "core/provisioning.h"

#include <gtest/gtest.h>

namespace gatehouse::core {
namespace {
Result<void> Failure() {
  return Result<void>::Err(
      Status::Error(StatusCode::kUnavailable, "Injected failure"));
}
class Store final : public ProvisionStore {
 public:
  ProvisionStage stage{ProvisionStage::kReady};
  bool fail_save{false};
  bool fail_complete{false};
  Result<ProvisionStage> Load(const ProvisionRequest&) override {
    return Result<ProvisionStage>::Ok(stage);
  }
  Result<void> Transition(const ProvisionRequest&, ProvisionStage from,
                          ProvisionStage to) override {
    if (stage != from || (fail_save && to == ProvisionStage::kPrincipalCreated))
      return Failure();
    stage = to;
    return Result<void>::Ok();
  }
  Result<void> Complete(const ProvisionRequest&) override {
    if (fail_complete) return Failure();
    stage = ProvisionStage::kCompleted;
    return Result<void>::Ok();
  }
};
class Accounts final : public AccountProvisioner {
 public:
  int creates{0};
  int activations{0};
  bool fail_prepare{false}, fail_create{false}, fail_activate{false};
  bool fail_confirm{false};
  Result<void> Prepare(const ProvisionRequest&) override {
    return fail_prepare ? Failure() : Result<void>::Ok();
  }
  Result<void> CreatePrincipal(const std::string&) override {
    ++creates;
    return fail_create ? Failure() : Result<void>::Ok();
  }
  Result<void> ConfirmPrincipal(const std::string&) override {
    return fail_confirm ? Failure() : Result<void>::Ok();
  }
  Result<void> Activate() override {
    ++activations;
    return fail_activate ? Failure() : Result<void>::Ok();
  }
};
const ProvisionRequest kRequest{"invitation", "session", "User",
                                "long-password"};

TEST(ProvisioningTest, SuccessAndReplayDoNotDuplicateExternalEffects) {
  Store store;
  Accounts accounts;
  ASSERT_TRUE(ProvisionAccount(kRequest, store, accounts).ok());
  EXPECT_EQ(store.stage, ProvisionStage::kCompleted);
  ASSERT_TRUE(ProvisionAccount(kRequest, store, accounts).ok());
  EXPECT_EQ(accounts.creates, 1);
  EXPECT_EQ(accounts.activations, 1);
}
TEST(ProvisioningTest, FailedPreflightHasNoExternalEffects) {
  Store store;
  Accounts accounts;
  accounts.fail_prepare = true;
  EXPECT_FALSE(ProvisionAccount(kRequest, store, accounts).ok());
  EXPECT_EQ(store.stage, ProvisionStage::kReady);
  EXPECT_EQ(accounts.creates, 0);
}
TEST(ProvisioningTest, UncertainCreationCannotBeRepeated) {
  Store store;
  Accounts accounts;
  accounts.fail_create = true;
  EXPECT_FALSE(ProvisionAccount(kRequest, store, accounts).ok());
  EXPECT_FALSE(ProvisionAccount(kRequest, store, accounts).ok());
  EXPECT_EQ(accounts.creates, 1);
  EXPECT_EQ(accounts.activations, 0);
  EXPECT_EQ(store.stage, ProvisionStage::kCreating);
}
TEST(ProvisioningTest, LostCreationCheckpointRequiresReconciliation) {
  Store store;
  Accounts accounts;
  store.fail_save = true;
  EXPECT_FALSE(ProvisionAccount(kRequest, store, accounts).ok());
  EXPECT_FALSE(ProvisionAccount(kRequest, store, accounts).ok());
  EXPECT_EQ(accounts.creates, 1);
  EXPECT_EQ(store.stage, ProvisionStage::kCreating);
}
TEST(ProvisioningTest, ActivationCanBeRetriedWithoutCreatingPrincipalAgain) {
  Store store;
  Accounts accounts;
  accounts.fail_activate = true;
  EXPECT_FALSE(ProvisionAccount(kRequest, store, accounts).ok());
  EXPECT_EQ(store.stage, ProvisionStage::kPrincipalCreated);
  accounts.fail_activate = false;
  ASSERT_TRUE(ProvisionAccount(kRequest, store, accounts).ok());
  EXPECT_EQ(accounts.creates, 1);
  EXPECT_EQ(accounts.activations, 2);
}
TEST(ProvisioningTest, CompletionRetryDoesNotRepeatExternalEffects) {
  Store store;
  Accounts accounts;
  store.fail_complete = true;
  EXPECT_FALSE(ProvisionAccount(kRequest, store, accounts).ok());
  EXPECT_EQ(store.stage, ProvisionStage::kActivated);
  store.fail_complete = false;
  EXPECT_TRUE(ProvisionAccount(kRequest, store, accounts).ok());
  EXPECT_EQ(accounts.creates, 1);
  EXPECT_EQ(accounts.activations, 1);
}
TEST(ProvisioningTest, InterruptedActivationRequiresReconciliation) {
  Store store;
  Accounts accounts;
  store.stage = ProvisionStage::kActivating;
  EXPECT_FALSE(ProvisionAccount(kRequest, store, accounts).ok());
  EXPECT_EQ(accounts.creates, 0);
  EXPECT_EQ(accounts.activations, 0);
}
TEST(ProvisioningTest, RetryMustConfirmTheExistingPrincipalPassword) {
  Store store;
  Accounts accounts;
  store.stage = ProvisionStage::kPrincipalCreated;
  accounts.fail_confirm = true;
  EXPECT_FALSE(ProvisionAccount(kRequest, store, accounts).ok());
  EXPECT_EQ(store.stage, ProvisionStage::kPrincipalCreated);
  EXPECT_EQ(accounts.creates, 0);
  EXPECT_EQ(accounts.activations, 0);
}

TEST(ProvisioningTest, RejectsShortPassword) {
  Store store;
  Accounts accounts;
  auto request = kRequest;
  request.password = "short";
  EXPECT_FALSE(ProvisionAccount(request, store, accounts).ok());
  EXPECT_EQ(accounts.creates, 0);
}
}  // namespace
}  // namespace gatehouse::core
