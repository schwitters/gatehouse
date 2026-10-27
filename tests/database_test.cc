#include <gtest/gtest.h>
#include <unistd.h>

#include <chrono>
#include <filesystem>
#include <future>

#include "core/time.h"
#include "infra/migrate.h"
#include "infra/invite_session_repo.h"
#include "infra/invite_otp_repo.h"
#include "infra/provision_store.h"
#include "infra/sqlite_db.h"
#include "infra/sqlite_transaction.h"

namespace gatehouse::infra {
namespace {
class DatabaseTest : public testing::Test {
 protected:
  void SetUp() override {
    char pattern[] = "/tmp/gatehouse-db-XXXXXX";
    const int descriptor = mkstemp(pattern);
    ASSERT_GE(descriptor, 0);
    ASSERT_EQ(close(descriptor), 0);
    path_ = pattern;
    ASSERT_TRUE(db_.Open(path_.string()).ok());
    ASSERT_TRUE(Migrate(db_, {}).ok());
  }
  void TearDown() override {
    db_.Close();
    std::filesystem::remove(path_);
    std::filesystem::remove(path_.string() + "-wal");
    std::filesystem::remove(path_.string() + "-shm");
  }
  void Seed() {
    const auto now = core::UnixNow();
    ASSERT_TRUE(db_.Exec(R"SQL(
      INSERT INTO invite(invite_id, tenant_id, invited_email, invited_uid,
                         token_hash, status, created_at, expires_at)
      VALUES ('invitation', 'tenant', 'user@example.invalid', 'user', X'01', 3, 0,
    )SQL" + std::to_string(now + 3600) +
                         ");")
                    .ok());
    ASSERT_TRUE(db_.Exec(R"SQL(
      INSERT INTO invite_session(sid, invite_id, created_at, expires_at)
      VALUES ('session', 'invitation', 0,
    )SQL" + std::to_string(now + 1800) +
                         ");")
                    .ok());
    ASSERT_TRUE(db_.Exec(R"SQL(
      INSERT INTO invite_otp(otp_id, sid, otp_hash, issued_at, expires_at, consumed_at)
      VALUES ('otp', 'session', X'01', 0, 9999999999, 1)
    )SQL")
                    .ok());
  }
  std::filesystem::path path_;
  SqliteDb db_;
  core::ProvisionRequest request_{"invitation", "session", "Display",
                                  "long-password"};
};
TEST_F(DatabaseTest, WorkerReadsAreIsolatedFromUncommittedTransaction) {
  ASSERT_TRUE(db_.Exec("CREATE TABLE isolation_test(value INTEGER);").ok());
  SqliteTransaction transaction(db_);
  ASSERT_TRUE(transaction.Begin().ok());
  ASSERT_TRUE(db_.Exec("INSERT INTO isolation_test VALUES(1);").ok());
  auto worker = std::async(std::launch::async, [&] {
    if (!db_.ConnectForThread().ok()) return -1;
    sqlite3_stmt* statement = nullptr;
    if (sqlite3_prepare_v2(db_.handle(), "SELECT COUNT(*) FROM isolation_test;",
                           -1, &statement, nullptr) != SQLITE_OK)
      return -2;
    const int count = sqlite3_step(statement) == SQLITE_ROW
                          ? sqlite3_column_int(statement, 0)
                          : -3;
    sqlite3_finalize(statement);
    return count;
  });
  EXPECT_EQ(worker.wait_for(std::chrono::seconds(2)),
            std::future_status::ready);
  EXPECT_EQ(worker.get(), 0);
  ASSERT_TRUE(transaction.Commit().ok());
}
TEST_F(DatabaseTest, TransactionDestructorRollsBack) {
  ASSERT_TRUE(db_.Exec("CREATE TABLE rollback_test(value INTEGER);").ok());
  {
    SqliteTransaction transaction(db_);
    ASSERT_TRUE(transaction.Begin().ok());
    ASSERT_TRUE(db_.Exec("INSERT INTO rollback_test VALUES(1);").ok());
  }
  ASSERT_TRUE(db_.Exec("BEGIN IMMEDIATE;").ok());
  EXPECT_TRUE(db_.Exec("ROLLBACK;").ok());
}
TEST_F(DatabaseTest,
       ClaimIsExclusiveAndRevocationIsBlockedDuringExternalEffects) {
  Seed();
  SqliteProvisionStore store(db_);
  ASSERT_TRUE(store.Load(request_).ok());
  ASSERT_TRUE(store
                  .Transition(request_, core::ProvisionStage::kReady,
                              core::ProvisionStage::kCreating)
                  .ok());
  EXPECT_FALSE(store
                   .Transition(request_, core::ProvisionStage::kReady,
                               core::ProvisionStage::kCreating)
                   .ok());
  EXPECT_FALSE(db_.Exec("UPDATE invite SET status=6;").ok());
}
TEST_F(DatabaseTest, CompletionIsAtomicWhenSessionUpdateFails) {
  Seed();
  SqliteProvisionStore store(db_);
  ASSERT_TRUE(store.Load(request_).ok());
  ASSERT_TRUE(store
                  .Transition(request_, core::ProvisionStage::kReady,
                              core::ProvisionStage::kActivated)
                  .ok());
  ASSERT_TRUE(db_.Exec(R"SQL(
    CREATE TRIGGER fail_consume BEFORE UPDATE ON invite_session
    BEGIN SELECT RAISE(ABORT, 'Injected failure'); END;
  )SQL")
                  .ok());
  EXPECT_FALSE(store.Complete(request_).ok());
  auto state = store.Load(request_);
  ASSERT_TRUE(state.ok());
  EXPECT_EQ(state.value(), core::ProvisionStage::kActivated);
  ASSERT_TRUE(db_.Exec("DROP TRIGGER fail_consume;").ok());
  EXPECT_TRUE(store.Complete(request_).ok());
}
TEST_F(DatabaseTest, ExpiredSessionsRemoveDependentOtpRows) {
  Seed();
  ASSERT_TRUE(db_.Exec("UPDATE invite_session SET expires_at=0;").ok());
  InviteSessionRepo sessions(db_);
  ASSERT_TRUE(sessions.DeleteExpired(core::UnixNow()).ok());
  auto session = sessions.GetBySid("session");
  ASSERT_TRUE(session.ok());
  EXPECT_FALSE(session.value().has_value());
}
TEST_F(DatabaseTest, FailedOtpUpdateRollsBackAndDoesNotPoisonTheConnection) {
  Seed();
  ASSERT_TRUE(db_.Exec("UPDATE invite_otp SET consumed_at=NULL;").ok());
  ASSERT_TRUE(db_.Exec(R"SQL(
    CREATE TRIGGER fail_otp BEFORE UPDATE ON invite_otp
    BEGIN SELECT RAISE(ABORT, 'Injected failure'); END;
  )SQL").ok());
  InviteOtpRepo otps(db_);
  EXPECT_FALSE(otps.VerifyAndConsume("session", {1}, core::UnixNow()).ok());
  ASSERT_TRUE(db_.Exec("DROP TRIGGER fail_otp;").ok());
  auto consumed = otps.VerifyAndConsume("session", {1}, core::UnixNow());
  ASSERT_TRUE(consumed.ok());
  EXPECT_TRUE(consumed.value());
  auto replay = otps.VerifyAndConsume("session", {1}, core::UnixNow());
  ASSERT_TRUE(replay.ok());
  EXPECT_FALSE(replay.value());
}
TEST_F(DatabaseTest, FutureSchemaIsRejected) {
  ASSERT_TRUE(db_.SetPragmaUserVersion(8).ok());
  EXPECT_FALSE(Migrate(db_, {}).ok());
}
TEST_F(DatabaseTest, MigrationCanBeRepeated) {
  EXPECT_TRUE(Migrate(db_, {}).ok());
  auto version = db_.GetPragmaUserVersion();
  ASSERT_TRUE(version.ok());
  EXPECT_EQ(version.value(), 7);
}
}  // namespace
}  // namespace gatehouse::infra
