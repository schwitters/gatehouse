#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "core/result.h"
#include "infra/sqlite_db.h"

namespace gatehouse::infra {

enum class InviteStatus : std::int32_t {
  kInvited = 0,
  kLinkVerified = 1,
  kStepupSent = 2,
  kStepupVerified = 3,
  kCompleted = 4,
  kExpired = 5,
  kRevoked = 6,
};

struct InviteRow {
  std::string invite_id;
  std::string tenant_id;
  std::string invited_email;
  std::string invited_uid;

  std::vector<std::uint8_t> token_hash;
  InviteStatus status{InviteStatus::kInvited};

  std::int64_t created_at{0};
  std::int64_t expires_at{0};
  std::int64_t consumed_at{0};
  std::int64_t revoked_at{0};
  std::string created_by;
};

class InviteRepo final {
 public:
  explicit InviteRepo(SqliteDb& db);

  [[nodiscard]] core::Result<void> Insert(const InviteRow& row);

  [[nodiscard]] core::Result<std::optional<InviteRow>> GetByTokenHash(
      const std::vector<std::uint8_t>& token_hash);

  [[nodiscard]] core::Result<std::optional<InviteRow>> GetById(const std::string& invite_id);

  [[nodiscard]] core::Result<void> UpdateStatus(const std::string& invite_id, InviteStatus st,
                                                std::int64_t now);

  [[nodiscard]] core::Result<void> UpdateEmail(const std::string& invite_id,
                                               const std::string& email);

  [[nodiscard]] core::Result<void> Revoke(const std::string& invite_id, std::int64_t now);

  // Revoke all non-completed, non-revoked invites for tenant+uid (used before re-invite).
  [[nodiscard]] core::Result<void> RevokePending(const std::string& tenant_id,
                                                 const std::string& uid,
                                                 std::int64_t now);

  // Returns UIDs that have an active (non-expired, non-revoked) or completed invite.
  [[nodiscard]] core::Result<std::vector<std::string>> GetInvitedUids(const std::string& tenant_id,
                                                                       std::int64_t now);

  [[nodiscard]] core::Result<std::vector<InviteRow>> ListLatest(std::int32_t limit,
                                                                const std::string& tenant_id,
                                                                const std::string& invited_uid);

  // Returns the most recent invite per uid for the given tenant.
  // Result is one InviteRow per uid (the latest by created_at).
  [[nodiscard]] core::Result<std::vector<InviteRow>> GetLatestPerUid(
      const std::string& tenant_id);

 private:
  SqliteDb& db_;
};

}  // namespace gatehouse::infra
