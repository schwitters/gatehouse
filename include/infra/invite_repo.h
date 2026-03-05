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

  [[nodiscard]] core::Result<void> Revoke(const std::string& invite_id, std::int64_t now);

  // List newest invites, optionally filtered by tenant_id and/or invited_uid.
  [[nodiscard]] core::Result<std::vector<InviteRow>> ListLatest(std::int32_t limit,
                                                                const std::string& tenant_id,
                                                                const std::string& invited_uid);

 private:
  SqliteDb& db_;
};

}  // namespace gatehouse::infra
