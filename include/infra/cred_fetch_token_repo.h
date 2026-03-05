#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "core/result.h"
#include "infra/sqlite_db.h"

namespace gatehouse::infra {

struct CredFetchTokenRow {
  std::string cft_id;
  std::string uid;
  std::string tenant_id{"default"};
  std::string host_id;

  std::vector<std::uint8_t> token_hash;  // store raw hash bytes
  std::int64_t issued_at{0};
  std::int64_t expires_at{0};
  std::int64_t consumed_at{0};

  std::string ticket_id;
};

class CredFetchTokenRepo final {
 public:
  explicit CredFetchTokenRepo(SqliteDb& db);

  [[nodiscard]] core::Result<void> Insert(const CredFetchTokenRow& row);

  // Verify+consume atomically. Returns ticket_id on success.
  [[nodiscard]] core::Result<std::optional<std::string>> VerifyAndConsume(
      const std::string& uid, const std::string& host_id,
      const std::vector<std::uint8_t>& token_hash, std::int64_t now);

 private:
  SqliteDb& db_;
};

}  // namespace gatehouse::infra
