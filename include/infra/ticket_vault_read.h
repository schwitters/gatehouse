#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "core/result.h"
#include "infra/sqlite_db.h"

namespace gatehouse::infra {

struct TicketVaultReadRow {
  std::string ticket_id;
  std::string uid;
  std::string tenant_id;
  std::int64_t expires_at{0};

  std::string enc_alg;
  std::string enc_key_id;
  std::vector<std::uint8_t> nonce;
  std::vector<std::uint8_t> aad;
  std::vector<std::uint8_t> ccache_blob_enc;
};

class TicketVaultReadRepo final {
 public:
  explicit TicketVaultReadRepo(SqliteDb& db);

  [[nodiscard]] core::Result<std::optional<TicketVaultReadRow>> GetById(const std::string& ticket_id);

 private:
  SqliteDb& db_;
};

}  // namespace gatehouse::infra
