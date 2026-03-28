#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "core/result.h"
#include "infra/sqlite_db.h"

namespace gatehouse::infra {

struct TicketVaultRow {
  std::string ticket_id;
  std::string uid;
  std::string tenant_id{"default"};
  std::int64_t created_at{0};
  std::int64_t expires_at{0};

  std::string enc_alg{"AES-256-GCM"};
  std::string enc_key_id{"env:v1"};
  std::vector<std::uint8_t> nonce;            // 12 bytes
  std::vector<std::uint8_t> aad;              // optional
  std::vector<std::uint8_t> ccache_blob_enc;  // ciphertext||tag
};

class TicketVaultRepo final {
 public:
  explicit TicketVaultRepo(SqliteDb& db);

  [[nodiscard]] core::Result<void> Insert(const TicketVaultRow& row);
  [[nodiscard]] core::Result<void> Delete(const std::string& ticket_id);

 private:
  SqliteDb& db_;
};

}  // namespace gatehouse::infra
