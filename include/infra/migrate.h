#pragma once

#include <string>

#include "core/result.h"
#include "infra/sqlite_db.h"

namespace gatehouse::infra {

struct MigrateConfig {
  std::string schema_v1_path{"db/schema_v1.sql"};
  std::string schema_v2_path{"db/schema_v2.sql"};
  std::string schema_v3_path{"db/schema_v3.sql"};
  std::string schema_v4_path{"db/schema_v4.sql"};
  std::string schema_v5_path{"db/schema_v5.sql"};
};

// Applies schema incrementally up to current.
// user_version: 0->1->2->3->4->5
[[nodiscard]] core::Result<void> Migrate(SqliteDb& db, const MigrateConfig& cfg);

}  // namespace gatehouse::infra
