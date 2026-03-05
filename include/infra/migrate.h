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
};

// Applies schema incrementally:
// - if user_version == 0: apply v1 -> user_version=1
// - if user_version == 1: apply v2 -> user_version=2
// - if user_version == 2: apply v3 -> user_version=3
// - if user_version == 3: apply v4 -> user_version=4
[[nodiscard]] core::Result<void> Migrate(SqliteDb& db, const MigrateConfig& cfg);

}  // namespace gatehouse::infra
