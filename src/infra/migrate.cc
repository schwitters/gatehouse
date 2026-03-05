#include "infra/migrate.h"

#include <fstream>
#include <sstream>
#include <string>

namespace gatehouse::infra {
namespace {

core::Result<std::string> ReadFileToString(const std::string& path) {
  std::ifstream in(path, std::ios::in | std::ios::binary);
  if (!in) {
    return core::Result<std::string>::Err(core::Status::Error(
        core::StatusCode::kNotFound, "schema file not found: " + path));
  }
  std::ostringstream ss;
  ss << in.rdbuf();
  return core::Result<std::string>::Ok(ss.str());
}

core::Result<void> ExecTx(SqliteDb& db, const std::string& sql) {
  auto rc = db.Exec("BEGIN IMMEDIATE;");
  if (!rc.ok()) return rc;

  rc = db.Exec(sql);
  if (!rc.ok()) {
    (void)db.Exec("ROLLBACK;");
    return rc;
  }

  rc = db.Exec("COMMIT;");
  if (!rc.ok()) {
    (void)db.Exec("ROLLBACK;");
    return rc;
  }
  return core::Result<void>::Ok();
}

}  // namespace

core::Result<void> Migrate(SqliteDb& db, const MigrateConfig& cfg) {
  auto v = db.GetPragmaUserVersion();
  if (!v.ok()) return core::Result<void>::Err(v.status());

  if (v.value() == 0) {
    auto sql = ReadFileToString(cfg.schema_v1_path);
    if (!sql.ok()) return core::Result<void>::Err(sql.status());
    auto rc = ExecTx(db, sql.value());
    if (!rc.ok()) return rc;
    auto u = db.SetPragmaUserVersion(1);
    if (!u.ok()) return u;
    v = db.GetPragmaUserVersion();
    if (!v.ok()) return core::Result<void>::Err(v.status());
  }

  if (v.value() == 1) {
    auto sql = ReadFileToString(cfg.schema_v2_path);
    if (!sql.ok()) return core::Result<void>::Err(sql.status());
    auto rc = ExecTx(db, sql.value());
    if (!rc.ok()) return rc;
    auto u = db.SetPragmaUserVersion(2);
    if (!u.ok()) return u;
    v = db.GetPragmaUserVersion();
    if (!v.ok()) return core::Result<void>::Err(v.status());
  }

  if (v.value() == 2) {
    auto sql = ReadFileToString(cfg.schema_v3_path);
    if (!sql.ok()) return core::Result<void>::Err(sql.status());
    auto rc = ExecTx(db, sql.value());
    if (!rc.ok()) return rc;
    auto u = db.SetPragmaUserVersion(3);
    if (!u.ok()) return u;
    v = db.GetPragmaUserVersion();
    if (!v.ok()) return core::Result<void>::Err(v.status());
  }

  if (v.value() == 3) {
    auto sql = ReadFileToString(cfg.schema_v4_path);
    if (!sql.ok()) return core::Result<void>::Err(sql.status());
    auto rc = ExecTx(db, sql.value());
    if (!rc.ok()) return rc;
    auto u = db.SetPragmaUserVersion(4);
    if (!u.ok()) return u;
    v = db.GetPragmaUserVersion();
    if (!v.ok()) return core::Result<void>::Err(v.status());
  }

  if (v.value() == 4) {
    auto sql = ReadFileToString(cfg.schema_v5_path);
    if (!sql.ok()) return core::Result<void>::Err(sql.status());
    auto rc = ExecTx(db, sql.value());
    if (!rc.ok()) return rc;
    auto u = db.SetPragmaUserVersion(5);
    if (!u.ok()) return u;
  }

  return core::Result<void>::Ok();
}

}  // namespace gatehouse::infra
