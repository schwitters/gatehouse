#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "app/http_server.h"
#include "infra/migrate.h"
#include "infra/sqlite_db.h"

namespace {

void PrintUsage(const char* argv0) {
  std::cerr
      << "Usage: " << argv0
      << " [--bind ADDR] [--port PORT] [--threads N] [--db PATH]\n"
      << "       [--session-ttl SECONDS] [--cookie NAME]\n"
      << "       [--realm REALM]\n"
      << "       [--public-base-url URL] [--invite-ttl SECONDS]\n"
      << "       [--admin-uids CSV] [--ldap-admin-group DN] [--email-backend console|curl]\n"
      << "       [--ldap-url URL] [--ldap-bind-dn DN] [--ldap-bind-pw PW]\n"
      << "       [--ldap-base-dn DN] [--ldap-starttls]\n"
      << "       [--ldif PATH]  (fallback)\n";
}

bool ParseU16(const std::string& s, std::uint16_t* out) {
  try {
    const unsigned long v = std::stoul(s);
    if (v > 65535UL) return false;
    *out = static_cast<std::uint16_t>(v);
    return true;
  } catch (...) { return false; }
}
bool ParseU32(const std::string& s, std::uint32_t* out) {
  try {
    const unsigned long v = std::stoul(s);
    if (v > 0xFFFFFFFFUL) return false;
    *out = static_cast<std::uint32_t>(v);
    return true;
  } catch (...) { return false; }
}
bool ParseI64(const std::string& s, std::int64_t* out) {
  try {
    const long long v = std::stoll(s);
    *out = static_cast<std::int64_t>(v);
    return true;
  } catch (...) { return false; }
}

std::vector<std::string> SplitCsv(const std::string& s) {
  std::vector<std::string> out;
  std::string cur;
  for (char c : s) {
    if (c == ',') {
      if (!cur.empty()) out.push_back(cur);
      cur.clear();
      continue;
    }
    cur.push_back(c);
  }
  if (!cur.empty()) out.push_back(cur);
  return out;
}

}  // namespace

int main(int argc, char** argv) {
  gatehouse::app::HttpServerConfig cfg;
  std::string db_path{"gatehouse.db"};

  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];

    if (arg == "--help" || arg == "-h") { PrintUsage(argv[0]); return 0; }
    if (arg == "--bind" && i + 1 < argc) { cfg.bind_addr = argv[++i]; continue; }
    if (arg == "--port" && i + 1 < argc) {
      std::uint16_t port{};
      if (!ParseU16(argv[++i], &port)) { std::cerr << "Invalid --port\n"; return 2; }
      cfg.port = port; continue;
    }
    if (arg == "--threads" && i + 1 < argc) {
      std::uint32_t th{};
      if (!ParseU32(argv[++i], &th) || th == 0) { std::cerr << "Invalid --threads\n"; return 2; }
      cfg.threads = th; continue;
    }
    if (arg == "--db" && i + 1 < argc) { db_path = argv[++i]; continue; }
    if (arg == "--session-ttl" && i + 1 < argc) {
      std::int64_t ttl{};
      if (!ParseI64(argv[++i], &ttl) || ttl <= 0) { std::cerr << "Invalid --session-ttl\n"; return 2; }
      cfg.session_ttl_seconds = ttl; continue;
    }
    if (arg == "--cookie" && i + 1 < argc) { cfg.session_cookie_name = argv[++i]; continue; }
    if (arg == "--realm" && i + 1 < argc) { cfg.auth_cfg.krb5_realm = argv[++i]; continue; }

    if (arg == "--public-base-url" && i + 1 < argc) { cfg.public_base_url = argv[++i]; continue; }
    if (arg == "--invite-ttl" && i + 1 < argc) {
      std::int64_t ttl{};
      if (!ParseI64(argv[++i], &ttl) || ttl <= 0) { std::cerr << "Invalid --invite-ttl\n"; return 2; }
      cfg.invite_ttl_seconds = ttl; continue;
    }
    if (arg == "--admin-uids" && i + 1 < argc) { cfg.admin_uids = SplitCsv(argv[++i]); continue; }
    if (arg == "--ldap-admin-group" && i + 1 < argc) { cfg.ldap_admin_group = argv[++i]; continue; }
    if (arg == "--email-backend" && i + 1 < argc) { cfg.email_backend = argv[++i]; continue; }

    // LDAP
    if (arg == "--ldap-url" && i + 1 < argc) { cfg.ldap_url = argv[++i]; continue; }
    if (arg == "--ldap-bind-dn" && i + 1 < argc) { cfg.ldap_bind_dn = argv[++i]; continue; }
    if (arg == "--ldap-bind-pw" && i + 1 < argc) { cfg.ldap_bind_pw = argv[++i]; continue; }
    if (arg == "--ldap-base-dn" && i + 1 < argc) { cfg.ldap_base_dn = argv[++i]; continue; }
    if (arg == "--ldap-starttls") { cfg.ldap_starttls = true; continue; }

    // LDIF fallback
    if (arg == "--ldif" && i + 1 < argc) { cfg.ldif_path = argv[++i]; continue; }

    std::cerr << "Unknown arg: " << arg << "\n";
    PrintUsage(argv[0]);
    return 2;
  }

  auto db = std::make_shared<gatehouse::infra::SqliteDb>();
  {
    auto rc = db->Open(db_path);
    if (!rc.ok()) { std::cerr << "DB open failed: " << rc.status().ToString() << "\n"; return 1; }
  }
  {
    gatehouse::infra::MigrateConfig mcfg;
    mcfg.schema_v1_path = "db/schema_v1.sql";
    mcfg.schema_v2_path = "db/schema_v2.sql";
    auto rc = gatehouse::infra::Migrate(*db, mcfg);
    if (!rc.ok()) { std::cerr << "DB migrate failed: " << rc.status().ToString() << "\n"; return 1; }
  }

  gatehouse::app::HttpServer server(cfg, db);
  const auto rc = server.Run();
  if (!rc.ok()) { std::cerr << "Fatal: " << rc.status().ToString() << "\n"; return 1; }
  return 0;
}
