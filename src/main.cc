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
      << "Usage: " << argv0 << " [OPTIONS]\n"
      << "\n"
      << "General:\n"
      << "  --instance-title TITLE Instance title shown in UI and emails (default: Gatehouse)\n"
      << "\n"
      << "Server:\n"
      << "  --bind ADDR            TCP bind address (default: 0.0.0.0)\n"
      << "  --port PORT            TCP port (default: 18080)\n"
      << "  --unix-socket PATH     Listen on Unix Domain Socket instead of TCP\n"
      << "  --threads N            Worker threads (default: 2)\n"
      << "  --db PATH              SQLite database path (default: gatehouse.db)\n"
      << "\n"
      << "Session:\n"
      << "  --session-ttl SECONDS  Session lifetime (default: 3600)\n"
      << "  --cookie NAME          Session cookie name (default: gh_sid)\n"
      << "\n"
      << "Auth:\n"
      << "  --realm REALM          Kerberos realm\n"
      << "\n"
      << "Invitations:\n"
      << "  --public-base-url URL  Base URL for invite links (default: http://127.0.0.1:18080)\n"
      << "  --invite-ttl SECONDS   Invite link lifetime (default: 604800)\n"
      << "  --admin-uids CSV       Comma-separated UIDs with admin access (default: demo)\n"
      << "  --ldap-admin-group DN  LDAP group DN whose members get admin access\n"
      << "  --email-backend MODE   Email delivery: console (default) | curl\n"
      << "\n"
      << "LDAP:\n"
      << "  --ldap-url URL         LDAP server URL (ldap:// or ldaps://)\n"
      << "  --ldap-bind-dn DN      Bind DN\n"
      << "  --ldap-bind-pw PW      Bind password\n"
      << "  --ldap-base-dn DN      Base DN (default: dc=catuno,dc=lab)\n"
      << "  --ldap-starttls        Upgrade LDAP connection with StartTLS\n"
      << "\n"
      << "Guacamole:\n"
      << "  --guacamole-url URL          Guacamole web app base URL (enables Connect buttons)\n"
      << "  --guacamole-secret S         Shared secret for Guacamole Encrypted JSON auth\n"
      << "  --guac-token-ttl SECS        Credential-fetch token lifetime (default: 60)\n"
      << "  --guac-connection-template P Path to Guacamole connection JSON template\n"
      << "                               (default: built-in; see config/guac_connection_template.json)\n"
      << "\n"
      << "Security:\n"
      << "  --secure-cookies       Set Secure flag on session cookies (use with HTTPS/reverse proxy)\n"
      << "  --ldif PATH            LDIF file as directory fallback (dev/test)\n"
      << "\n"
      << "Reverse proxy:\n"
      << "  --base-uri PATH        URL path prefix (e.g. /gatehouse). Must start with /,\n"
      << "                         must not end with /. Empty = serve at root (default)\n"
      << "\n"
      << "Environment variables:\n"
      << "  GATEHOUSE_MASTER_KEY_HEX   (required) 64 hex chars = 32-byte AES-256-GCM key\n"
      << "                             Generate: openssl rand -hex 32\n"
      << "  GATEHOUSE_KADM5_ADMIN_PRINC  Kerberos admin principal for invite completion\n"
      << "  GATEHOUSE_KADM5_ADMIN_PASS   Kerberos admin password\n"
      << "  GATEHOUSE_SMTP_USER        SMTP username (--email-backend curl)\n"
      << "  GATEHOUSE_SMTP_PASS        SMTP app password (--email-backend curl)\n"
      << "  GATEHOUSE_SMTP_URL         SMTP server URL (default: smtps://smtp.gmail.com:465)\n";
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
  if (argc == 1) { PrintUsage(argv[0]); return 0; }

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
    if (arg == "--instance-title" && i + 1 < argc) { cfg.instance_title = argv[++i]; continue; }
    if (arg == "--unix-socket" && i + 1 < argc) { cfg.unix_socket = argv[++i]; continue; }
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
    if (arg == "--secure-cookies") { cfg.secure_cookies = true; continue; }

    // Guacamole
    if (arg == "--guacamole-url" && i + 1 < argc) { cfg.guacamole_url = argv[++i]; continue; }
    if (arg == "--guacamole-secret" && i + 1 < argc) { cfg.guacamole_secret = argv[++i]; continue; }
    if (arg == "--guac-connection-template" && i + 1 < argc) { cfg.guac_connection_template_path = argv[++i]; continue; }
    if (arg == "--guac-token-ttl" && i + 1 < argc) {
      std::int64_t ttl{};
      if (!ParseI64(argv[++i], &ttl) || ttl <= 0) { std::cerr << "Invalid --guac-token-ttl\n"; return 2; }
      cfg.guac_token_ttl_seconds = ttl; continue;
    }

    // LDIF fallback
    if (arg == "--ldif" && i + 1 < argc) { cfg.ldif_path = argv[++i]; continue; }

    // Reverse proxy
    if (arg == "--base-uri" && i + 1 < argc) { cfg.base_uri = argv[++i]; continue; }

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
