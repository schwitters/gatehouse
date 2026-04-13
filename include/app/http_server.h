#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "app/auth.h"
#include "core/result.h"

namespace gatehouse::infra {
class SqliteDb;
}

namespace gatehouse::app {

struct HttpServerConfig {
  std::string instance_title{"Gatehouse"};

  std::string bind_addr{"0.0.0.0"};
  std::uint16_t port{18080};
  std::uint32_t threads{2};

  // If non-empty, listen on a Unix Domain Socket instead of TCP.
  std::string unix_socket;

  std::string session_cookie_name{"gh_sid"};
  std::int64_t session_ttl_seconds{3600};

  AuthConfig auth_cfg{};

  // Invitations
  std::string public_base_url{"http://127.0.0.1:18080"};
  std::int64_t invite_ttl_seconds{7 * 24 * 60 * 60};
  std::vector<std::string> admin_uids{"demo"};
  std::string ldap_admin_group;

  // Email backends: "console" (default) | "curl"
  std::string email_backend{"console"};

  // LDAP (preferred over LDIF)
  std::string ldap_url;
  std::string ldap_bind_dn;
  std::string ldap_bind_pw;
  std::string ldap_base_dn{"dc=catuno,dc=lab"};
  bool ldap_starttls{false};

  // LDIF fallback (optional)
  std::string ldif_path;

  // Set Secure flag on session cookies (required for HTTPS deployments).
  // Disable for plain-HTTP deployments.
  bool secure_cookies{false};

  // Guacamole Encrypted JSON Authentication.
  // guacamole_url: base URL of the Guacamole web app (e.g. https://guac.example.com).
  // guacamole_secret: shared secret; first 16 UTF-8 bytes used as AES-128-CBC key.
  // guac_token_ttl_seconds: credential-fetch token lifetime (default: 60 s).
  std::string guacamole_url;
  std::string guacamole_secret;
  std::int64_t guac_token_ttl_seconds{60};

  // URL path prefix for hosting under a sub-path (e.g. "/gatehouse").
  // Must start with '/' or be empty. Must not end with '/'.
  std::string base_uri{""};
};

class HttpServer final {
 public:
  HttpServer(HttpServerConfig cfg, std::shared_ptr<infra::SqliteDb> db);

  [[nodiscard]] core::Result<void> Run();

 private:
  HttpServerConfig cfg_;
  std::shared_ptr<infra::SqliteDb> db_;
};

}  // namespace gatehouse::app
