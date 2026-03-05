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
  std::string bind_addr{"0.0.0.0"};
  std::uint16_t port{18080};
  std::uint32_t threads{2};

  std::string session_cookie_name{"gh_sid"};
  std::int64_t session_ttl_seconds{3600};

  AuthConfig auth_cfg{};

  // Invitations
  std::string public_base_url{"http://127.0.0.1:18080"};
  std::int64_t invite_ttl_seconds{7 * 24 * 60 * 60};
  std::vector<std::string> admin_uids{"demo"};

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
