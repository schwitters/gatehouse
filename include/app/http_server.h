#pragma once

#include <cstdint>
#include <memory>
#include <string>

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
  std::int64_t session_ttl_seconds{3600};  // 1h

  AuthConfig auth_cfg{};
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
