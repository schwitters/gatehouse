#pragma once

#include <optional>
#include <string>
#include <vector>

#include "core/result.h"

namespace gatehouse::app {

enum class AuthMode {
  kKrb5 = 1,
};

struct AuthConfig {
  AuthMode mode{AuthMode::kKrb5};
  std::string krb5_realm;
};

struct LoginRequest {
  std::string username;
  std::string password;
};

struct LoginPrincipal {
  std::string uid;
  std::string tenant_id{"default"};

  // Kerberos (only in kKrb5 mode)
  std::string principal;
  std::int64_t tgt_expires_at{0};
  std::vector<std::uint8_t> ccache_blob;
};

class AuthService final {
 public:
  explicit AuthService(AuthConfig cfg);

  [[nodiscard]] core::Result<std::optional<LoginPrincipal>> Verify(const LoginRequest& req) const;

 private:
  AuthConfig cfg_;
};

}  // namespace gatehouse::app
