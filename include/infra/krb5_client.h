#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "core/result.h"

namespace gatehouse::infra {

struct Krb5Config {
  std::string realm;
};

struct Krb5VerifyResult {
  std::string principal;                 // canonical principal string
  std::int64_t tgt_expires_at{0};         // unix epoch seconds
  std::vector<std::uint8_t> ccache_blob;  // FILE ccache bytes
};

class Krb5Client final {
 public:
  explicit Krb5Client(Krb5Config cfg);

  // Verifies password by acquiring initial creds and serializes ccache to bytes.
  [[nodiscard]] core::Result<Krb5VerifyResult> VerifyPasswordAndGetCcache(
      const std::string& username, const std::string& password) const;

  // Changes the password via kadmin/changepw
  [[nodiscard]] core::Result<void> ChangePassword(const std::string& username, const std::string& old_password, const std::string& new_password) const;

 private:

  [[nodiscard]] std::string MakePrincipal(const std::string& username) const;

  Krb5Config cfg_;
};

}  // namespace gatehouse::infra
