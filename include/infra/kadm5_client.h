#pragma once

#include <string>
#include "core/result.h"

namespace gatehouse::infra {

struct Kadm5Config {
  std::string realm;
  std::string admin_principal;
  std::string admin_password;
  std::string admin_server; // optional
};

class Kadm5Client final {
 public:
  explicit Kadm5Client(Kadm5Config cfg);

  [[nodiscard]] core::Result<void> CreatePrincipal(
      const std::string& new_principal,
      const std::string& new_password,
      const std::string& ldap_dn) const;

 private:
  Kadm5Config cfg_;
};

}  // namespace gatehouse::infra
