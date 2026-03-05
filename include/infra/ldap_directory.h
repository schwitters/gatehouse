#pragma once

#include <optional>
#include <string>

#include "core/result.h"

namespace gatehouse::infra {

struct LdapConfig {
  std::string url;        // e.g. "ldaps://ldap.example:636" or "ldap://...:389"
  std::string bind_dn;    // e.g. "cn=admin,dc=catuno,dc=lab"
  std::string bind_pw;    // secret
  std::string base_dn;    // e.g. "dc=catuno,dc=lab"
  bool starttls{false};   // only for ldap:// (ignored for ldaps://)
  int network_timeout_seconds{5};
};

class LdapDirectory final {
 public:
  explicit LdapDirectory(LdapConfig cfg);

  // Lookup mail by tenant OU + uid:
  // base = "ou=people,ou=<tenant_ou>,<base_dn>"
  // filter = "(uid=<uid>)"
  [[nodiscard]] core::Result<std::optional<std::string>> LookupMail(const std::string& tenant_ou,
                                                                    const std::string& uid) const;

 private:
  LdapConfig cfg_;
};

}  // namespace gatehouse::infra
