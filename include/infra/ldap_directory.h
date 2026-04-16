#pragma once

#include <optional>
#include <string>
#include <vector>

#include "core/result.h"

namespace gatehouse::infra {

struct LdapConfig {
  // Examples:
  //   ldaps://ldap.example:636
  //   ldap://ldap.example:389
  std::string url;

  // Example:
  //   uid=svc-bind,cn=users,cn=accounts,dc=catuno,dc=lab
  std::string bind_dn;

  // LDAP bind password / secret.
  std::string bind_pw;

  // Example:
  //   dc=catuno,dc=lab
  std::string base_dn;

  // Only used for ldap:// connections.
  // Ignored for ldaps://.
  bool starttls{false};

  int network_timeout_seconds{5};
};

class LdapDirectory final {
 public:
  struct LdapUser {
    std::string uid;
    std::string mail;
    std::string given_name;
    std::string surname;
  };

  struct LdapHost {
    std::string dn;
    std::string hostname;
    std::string ip;
    std::string protocol;  // "rdp" or "ssh", derived from hostname prefix
  };

  struct LdapUserDetail {
    std::string uid;
    std::string mail;
    std::string given_name;
    std::string surname;
    std::vector<LdapHost> hosts;
  };

  explicit LdapDirectory(LdapConfig cfg);

  // Resolve the user's mail attribute below:
  //   cn=users,cn=accounts,ou=<tenant_ou>,<base_dn>
  [[nodiscard]] core::Result<std::optional<std::string>> LookupMail(
      const std::string& tenant_ou, const std::string& uid) const;

  // Check whether a user is a member of the given group DN.
  // Supports memberUid, member and uniqueMember semantics.
  [[nodiscard]] core::Result<bool> IsUserInGroup(
      const std::string& uid, const std::string& group_dn) const;

  // Resolve a user's LDAP DN below:
  //   cn=users,cn=accounts,ou=<tenant_ou>,<base_dn>
  [[nodiscard]] core::Result<std::optional<std::string>> GetUserDn(
      const std::string& tenant_ou, const std::string& uid) const;

  // Resolve the tenant OU by searching the configured base DN for uid=<uid>.
  [[nodiscard]] core::Result<std::optional<std::string>> ResolveTenantByUid(
      const std::string& uid) const;

  // Unlock the user, e.g. by deleting pwdAccountLockedTime.
  [[nodiscard]] core::Result<void> ActivateUser(
      const std::string& tenant_ou, const std::string& uid) const;

  // Check if the user has any Kerberos principal attributes in LDAP.
  // Checks: krbExtraData, krbLastPwdChange, krbLoginFailedCount, krbPrincipalKey, krbPrincipalName.
  [[nodiscard]] core::Result<bool> HasKrbAttributes(
      const std::string& tenant_ou, const std::string& uid) const;

  // Delete Kerberos principal attributes from the user's LDAP entry.
  // Attributes: krbExtraData, krbLastPwdChange, krbLoginFailedCount, krbPrincipalKey, krbPrincipalName.
  // Tolerates missing attributes (LDAP_NO_SUCH_ATTRIBUTE).
  [[nodiscard]] core::Result<void> DeleteKrbAttributes(
      const std::string& tenant_ou, const std::string& uid) const;

  // List tenant OUs directly under base_dn.
  [[nodiscard]] core::Result<std::vector<std::string>> ListTenants() const;

  // List users below:
  //   cn=users,cn=accounts,ou=<tenant_ou>,<base_dn>
  [[nodiscard]] core::Result<std::vector<LdapUser>> ListUsers(
      const std::string& tenant_ou) const;

  // Read managed hosts from the user's labeledURI values and dereference them.
  [[nodiscard]] core::Result<std::vector<LdapHost>> GetUserHosts(
      const std::string& tenant_ou, const std::string& uid) const;

  // Returns all users in the tenant with full details (uid, givenName, sn, mail)
  // and their managed hosts. Uses a single LDAP connection.
  [[nodiscard]] core::Result<std::vector<LdapUserDetail>> ListUsersWithHosts(
      const std::string& tenant_ou) const;

 private:
  LdapConfig cfg_;
};

}  // namespace gatehouse::infra