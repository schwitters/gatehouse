#include "infra/ldap_directory.h"

#include <cstdio>
#include <cstring>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <ldap.h>

namespace gatehouse::infra {
namespace {

core::Status LErr(const char* what, int rc) {
  const char* s = ldap_err2string(rc);
  return core::Status::Error(
      core::StatusCode::kUnavailable,
      std::string(what) + " (ldap=" + std::to_string(rc) + "): " + (s ? s : ""));
}

std::string EscapeFilterValue(const std::string& in) {
  std::string out;
  out.reserve(in.size());
  for (char ch : in) {
    const unsigned char c = static_cast<unsigned char>(ch);
    switch (c) {
      case '\\':
        out += "\\5c";
        break;
      case '*':
        out += "\\2a";
        break;
      case '(':
        out += "\\28";
        break;
      case ')':
        out += "\\29";
        break;
      case '\0':
        out += "\\00";
        break;
      default:
        out.push_back(static_cast<char>(c));
        break;
    }
  }
  return out;
}

class LdapHandle final {
 public:
  LdapHandle() = default;
  explicit LdapHandle(LDAP* ld) : ld_(ld) {}

  LdapHandle(const LdapHandle&) = delete;
  LdapHandle& operator=(const LdapHandle&) = delete;

  LdapHandle(LdapHandle&& other) noexcept : ld_(other.ld_) {
    other.ld_ = nullptr;
  }

  LdapHandle& operator=(LdapHandle&& other) noexcept {
    if (this != &other) {
      Reset();
      ld_ = other.ld_;
      other.ld_ = nullptr;
    }
    return *this;
  }

  ~LdapHandle() { Reset(); }

  LDAP* get() const { return ld_; }
  explicit operator bool() const { return ld_ != nullptr; }

  void Reset(LDAP* ld = nullptr) {
    if (ld_ != nullptr) {
      ldap_unbind_ext_s(ld_, nullptr, nullptr);
    }
    ld_ = ld;
  }

 private:
  LDAP* ld_ = nullptr;
};

class LdapMessageHandle final {
 public:
  LdapMessageHandle() = default;
  explicit LdapMessageHandle(LDAPMessage* msg) : msg_(msg) {}

  LdapMessageHandle(const LdapMessageHandle&) = delete;
  LdapMessageHandle& operator=(const LdapMessageHandle&) = delete;

  LdapMessageHandle(LdapMessageHandle&& other) noexcept : msg_(other.msg_) {
    other.msg_ = nullptr;
  }

  LdapMessageHandle& operator=(LdapMessageHandle&& other) noexcept {
    if (this != &other) {
      Reset();
      msg_ = other.msg_;
      other.msg_ = nullptr;
    }
    return *this;
  }

  ~LdapMessageHandle() { Reset(); }

  LDAPMessage* get() const { return msg_; }
  explicit operator bool() const { return msg_ != nullptr; }

  void Reset(LDAPMessage* msg = nullptr) {
    if (msg_ != nullptr) {
      ldap_msgfree(msg_);
    }
    msg_ = msg;
  }

 private:
  LDAPMessage* msg_ = nullptr;
};

class BervalValuesHandle final {
 public:
  BervalValuesHandle() = default;
  explicit BervalValuesHandle(struct berval** vals) : vals_(vals) {}

  BervalValuesHandle(const BervalValuesHandle&) = delete;
  BervalValuesHandle& operator=(const BervalValuesHandle&) = delete;

  BervalValuesHandle(BervalValuesHandle&& other) noexcept : vals_(other.vals_) {
    other.vals_ = nullptr;
  }

  BervalValuesHandle& operator=(BervalValuesHandle&& other) noexcept {
    if (this != &other) {
      Reset();
      vals_ = other.vals_;
      other.vals_ = nullptr;
    }
    return *this;
  }

  ~BervalValuesHandle() { Reset(); }

  struct berval** get() const { return vals_; }
  struct berval* operator[](int index) const { return vals_[index]; }
  explicit operator bool() const { return vals_ != nullptr; }

  void Reset(struct berval** vals = nullptr) {
    if (vals_ != nullptr) {
      ldap_value_free_len(vals_);
    }
    vals_ = vals;
  }

 private:
  struct berval** vals_ = nullptr;
};

class LdapAllocatedString final {
 public:
  LdapAllocatedString() = default;
  explicit LdapAllocatedString(char* ptr) : ptr_(ptr) {}

  LdapAllocatedString(const LdapAllocatedString&) = delete;
  LdapAllocatedString& operator=(const LdapAllocatedString&) = delete;

  LdapAllocatedString(LdapAllocatedString&& other) noexcept : ptr_(other.ptr_) {
    other.ptr_ = nullptr;
  }

  LdapAllocatedString& operator=(LdapAllocatedString&& other) noexcept {
    if (this != &other) {
      Reset();
      ptr_ = other.ptr_;
      other.ptr_ = nullptr;
    }
    return *this;
  }

  ~LdapAllocatedString() { Reset(); }

  char* get() const { return ptr_; }
  explicit operator bool() const { return ptr_ != nullptr; }

  void Reset(char* ptr = nullptr) {
    if (ptr_ != nullptr) {
      ldap_memfree(ptr_);
    }
    ptr_ = ptr;
  }

 private:
  char* ptr_ = nullptr;
};

bool IsLdapsUrl(const std::string& url) {
  return url.rfind("ldaps://", 0) == 0;
}

bool IsLdapiUrl(const std::string& url) {
  return url.rfind("ldapi://", 0) == 0;
}

std::string BuildUsersBase(const LdapConfig& cfg, const std::string& tenant_ou) {
  return "cn=users,cn=accounts,ou=" + tenant_ou + "," + cfg.base_dn;
}

core::Result<LdapHandle> ConnectAndBind(const LdapConfig& cfg) {
  if (cfg.url.empty() || cfg.bind_dn.empty() || cfg.base_dn.empty()) {
    return core::Result<LdapHandle>::Err(core::Status::Error(
        core::StatusCode::kFailedPrecondition,
        "LDAP config incomplete (url/bind_dn/base_dn)"));
  }

  LDAP* raw = nullptr;
  const int init_rc = ldap_initialize(&raw, cfg.url.c_str());
  if (init_rc != LDAP_SUCCESS || raw == nullptr) {
    return core::Result<LdapHandle>::Err(LErr("ldap_initialize", init_rc));
  }

  LdapHandle ld(raw);

  int version = LDAP_VERSION3;
  int rc = ldap_set_option(ld.get(), LDAP_OPT_PROTOCOL_VERSION, &version);
  if (rc != LDAP_OPT_SUCCESS) {
    return core::Result<LdapHandle>::Err(
        LErr("ldap_set_option(PROTOCOL_VERSION)", rc));
  }

  struct timeval tv;
  tv.tv_sec = cfg.network_timeout_seconds;
  tv.tv_usec = 0;
  rc = ldap_set_option(ld.get(), LDAP_OPT_NETWORK_TIMEOUT, &tv);
  if (rc != LDAP_OPT_SUCCESS) {
    return core::Result<LdapHandle>::Err(
        LErr("ldap_set_option(NETWORK_TIMEOUT)", rc));
  }

  if (cfg.starttls && !IsLdapsUrl(cfg.url)) {
    // MED-06: Require server certificate verification before upgrading to TLS.
    int tls_req = LDAP_OPT_X_TLS_DEMAND;
    (void)ldap_set_option(ld.get(), LDAP_OPT_X_TLS_REQUIRE_CERT, &tls_req);
    rc = ldap_start_tls_s(ld.get(), nullptr, nullptr);
    if (rc != LDAP_SUCCESS) {
      return core::Result<LdapHandle>::Err(LErr("ldap_start_tls_s", rc));
    }
  } else if (!IsLdapsUrl(cfg.url) && !IsLdapiUrl(cfg.url)) {
    std::fprintf(stderr,
                 "[gatehouse][ldap] WARNING: connecting without TLS (%s). "
                 "Credentials will be transmitted in plaintext.\n",
                 cfg.url.c_str());
  }

  struct berval cred;
  cred.bv_val = const_cast<char*>(cfg.bind_pw.c_str());
  cred.bv_len = cfg.bind_pw.size();

  rc = ldap_sasl_bind_s(ld.get(), cfg.bind_dn.c_str(), LDAP_SASL_SIMPLE, &cred,
                        nullptr, nullptr, nullptr);
  if (rc != LDAP_SUCCESS) {
    return core::Result<LdapHandle>::Err(
        LErr("ldap_sasl_bind_s(simple)", rc));
  }

  return core::Result<LdapHandle>::Ok(std::move(ld));
}

std::optional<std::string> GetFirstAttributeValue(LDAP* ld,
                                                  LDAPMessage* entry,
                                                  const char* attr) {
  BervalValuesHandle vals(
      ldap_get_values_len(ld, entry, const_cast<char*>(attr)));
  if (!vals || vals[0] == nullptr || vals[0]->bv_val == nullptr) {
    return std::nullopt;
  }
  return std::string(vals[0]->bv_val, vals[0]->bv_len);
}

std::vector<std::string> GetAllAttributeValues(LDAP* ld,
                                               LDAPMessage* entry,
                                               const char* attr) {
  std::vector<std::string> values;
  BervalValuesHandle vals(
      ldap_get_values_len(ld, entry, const_cast<char*>(attr)));
  if (!vals) {
    return values;
  }

  for (int i = 0; vals[i] != nullptr; ++i) {
    if (vals[i]->bv_val != nullptr) {
      values.emplace_back(vals[i]->bv_val, vals[i]->bv_len);
    }
  }
  return values;
}

std::optional<std::string> GetEntryDn(LDAP* ld, LDAPMessage* entry) {
  LdapAllocatedString dn(ldap_get_dn(ld, entry));
  if (!dn || dn.get() == nullptr || dn.get()[0] == '\0') {
    return std::nullopt;
  }
  return std::string(dn.get());
}

core::Result<std::optional<std::string>> FindUserDnByUid(const LdapConfig& cfg,
                                                         LDAP* ld,
                                                         const std::string& tenant_ou,
                                                         const std::string& uid) {
  const std::string base = BuildUsersBase(cfg, tenant_ou);
  const std::string filter = "(uid=" + EscapeFilterValue(uid) + ")";
  char* attrs[] = {const_cast<char*>("1.1"), nullptr};

  struct timeval tv{cfg.network_timeout_seconds, 0};
  LDAPMessage* raw_res = nullptr;
  int rc = ldap_search_ext_s(ld, base.c_str(), LDAP_SCOPE_SUBTREE,
                             filter.c_str(), attrs, 0,
                             nullptr, nullptr, &tv, 1, &raw_res);
  LdapMessageHandle res(raw_res);

  if (rc == LDAP_NO_SUCH_OBJECT) {
    return core::Result<std::optional<std::string>>::Ok(std::nullopt);
  }
  if (rc != LDAP_SUCCESS && rc != LDAP_SIZELIMIT_EXCEEDED) {
    return core::Result<std::optional<std::string>>::Err(
        LErr("ldap_search_ext_s(find user dn)", rc));
  }

  LDAPMessage* entry = ldap_first_entry(ld, res.get());
  if (entry == nullptr) {
    return core::Result<std::optional<std::string>>::Ok(std::nullopt);
  }

  return core::Result<std::optional<std::string>>::Ok(GetEntryDn(ld, entry));
}

// Derive connection protocol from a host CN of the form "{svc}-{uid}".
// Hostnames starting with "rdp" or "dsk" indicate a Remote Desktop host;
// everything else is reachable via SSH.
std::string ProtocolFromHostname(const std::string& cn) {
  const auto dash = cn.find('-');
  const std::string svc = (dash != std::string::npos) ? cn.substr(0, dash) : cn;
  if (svc == "rdp" || svc == "dsk") return "rdp";
  return "ssh";
}

}  // namespace

LdapDirectory::LdapDirectory(LdapConfig cfg) : cfg_(std::move(cfg)) {}

core::Result<std::optional<std::string>> LdapDirectory::LookupMail(
    const std::string& tenant_ou, const std::string& uid) const {
  std::fprintf(stderr, "[gatehouse][ldap] LookupMail begin tenant_ou=%s uid=%s\n",
               tenant_ou.c_str(), uid.c_str());

  if (tenant_ou.empty() || uid.empty()) {
    return core::Result<std::optional<std::string>>::Err(core::Status::Error(
        core::StatusCode::kInvalidArgument, "tenant_ou/uid empty"));
  }

  auto ld_res = ConnectAndBind(cfg_);
  if (!ld_res.ok()) {
    return core::Result<std::optional<std::string>>::Err(ld_res.status());
  }
  LdapHandle ld = std::move(ld_res.value());

  const std::string base = BuildUsersBase(cfg_, tenant_ou);
  const std::string filter = "(uid=" + EscapeFilterValue(uid) + ")";
  char* attrs[] = {const_cast<char*>("mail"), nullptr};

  struct timeval tv{cfg_.network_timeout_seconds, 0};
  LDAPMessage* raw_res = nullptr;
  int rc = ldap_search_ext_s(ld.get(), base.c_str(), LDAP_SCOPE_SUBTREE,
                             filter.c_str(), attrs, 0,
                             nullptr, nullptr, &tv, 1, &raw_res);
  LdapMessageHandle res(raw_res);

  std::fprintf(stderr, "[gatehouse][ldap] ldap_search_ext_s rc=%d res=%p\n",
               rc, static_cast<void*>(res.get()));

  if (rc == LDAP_NO_SUCH_OBJECT) {
    return core::Result<std::optional<std::string>>::Ok(std::nullopt);
  }
  if (rc != LDAP_SUCCESS && rc != LDAP_SIZELIMIT_EXCEEDED) {
    return core::Result<std::optional<std::string>>::Err(
        LErr("ldap_search_ext_s", rc));
  }

  LDAPMessage* entry = ldap_first_entry(ld.get(), res.get());
  if (entry == nullptr) {
    return core::Result<std::optional<std::string>>::Ok(std::nullopt);
  }

  std::optional<std::string> mail =
      GetFirstAttributeValue(ld.get(), entry, "mail");
  std::fprintf(stderr, "[gatehouse][ldap] LookupMail done mail=%s\n",
               mail.has_value() ? mail->c_str() : "(nullopt)");
  return core::Result<std::optional<std::string>>::Ok(std::move(mail));
}

core::Result<bool> LdapDirectory::IsUserInGroup(const std::string& uid,
                                                const std::string& group_dn) const {
  if (uid.empty() || group_dn.empty()) {
    return core::Result<bool>::Ok(false);
  }

  // Single connection for both lookups.
  auto ld_res = ConnectAndBind(cfg_);
  if (!ld_res.ok()) {
    return core::Result<bool>::Err(ld_res.status());
  }
  LdapHandle ld = std::move(ld_res.value());

  struct timeval tv{cfg_.network_timeout_seconds, 0};

  // Step 1: Resolve the user's full DN by searching globally from base_dn.
  // This works for both tenant users (ou=<tenant>,...) and top-level IPA users
  // who have no ou= component in their DN.
  std::string user_dn;
  {
    const std::string filter = "(uid=" + EscapeFilterValue(uid) + ")";
    char* attrs[] = {const_cast<char*>("1.1"), nullptr};

    LDAPMessage* raw_res = nullptr;
    const int rc = ldap_search_ext_s(ld.get(), cfg_.base_dn.c_str(),
                                     LDAP_SCOPE_SUBTREE, filter.c_str(),
                                     attrs, 0, nullptr, nullptr, &tv, 1,
                                     &raw_res);
    LdapMessageHandle res(raw_res);

    if (rc == LDAP_NO_SUCH_OBJECT) {
      return core::Result<bool>::Ok(false);
    }
    if (rc != LDAP_SUCCESS && rc != LDAP_SIZELIMIT_EXCEEDED) {
      return core::Result<bool>::Err(LErr("ldap_search_ext_s(find user for group check)", rc));
    }

    LDAPMessage* entry = ldap_first_entry(ld.get(), res.get());
    if (entry != nullptr) {
      std::optional<std::string> dn = GetEntryDn(ld.get(), entry);
      if (dn.has_value() && !dn->empty()) user_dn = std::move(*dn);
    }
    // user_dn may remain empty if the principal has no LDAP posixAccount entry
    // (e.g. Kerberos-only principals).  The group-check below handles both cases:
    // exact DN match when user_dn is set, uid-RDN fallback otherwise.
  }

  // Step 2: Fetch the group entry and check membership.
  {
    char* attrs[] = {
        const_cast<char*>("memberUid"),
        const_cast<char*>("member"),
        const_cast<char*>("uniqueMember"),
        nullptr};

    LDAPMessage* raw_res = nullptr;
    const int rc = ldap_search_ext_s(ld.get(), group_dn.c_str(),
                                     LDAP_SCOPE_BASE, "(objectClass=*)",
                                     attrs, 0, nullptr, nullptr, &tv, 0,
                                     &raw_res);
    LdapMessageHandle res(raw_res);

    if (rc == LDAP_NO_SUCH_OBJECT) {
      return core::Result<bool>::Ok(false);
    }
    if (rc != LDAP_SUCCESS && rc != LDAP_SIZELIMIT_EXCEEDED) {
      return core::Result<bool>::Err(LErr("ldap_search_ext_s(group)", rc));
    }

    LDAPMessage* entry = ldap_first_entry(ld.get(), res.get());
    if (entry == nullptr) {
      return core::Result<bool>::Ok(false);
    }

    // memberUid stores plain uid strings (posixGroup style).
    {
      BervalValuesHandle vals(
          ldap_get_values_len(ld.get(), entry, const_cast<char*>("memberUid")));
      if (vals) {
        for (int i = 0; vals[i] != nullptr; ++i) {
          std::string val(vals[i]->bv_val, vals[i]->bv_len);
          if (val == uid) {
            return core::Result<bool>::Ok(true);
          }
        }
      }
    }

    // member and uniqueMember store full DNs.
    // Primary check: exact DN match (user_dn found via LDAP lookup).
    // Fallback: uid= RDN prefix match — handles Kerberos-only principals that
    // are referenced by a full DN in the group but have no posixAccount entry.
    const std::string uid_rdn_prefix = "uid=" + uid + ",";
    for (const char* attr : {"member", "uniqueMember"}) {
      BervalValuesHandle vals(
          ldap_get_values_len(ld.get(), entry, const_cast<char*>(attr)));
      if (vals) {
        for (int i = 0; vals[i] != nullptr; ++i) {
          std::string val(vals[i]->bv_val, vals[i]->bv_len);
          if ((!user_dn.empty() && val == user_dn) ||
              (user_dn.empty() && val.size() > uid_rdn_prefix.size() &&
               val.substr(0, uid_rdn_prefix.size()) == uid_rdn_prefix)) {
            return core::Result<bool>::Ok(true);
          }
        }
      }
    }
  }

  return core::Result<bool>::Ok(false);
}

core::Result<void> LdapDirectory::ActivateUser(const std::string& tenant_ou,
                                               const std::string& uid) const {
  std::fprintf(stderr, "[gatehouse][ldap] ActivateUser begin tenant_ou=%s uid=%s\n",
               tenant_ou.c_str(), uid.c_str());

  if (tenant_ou.empty() || uid.empty()) {
    return core::Result<void>::Err(core::Status::Error(
        core::StatusCode::kInvalidArgument, "tenant_ou/uid empty"));
  }

  auto ld_res = ConnectAndBind(cfg_);
  if (!ld_res.ok()) {
    return core::Result<void>::Err(ld_res.status());
  }
  LdapHandle ld = std::move(ld_res.value());

  auto user_dn_res = FindUserDnByUid(cfg_, ld.get(), tenant_ou, uid);
  if (!user_dn_res.ok()) {
    return core::Result<void>::Err(user_dn_res.status());
  }
  std::optional<std::string> user_dn = std::move(user_dn_res.value());
  if (!user_dn.has_value() || user_dn->empty()) {
    return core::Result<void>::Err(core::Status::Error(
        core::StatusCode::kNotFound, "User not found for activation"));
  }

  std::fprintf(stderr, "[gatehouse][ldap] Unlocking DN: %s\n", user_dn->c_str());

  LDAPMod mod;
  std::memset(&mod, 0, sizeof(mod));
  mod.mod_op = LDAP_MOD_DELETE;
  mod.mod_type = const_cast<char*>("pwdAccountLockedTime");
  mod.mod_values = nullptr;

  LDAPMod* mods[] = {&mod, nullptr};

  const int rc = ldap_modify_ext_s(ld.get(), user_dn->c_str(), mods, nullptr, nullptr);
  if (rc != LDAP_SUCCESS && rc != LDAP_NO_SUCH_ATTRIBUTE) {
    return core::Result<void>::Err(LErr("ldap_modify_ext_s", rc));
  }

  std::fprintf(stderr, "[gatehouse][ldap] ActivateUser success\n");
  return core::Result<void>::Ok();
}

core::Result<bool> LdapDirectory::HasKrbAttributes(
    const std::string& tenant_ou, const std::string& uid) const {
  if (tenant_ou.empty() || uid.empty()) {
    return core::Result<bool>::Ok(false);
  }

  auto ld_res = ConnectAndBind(cfg_);
  if (!ld_res.ok()) return core::Result<bool>::Err(ld_res.status());
  LdapHandle ld = std::move(ld_res.value());

  auto user_dn_res = FindUserDnByUid(cfg_, ld.get(), tenant_ou, uid);
  if (!user_dn_res.ok()) return core::Result<bool>::Err(user_dn_res.status());
  if (!user_dn_res.value().has_value()) return core::Result<bool>::Ok(false);
  const std::string user_dn = *user_dn_res.value();

  char* attrs[] = {
      const_cast<char*>("krbExtraData"),
      const_cast<char*>("krbLastPwdChange"),
      const_cast<char*>("krbLoginFailedCount"),
      const_cast<char*>("krbPrincipalKey"),
      const_cast<char*>("krbPrincipalName"),
      nullptr};

  struct timeval tv{cfg_.network_timeout_seconds, 0};
  LDAPMessage* raw_res = nullptr;
  const int rc = ldap_search_ext_s(ld.get(), user_dn.c_str(), LDAP_SCOPE_BASE,
                                   "(objectClass=*)", attrs, 0,
                                   nullptr, nullptr, &tv, 1, &raw_res);
  LdapMessageHandle res(raw_res);

  if (rc != LDAP_SUCCESS && rc != LDAP_SIZELIMIT_EXCEEDED) {
    return core::Result<bool>::Err(LErr("ldap_search_ext_s(has-krb-attrs)", rc));
  }

  LDAPMessage* entry = ldap_first_entry(ld.get(), res.get());
  if (entry == nullptr) return core::Result<bool>::Ok(false);

  for (const char* attr : {"krbExtraData", "krbLastPwdChange", "krbLoginFailedCount",
                            "krbPrincipalKey", "krbPrincipalName"}) {
    BervalValuesHandle vals(
        ldap_get_values_len(ld.get(), entry, const_cast<char*>(attr)));
    if (vals && vals[0] != nullptr) return core::Result<bool>::Ok(true);
  }

  return core::Result<bool>::Ok(false);
}

core::Result<void> LdapDirectory::DeleteKrbAttributes(
    const std::string& tenant_ou, const std::string& uid) const {
  std::fprintf(stderr, "[gatehouse][ldap] DeleteKrbAttributes begin tenant_ou=%s uid=%s\n",
               tenant_ou.c_str(), uid.c_str());

  if (tenant_ou.empty() || uid.empty()) {
    return core::Result<void>::Err(core::Status::Error(
        core::StatusCode::kInvalidArgument, "tenant_ou/uid empty"));
  }

  auto ld_res = ConnectAndBind(cfg_);
  if (!ld_res.ok()) return core::Result<void>::Err(ld_res.status());
  LdapHandle ld = std::move(ld_res.value());

  auto user_dn_res = FindUserDnByUid(cfg_, ld.get(), tenant_ou, uid);
  if (!user_dn_res.ok()) return core::Result<void>::Err(user_dn_res.status());
  if (!user_dn_res.value().has_value() || user_dn_res.value()->empty()) {
    return core::Result<void>::Err(core::Status::Error(
        core::StatusCode::kNotFound, "User not found for Kerberos attribute deletion"));
  }
  const std::string user_dn = *user_dn_res.value();

  std::fprintf(stderr, "[gatehouse][ldap] DeleteKrbAttributes DN: %s\n", user_dn.c_str());

  const char* krb_attrs[] = {
      "krbExtraData", "krbLastPwdChange", "krbLoginFailedCount",
      "krbPrincipalKey", "krbPrincipalName"};

  for (const char* attr : krb_attrs) {
    LDAPMod mod;
    std::memset(&mod, 0, sizeof(mod));
    mod.mod_op = LDAP_MOD_DELETE;
    mod.mod_type = const_cast<char*>(attr);
    mod.mod_values = nullptr;
    LDAPMod* mods[] = {&mod, nullptr};

    const int rc = ldap_modify_ext_s(ld.get(), user_dn.c_str(), mods, nullptr, nullptr);
    if (rc != LDAP_SUCCESS && rc != LDAP_NO_SUCH_ATTRIBUTE) {
      std::fprintf(stderr, "[gatehouse][ldap] DeleteKrbAttributes: delete %s returned %d (%s)\n",
                   attr, rc, ldap_err2string(rc));
    }
  }

  std::fprintf(stderr, "[gatehouse][ldap] DeleteKrbAttributes done\n");
  return core::Result<void>::Ok();
}

core::Result<std::vector<LdapDirectory::LdapUser>> LdapDirectory::ListUsers(
    const std::string& tenant_ou) const {
  if (tenant_ou.empty()) {
    return core::Result<std::vector<LdapUser>>::Err(core::Status::Error(
        core::StatusCode::kInvalidArgument, "tenant_ou empty"));
  }

  auto ld_res = ConnectAndBind(cfg_);
  if (!ld_res.ok()) {
    return core::Result<std::vector<LdapUser>>::Err(ld_res.status());
  }
  LdapHandle ld = std::move(ld_res.value());

  const std::string base = BuildUsersBase(cfg_, tenant_ou);
  const std::string filter = "(&(uid=*)(mail=*))";
  char* attrs[] = {
      const_cast<char*>("uid"),
      const_cast<char*>("mail"),
      const_cast<char*>("givenName"),
      const_cast<char*>("sn"),
      nullptr};

  struct timeval tv{cfg_.network_timeout_seconds, 0};
  LDAPMessage* raw_res = nullptr;
  int rc = ldap_search_ext_s(ld.get(), base.c_str(), LDAP_SCOPE_SUBTREE,
                             filter.c_str(), attrs, 0,
                             nullptr, nullptr, &tv, 0, &raw_res);
  LdapMessageHandle res(raw_res);

  if (rc == LDAP_NO_SUCH_OBJECT) {
    return core::Result<std::vector<LdapUser>>::Ok({});
  }
  if (rc != LDAP_SUCCESS && rc != LDAP_SIZELIMIT_EXCEEDED) {
    return core::Result<std::vector<LdapUser>>::Err(
        LErr("ldap_search_ext_s", rc));
  }

  std::vector<LdapUser> users;
  for (LDAPMessage* entry = ldap_first_entry(ld.get(), res.get());
       entry != nullptr;
       entry = ldap_next_entry(ld.get(), entry)) {
    LdapUser user;

    std::optional<std::string> uid_val =
        GetFirstAttributeValue(ld.get(), entry, "uid");
    if (uid_val.has_value()) {
      user.uid = std::move(*uid_val);
    }

    std::optional<std::string> mail_val =
        GetFirstAttributeValue(ld.get(), entry, "mail");
    if (mail_val.has_value()) {
      user.mail = std::move(*mail_val);
    }

    std::optional<std::string> gn = GetFirstAttributeValue(ld.get(), entry, "givenName");
    if (gn.has_value()) user.given_name = std::move(*gn);

    std::optional<std::string> sn = GetFirstAttributeValue(ld.get(), entry, "sn");
    if (sn.has_value()) user.surname = std::move(*sn);

    if (!user.uid.empty() && !user.mail.empty()) {
      users.push_back(std::move(user));
    }
  }

  return core::Result<std::vector<LdapUser>>::Ok(std::move(users));
}

core::Result<std::vector<LdapDirectory::LdapHost>> LdapDirectory::GetUserHosts(
    const std::string& tenant_ou, const std::string& uid) const {
  if (tenant_ou.empty() || uid.empty()) {
    return core::Result<std::vector<LdapHost>>::Err(core::Status::Error(
        core::StatusCode::kInvalidArgument, "tenant_ou/uid empty"));
  }

  auto ld_res = ConnectAndBind(cfg_);
  if (!ld_res.ok()) {
    return core::Result<std::vector<LdapHost>>::Err(ld_res.status());
  }
  LdapHandle ld = std::move(ld_res.value());

  const std::string user_base = "ou=" + tenant_ou + "," + cfg_.base_dn;
  const std::string filter = "(uid=" + EscapeFilterValue(uid) + ")";
  char* user_attrs[] = {const_cast<char*>("labeledURI"), nullptr};

  struct timeval tv{cfg_.network_timeout_seconds, 0};
  LDAPMessage* raw_user_res = nullptr;
  int rc = ldap_search_ext_s(ld.get(), user_base.c_str(), LDAP_SCOPE_SUBTREE,
                             filter.c_str(), user_attrs, 0,
                             nullptr, nullptr, &tv, 1, &raw_user_res);
  LdapMessageHandle user_res(raw_user_res);

  if (rc == LDAP_NO_SUCH_OBJECT) {
    return core::Result<std::vector<LdapHost>>::Ok({});
  }
  if (rc != LDAP_SUCCESS && rc != LDAP_SIZELIMIT_EXCEEDED) {
    return core::Result<std::vector<LdapHost>>::Err(
        LErr("ldap_search_ext_s (user)", rc));
  }

  LDAPMessage* user_entry = ldap_first_entry(ld.get(), user_res.get());
  if (user_entry == nullptr) {
    return core::Result<std::vector<LdapHost>>::Ok({});
  }

  std::vector<std::string> host_dns;
  {
    std::vector<std::string> uris =
        GetAllAttributeValues(ld.get(), user_entry, "labeledURI");
    for (const auto& uri : uris) {
      const std::string prefix = "managed-host:";
      if (uri.rfind(prefix, 0) == 0) {
        host_dns.push_back(uri.substr(prefix.size()));
      }
    }
  }

  std::vector<LdapHost> hosts;
  char* host_attrs[] = {
      const_cast<char*>("cn"),
      const_cast<char*>("ipHostNumber"),
      const_cast<char*>("aRecord"),
      nullptr};

  for (const auto& host_dn : host_dns) {
    LDAPMessage* raw_host_res = nullptr;
    rc = ldap_search_ext_s(ld.get(), host_dn.c_str(), LDAP_SCOPE_BASE,
                           "(objectClass=*)", host_attrs, 0,
                           nullptr, nullptr, &tv, 1, &raw_host_res);
    LdapMessageHandle host_res(raw_host_res);

    if (rc != LDAP_SUCCESS && rc != LDAP_SIZELIMIT_EXCEEDED) {
      continue;
    }

    LDAPMessage* host_entry = ldap_first_entry(ld.get(), host_res.get());
    if (host_entry == nullptr) {
      continue;
    }

    LdapHost host;
    host.dn = host_dn;

    std::optional<std::string> cn_val =
        GetFirstAttributeValue(ld.get(), host_entry, "cn");
    if (cn_val.has_value()) {
      host.hostname = *cn_val;
      host.protocol = ProtocolFromHostname(*cn_val);
    }

    std::optional<std::string> ip_val =
        GetFirstAttributeValue(ld.get(), host_entry, "ipHostNumber");
    if (!ip_val.has_value()) {
      ip_val = GetFirstAttributeValue(ld.get(), host_entry, "aRecord");
    }
    if (ip_val.has_value()) {
      host.ip = std::move(*ip_val);
    }

    hosts.push_back(std::move(host));
  }

  return core::Result<std::vector<LdapHost>>::Ok(std::move(hosts));
}

core::Result<std::optional<std::string>> LdapDirectory::GetUserDn(
    const std::string& tenant_ou, const std::string& uid) const {
  if (tenant_ou.empty() || uid.empty()) {
    return core::Result<std::optional<std::string>>::Err(core::Status::Error(
        core::StatusCode::kInvalidArgument, "tenant_ou/uid empty"));
  }

  auto ld_res = ConnectAndBind(cfg_);
  if (!ld_res.ok()) {
    return core::Result<std::optional<std::string>>::Err(ld_res.status());
  }
  LdapHandle ld = std::move(ld_res.value());

  return FindUserDnByUid(cfg_, ld.get(), tenant_ou, uid);
}

core::Result<std::optional<std::string>> LdapDirectory::ResolveTenantByUid(
    const std::string& uid) const {
  if (uid.empty()) {
    return core::Result<std::optional<std::string>>::Err(core::Status::Error(
        core::StatusCode::kInvalidArgument, "uid empty"));
  }

  auto ld_res = ConnectAndBind(cfg_);
  if (!ld_res.ok()) {
    return core::Result<std::optional<std::string>>::Err(ld_res.status());
  }
  LdapHandle ld = std::move(ld_res.value());

  const std::string filter = "(uid=" + EscapeFilterValue(uid) + ")";
  char* attrs[] = {const_cast<char*>("1.1"), nullptr};

  struct timeval tv{cfg_.network_timeout_seconds, 0};
  LDAPMessage* raw_res = nullptr;
  const int rc = ldap_search_ext_s(ld.get(), cfg_.base_dn.c_str(), LDAP_SCOPE_SUBTREE,
                                   filter.c_str(), attrs, 0,
                                   nullptr, nullptr, &tv, 1, &raw_res);
  LdapMessageHandle res(raw_res);

  if (rc == LDAP_NO_SUCH_OBJECT) {
    return core::Result<std::optional<std::string>>::Ok(std::nullopt);
  }
  if (rc != LDAP_SUCCESS && rc != LDAP_SIZELIMIT_EXCEEDED) {
    return core::Result<std::optional<std::string>>::Err(
        LErr("ldap_search_ext_s (resolve tenant)", rc));
  }

  LDAPMessage* entry = ldap_first_entry(ld.get(), res.get());
  if (entry == nullptr) {
    return core::Result<std::optional<std::string>>::Ok(std::nullopt);
  }

  std::optional<std::string> dn = GetEntryDn(ld.get(), entry);
  if (!dn.has_value()) {
    return core::Result<std::optional<std::string>>::Ok(std::nullopt);
  }

  const std::string needle = ",ou=";
  std::size_t pos = dn->find(needle);
  if (pos == std::string::npos) {
    return core::Result<std::optional<std::string>>::Ok(std::nullopt);
  }

  pos += needle.size();
  std::size_t end = dn->find(',', pos);
  if (end == std::string::npos) {
    end = dn->size();
  }

  return core::Result<std::optional<std::string>>::Ok(
      dn->substr(pos, end - pos));
}


core::Result<std::vector<std::string>> LdapDirectory::ListTenants() const {
  auto ld_res = ConnectAndBind(cfg_);
  if (!ld_res.ok()) {
    return core::Result<std::vector<std::string>>::Err(ld_res.status());
  }
  LdapHandle ld = std::move(ld_res.value());

  char* attrs[] = {const_cast<char*>("ou"), nullptr};
  struct timeval tv{cfg_.network_timeout_seconds, 0};
  LDAPMessage* raw_res = nullptr;
  const int rc = ldap_search_ext_s(ld.get(), cfg_.base_dn.c_str(), LDAP_SCOPE_ONELEVEL,
                                   "(objectClass=organizationalUnit)", attrs, 0,
                                   nullptr, nullptr, &tv, 0, &raw_res);
  LdapMessageHandle res(raw_res);

  if (rc == LDAP_NO_SUCH_OBJECT) {
    return core::Result<std::vector<std::string>>::Ok({});
  }
  if (rc != LDAP_SUCCESS && rc != LDAP_SIZELIMIT_EXCEEDED) {
    return core::Result<std::vector<std::string>>::Err(LErr("ldap_search_ext_s(tenants)", rc));
  }

  std::vector<std::string> tenants;
  for (LDAPMessage* entry = ldap_first_entry(ld.get(), res.get());
       entry != nullptr;
       entry = ldap_next_entry(ld.get(), entry)) {
    std::optional<std::string> ou = GetFirstAttributeValue(ld.get(), entry, "ou");
    if (ou.has_value() && !ou->empty()) {
      tenants.push_back(std::move(*ou));
    }
  }
  return core::Result<std::vector<std::string>>::Ok(std::move(tenants));
}

core::Result<std::vector<LdapDirectory::LdapUserDetail>> LdapDirectory::ListUsersWithHosts(
    const std::string& tenant_ou) const {
  if (tenant_ou.empty()) {
    return core::Result<std::vector<LdapUserDetail>>::Err(core::Status::Error(
        core::StatusCode::kInvalidArgument, "tenant_ou empty"));
  }

  auto ld_res = ConnectAndBind(cfg_);
  if (!ld_res.ok()) {
    return core::Result<std::vector<LdapUserDetail>>::Err(ld_res.status());
  }
  LdapHandle ld = std::move(ld_res.value());

  struct timeval tv{cfg_.network_timeout_seconds, 0};

  // Step 1: fetch all users in the tenant with extended attributes.
  const std::string user_base = BuildUsersBase(cfg_, tenant_ou);
  char* user_attrs[] = {
      const_cast<char*>("uid"),
      const_cast<char*>("mail"),
      const_cast<char*>("givenName"),
      const_cast<char*>("sn"),
      const_cast<char*>("labeledURI"),
      nullptr};

  LDAPMessage* raw_user_res = nullptr;
  int rc = ldap_search_ext_s(ld.get(), user_base.c_str(), LDAP_SCOPE_SUBTREE,
                             "(&(uid=*)(mail=*))", user_attrs, 0,
                             nullptr, nullptr, &tv, 0, &raw_user_res);
  LdapMessageHandle user_res(raw_user_res);

  if (rc == LDAP_NO_SUCH_OBJECT) {
    return core::Result<std::vector<LdapUserDetail>>::Ok({});
  }
  if (rc != LDAP_SUCCESS && rc != LDAP_SIZELIMIT_EXCEEDED) {
    return core::Result<std::vector<LdapUserDetail>>::Err(
        LErr("ldap_search_ext_s(users with hosts)", rc));
  }

  // Step 2: build user list and collect all unique host DNs.
  std::vector<LdapUserDetail> users;
  // Per user: which host DNs does it reference?
  std::vector<std::vector<std::string>> user_host_dns;

  for (LDAPMessage* entry = ldap_first_entry(ld.get(), user_res.get());
       entry != nullptr;
       entry = ldap_next_entry(ld.get(), entry)) {
    LdapUserDetail u;

    std::optional<std::string> uid_v = GetFirstAttributeValue(ld.get(), entry, "uid");
    if (!uid_v.has_value() || uid_v->empty()) continue;
    u.uid = std::move(*uid_v);

    std::optional<std::string> mail_v = GetFirstAttributeValue(ld.get(), entry, "mail");
    if (mail_v.has_value()) u.mail = std::move(*mail_v);

    std::optional<std::string> gn = GetFirstAttributeValue(ld.get(), entry, "givenName");
    if (gn.has_value()) u.given_name = std::move(*gn);

    std::optional<std::string> sn = GetFirstAttributeValue(ld.get(), entry, "sn");
    if (sn.has_value()) u.surname = std::move(*sn);

    // Collect managed-host: URIs.
    std::vector<std::string> host_dns;
    std::vector<std::string> uris = GetAllAttributeValues(ld.get(), entry, "labeledURI");
    const std::string prefix = "managed-host:";
    for (const auto& uri : uris) {
      if (uri.rfind(prefix, 0) == 0) {
        host_dns.push_back(uri.substr(prefix.size()));
      }
    }

    users.push_back(std::move(u));
    user_host_dns.push_back(std::move(host_dns));
  }

  // Step 3: resolve host DNs in the same connection.
  char* host_attrs[] = {
      const_cast<char*>("cn"),
      const_cast<char*>("ipHostNumber"),
      const_cast<char*>("aRecord"),
      nullptr};

  for (std::size_t i = 0; i < users.size(); ++i) {
    for (const auto& host_dn : user_host_dns[i]) {
      LDAPMessage* raw_host = nullptr;
      rc = ldap_search_ext_s(ld.get(), host_dn.c_str(), LDAP_SCOPE_BASE,
                             "(objectClass=*)", host_attrs, 0,
                             nullptr, nullptr, &tv, 1, &raw_host);
      LdapMessageHandle host_res(raw_host);

      if (rc != LDAP_SUCCESS && rc != LDAP_SIZELIMIT_EXCEEDED) continue;

      LDAPMessage* host_entry = ldap_first_entry(ld.get(), host_res.get());
      if (host_entry == nullptr) continue;

      LdapHost host;
      host.dn = host_dn;

      std::optional<std::string> cn = GetFirstAttributeValue(ld.get(), host_entry, "cn");
      if (cn.has_value()) {
        host.hostname = *cn;
        host.protocol = ProtocolFromHostname(*cn);
      }

      std::optional<std::string> ip = GetFirstAttributeValue(ld.get(), host_entry, "ipHostNumber");
      if (!ip.has_value()) ip = GetFirstAttributeValue(ld.get(), host_entry, "aRecord");
      if (ip.has_value()) host.ip = std::move(*ip);

      users[i].hosts.push_back(std::move(host));
    }
  }

  return core::Result<std::vector<LdapUserDetail>>::Ok(std::move(users));
}

}  // namespace gatehouse::infra
