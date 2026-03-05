#include "infra/ldap_directory.h"

#include <cstdio>
#include <cstring>
#include <optional>
#include <string>
#include <utility>

#include <ldap.h>

namespace gatehouse::infra {
namespace {

core::Status LErr(const char* what, int rc) {
  const char* s = ldap_err2string(rc);
  return core::Status::Error(core::StatusCode::kUnavailable,
                             std::string(what) + " (ldap=" + std::to_string(rc) + "): " +
                                 (s ? s : ""));
}

std::string EscapeFilterValue(const std::string& in) {
  std::string out;
  out.reserve(in.size());
  for (char ch : in) {
    const unsigned char c = static_cast<unsigned char>(ch);
    switch (c) {
      case '\\': out += "\\5c"; break;
      case '*':  out += "\\2a"; break;
      case '(':  out += "\\28"; break;
      case ')':  out += "\\29"; break;
      case '\0': out += "\\00"; break;
      default:   out.push_back(static_cast<char>(c)); break;
    }
  }
  return out;
}

}  // namespace

LdapDirectory::LdapDirectory(LdapConfig cfg) : cfg_(std::move(cfg)) {}

core::Result<std::optional<std::string>> LdapDirectory::LookupMail(
    const std::string& tenant_ou, const std::string& uid) const {
  std::fprintf(stderr, "[gatehouse][ldap] LookupMail begin tenant_ou=%s uid=%s\n",
               tenant_ou.c_str(), uid.c_str());

  if (cfg_.url.empty() || cfg_.bind_dn.empty() || cfg_.base_dn.empty()) {
    return core::Result<std::optional<std::string>>::Err(core::Status::Error(
        core::StatusCode::kFailedPrecondition, "LDAP config incomplete (url/bind_dn/base_dn)"));
  }
  if (tenant_ou.empty() || uid.empty()) {
    return core::Result<std::optional<std::string>>::Err(core::Status::Error(
        core::StatusCode::kInvalidArgument, "tenant_ou/uid empty"));
  }

  LDAP* ld = nullptr;
  int rc = ldap_initialize(&ld, cfg_.url.c_str());
  std::fprintf(stderr, "[gatehouse][ldap] ldap_initialize rc=%d ld=%p\n", rc, (void*)ld);
  if (rc != LDAP_SUCCESS || ld == nullptr) {
    return core::Result<std::optional<std::string>>::Err(LErr("ldap_initialize", rc));
  }

  int version = LDAP_VERSION3;
  (void)ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);

  struct timeval tv;
  tv.tv_sec = cfg_.network_timeout_seconds;
  tv.tv_usec = 0;
  (void)ldap_set_option(ld, LDAP_OPT_NETWORK_TIMEOUT, &tv);

  if (cfg_.starttls) {
    std::fprintf(stderr, "[gatehouse][ldap] ldap_start_tls_s...\n");
    rc = ldap_start_tls_s(ld, nullptr, nullptr);
    std::fprintf(stderr, "[gatehouse][ldap] ldap_start_tls_s rc=%d\n", rc);
    if (rc != LDAP_SUCCESS) {
      ldap_unbind_ext_s(ld, nullptr, nullptr);
      return core::Result<std::optional<std::string>>::Err(LErr("ldap_start_tls_s", rc));
    }
  }

  // One single simple bind using SASL SIMPLE with explicit password.
  std::fprintf(stderr, "[gatehouse][ldap] ldap_sasl_bind_s(simple) dn=%s ...\n",
               cfg_.bind_dn.c_str());
  struct berval cred;
  cred.bv_val = const_cast<char*>(cfg_.bind_pw.c_str());
  cred.bv_len = cfg_.bind_pw.size();

  rc = ldap_sasl_bind_s(ld, cfg_.bind_dn.c_str(), LDAP_SASL_SIMPLE, &cred,
                        nullptr, nullptr, nullptr);
  std::fprintf(stderr, "[gatehouse][ldap] ldap_sasl_bind_s rc=%d\n", rc);
  if (rc != LDAP_SUCCESS) {
    ldap_unbind_ext_s(ld, nullptr, nullptr);
    return core::Result<std::optional<std::string>>::Err(LErr("ldap_sasl_bind_s(simple)", rc));
  }

  const std::string base = "ou=people,ou=" + tenant_ou + "," + cfg_.base_dn;
  const std::string filter = "(uid=" + EscapeFilterValue(uid) + ")";
  std::fprintf(stderr, "[gatehouse][ldap] search base=%s filter=%s\n", base.c_str(), filter.c_str());

  char* attrs[] = {const_cast<char*>("mail"), nullptr};

  LDAPMessage* res = nullptr;
  rc = ldap_search_ext_s(ld, base.c_str(), LDAP_SCOPE_SUBTREE, filter.c_str(), attrs, 0,
                        nullptr, nullptr, &tv, 1, &res);
  std::fprintf(stderr, "[gatehouse][ldap] ldap_search_ext_s rc=%d res=%p\n", rc, (void*)res);

  if (rc != LDAP_SUCCESS) {
    if (res) ldap_msgfree(res);
    ldap_unbind_ext_s(ld, nullptr, nullptr);
    if (rc == LDAP_NO_SUCH_OBJECT) {
      return core::Result<std::optional<std::string>>::Ok(std::nullopt);
    }
    return core::Result<std::optional<std::string>>::Err(LErr("ldap_search_ext_s", rc));
  }

  LDAPMessage* entry = ldap_first_entry(ld, res);
  std::fprintf(stderr, "[gatehouse][ldap] ldap_first_entry entry=%p\n", (void*)entry);
  if (entry == nullptr) {
    ldap_msgfree(res);
    ldap_unbind_ext_s(ld, nullptr, nullptr);
    return core::Result<std::optional<std::string>>::Ok(std::nullopt);
  }

  // No attribute iteration: directly ask for "mail".
  std::fprintf(stderr, "[gatehouse][ldap] ldap_get_values_len(mail)...\n");
  struct berval** vals = ldap_get_values_len(ld, entry, const_cast<char*>("mail"));
  std::fprintf(stderr, "[gatehouse][ldap] ldap_get_values_len vals=%p\n", (void*)vals);

  std::optional<std::string> mail;
  if (vals != nullptr && vals[0] != nullptr && vals[0]->bv_val != nullptr) {
    mail = std::string(vals[0]->bv_val, vals[0]->bv_len);
  }
  if (vals) ldap_value_free_len(vals);

  ldap_msgfree(res);
  ldap_unbind_ext_s(ld, nullptr, nullptr);

  std::fprintf(stderr, "[gatehouse][ldap] LookupMail done mail=%s\n",
               mail.has_value() ? mail->c_str() : "(nullopt)");
  return core::Result<std::optional<std::string>>::Ok(mail);
}

}  // namespace gatehouse::infra
