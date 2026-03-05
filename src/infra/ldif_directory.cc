#include "infra/ldif_directory.h"

#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>

namespace gatehouse::infra {
namespace {

// Extremely small LDIF reader:
// - Splits entries by blank lines
// - Parses "dn: ..." and simple "attr: value" lines
// - Ignores folded lines and base64 values (attr::) for now (not needed for mail)
std::string Trim(const std::string& s) {
  std::size_t a = 0;
  while (a < s.size() && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r')) ++a;
  std::size_t b = s.size();
  while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r')) --b;
  return s.substr(a, b - a);
}

bool StartsWith(const std::string& s, const std::string& p) {
  return s.rfind(p, 0) == 0;
}

// Extract tenant ou from DN like:
// uid=scl,ou=people,ou=k8s-20260118,dc=catuno,dc=lab
std::optional<std::string> TenantOuFromDn(const std::string& dn) {
  const std::string needle = ",ou=people,ou=";
  const std::size_t pos = dn.find(needle);
  if (pos == std::string::npos) return std::nullopt;
  const std::size_t start = pos + needle.size();
  const std::size_t end = dn.find(',', start);
  if (end == std::string::npos) return std::nullopt;
  return dn.substr(start, end - start);
}

std::optional<std::string> UidFromDn(const std::string& dn) {
  const std::string needle = "uid=";
  if (!StartsWith(dn, needle)) return std::nullopt;
  const std::size_t end = dn.find(',');
  if (end == std::string::npos) return std::nullopt;
  return dn.substr(needle.size(), end - needle.size());
}

}  // namespace

std::string LdifDirectory::MakeKey(const std::string& tenant_ou, const std::string& uid) {
  return tenant_ou + "\n" + uid;
}

core::Result<void> LdifDirectory::LoadFile(const std::string& path) {
  std::ifstream in(path);
  if (!in) {
    return core::Result<void>::Err(core::Status::Error(
        core::StatusCode::kNotFound, "LDIF file not found: " + path));
  }

  std::ostringstream ss;
  ss << in.rdbuf();
  const std::string content = ss.str();

  std::size_t pos = 0;
  while (pos < content.size()) {
    // Find end of entry (blank line)
    std::size_t end = content.find("\n\n", pos);
    if (end == std::string::npos) end = content.size();
    const std::string entry = content.substr(pos, end - pos);
    pos = (end == content.size()) ? end : end + 2;

    std::string dn;
    std::string mail;

    std::size_t lp = 0;
    while (lp < entry.size()) {
      std::size_t le = entry.find('\n', lp);
      if (le == std::string::npos) le = entry.size();
      std::string line = entry.substr(lp, le - lp);
      lp = (le == entry.size()) ? le : le + 1;

      line = Trim(line);
      if (line.empty()) continue;

      if (StartsWith(line, "dn:")) {
        dn = Trim(line.substr(3));
        continue;
      }
      // only handle "mail: value" (not "mail:: base64")
      if (StartsWith(line, "mail:")) {
        mail = Trim(line.substr(5));
        continue;
      }
    }

    if (dn.empty() || mail.empty()) continue;

    const auto tenant = TenantOuFromDn(dn);
    const auto uid = UidFromDn(dn);
    if (!tenant.has_value() || !uid.has_value()) continue;

    mail_by_tenant_uid_[MakeKey(*tenant, *uid)] = mail;
  }

  return core::Result<void>::Ok();
}

std::optional<std::string> LdifDirectory::LookupMail(const std::string& tenant_ou,
                                                     const std::string& uid) const {
  const auto it = mail_by_tenant_uid_.find(MakeKey(tenant_ou, uid));
  if (it == mail_by_tenant_uid_.end()) return std::nullopt;
  return it->second;
}

}  // namespace gatehouse::infra
