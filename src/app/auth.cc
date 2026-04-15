#include "app/auth.h"

#include <cstdio>
#include <optional>
#include <string>
#include <utility>

#include "app/http_utils.h"
#include "infra/krb5_client.h"

namespace gatehouse::app {
namespace {

std::string CanonicalUidFromUsername(const std::string& username) {
  const std::size_t at = username.find('@');
  if (at == std::string::npos) return username;
  return username.substr(0, at);
}

}  // namespace

AuthService::AuthService(AuthConfig cfg) : cfg_(std::move(cfg)) {}

core::Result<std::optional<LoginPrincipal>> AuthService::Verify(const LoginRequest& req) const {
  if (req.username.empty() || req.password.empty()) {
    return core::Result<std::optional<LoginPrincipal>>::Err(
        core::Status::Error(core::StatusCode::kInvalidArgument, "missing credentials"));
  }

  infra::Krb5Client krb(infra::Krb5Config{.realm = cfg_.krb5_realm});
  auto vr = krb.VerifyPasswordAndGetCcache(req.username, req.password);
  if (!vr.ok()) {
    std::fprintf(stderr, "[gatehouse][auth] krb5 error user='%s': %s\n",
                 SanitizeForLog(req.username).c_str(),
                 vr.status().ToString().c_str());
    return core::Result<std::optional<LoginPrincipal>>::Ok(std::nullopt);
  }

  LoginPrincipal p;
  p.uid = CanonicalUidFromUsername(req.username);
  p.tenant_id = "default";
  p.principal = vr.value().principal;
  p.tgt_expires_at = vr.value().tgt_expires_at;
  p.ccache_blob = std::move(vr.value().ccache_blob);

  return core::Result<std::optional<LoginPrincipal>>::Ok(std::optional<LoginPrincipal>(std::move(p)));
}

}  // namespace gatehouse::app
