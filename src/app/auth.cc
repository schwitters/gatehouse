#include "app/auth.h"

#include <optional>
#include <string>
#include <utility>

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

  if (cfg_.mode == AuthMode::kDemo) {
    if (req.username == "demo" && req.password == "demo") {
      LoginPrincipal p;
      p.uid = "demo";
      p.tenant_id = "default";
      return core::Result<std::optional<LoginPrincipal>>::Ok(std::optional<LoginPrincipal>(p));
    }
    return core::Result<std::optional<LoginPrincipal>>::Ok(std::nullopt);
  }

  infra::Krb5Client krb(infra::Krb5Config{.realm = cfg_.krb5_realm});
  auto vr = krb.VerifyPasswordAndGetCcache(req.username, req.password);
  if (!vr.ok()) {
    if (cfg_.allow_demo_fallback && req.username == "demo" && req.password == "demo") {
      LoginPrincipal p;
      p.uid = "demo";
      p.tenant_id = "default";
      return core::Result<std::optional<LoginPrincipal>>::Ok(std::optional<LoginPrincipal>(p));
    }
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
