#include "app/invite_service.h"

#include <cstdlib>
#include <optional>

#include "infra/kadm5_client.h"
#include "infra/krb5_client.h"
#include "infra/provision_store.h"

namespace gatehouse::app {
namespace {
class DirectoryProvisioner final : public core::AccountProvisioner {
 public:
  explicit DirectoryProvisioner(ServerContext& context) : context_(context) {}

  core::Result<void> Prepare(const core::ProvisionRequest& request) override {
    const char* principal = std::getenv("GATEHOUSE_KADM5_ADMIN_PRINC");
    const char* password = std::getenv("GATEHOUSE_KADM5_ADMIN_PASS");
    if (!principal || !*principal || !password || !*password ||
        context_.cfg.auth_cfg.krb5_realm.empty() ||
        !context_.ldap_dir.has_value()) {
      return core::Result<void>::Err(core::Status::Error(
          core::StatusCode::kFailedPrecondition,
          "Provisioning requires Kerberos admin and LDAP configuration"));
    }
    const auto invite = context_.invites.GetById(request.invite_id);
    if (!invite.ok()) return core::Result<void>::Err(invite.status());
    if (!invite.value().has_value())
      return core::Result<void>::Err(core::Status::Error(
          core::StatusCode::kNotFound, "Invitation not found"));
    tenant_ = invite.value()->tenant_id;
    uid_ = invite.value()->invited_uid;
    const auto dn = context_.ldap_dir->GetUserDn(tenant_, uid_);
    if (!dn.ok()) return core::Result<void>::Err(dn.status());
    if (!dn.value().has_value())
      return core::Result<void>::Err(core::Status::Error(
          core::StatusCode::kNotFound, "Directory user not found"));
    dn_ = *dn.value();
    infra::Kadm5Config config;
    config.realm = context_.cfg.auth_cfg.krb5_realm;
    config.admin_principal = principal;
    config.admin_password = password;
    client_.emplace(std::move(config));
    return core::Result<void>::Ok();
  }

  core::Result<void> CreatePrincipal(const std::string& password) override {
    return client_->CreatePrincipal(
        uid_ + "@" + context_.cfg.auth_cfg.krb5_realm, password, dn_);
  }

  core::Result<void> ConfirmPrincipal(const std::string& password) override {
    infra::Krb5Client kerberos({context_.cfg.auth_cfg.krb5_realm});
    auto verified = kerberos.VerifyPasswordAndGetCcache(uid_, password);
    if (!verified.ok()) return core::Result<void>::Err(verified.status());
    return core::Result<void>::Ok();
  }

  core::Result<void> Activate() override {
    return context_.ldap_dir->ActivateUser(tenant_, uid_);
  }

 private:
  ServerContext& context_;
  std::string tenant_;
  std::string uid_;
  std::string dn_;
  std::optional<infra::Kadm5Client> client_;
};
}  // namespace

core::Result<void> CompleteInvitation(ServerContext& context,
                                      const core::ProvisionRequest& request) {
  infra::SqliteProvisionStore store(context.db);
  DirectoryProvisioner directory(context);
  return core::ProvisionAccount(request, store, directory);
}
}  // namespace gatehouse::app
