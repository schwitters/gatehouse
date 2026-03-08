#include "infra/kadm5_client.h"

#include <kadm5/admin.h>
#include <kdb.h>
#include <krb5.h>

#include <cstring>
#include <string>
#include <vector>

#include "krb5_helpers.h"

namespace gatehouse::infra {
namespace {

class ScopedKadm5Handle {
 public:
  ScopedKadm5Handle() = default;

  ~ScopedKadm5Handle() {
    if (handle_ != nullptr) {
      (void)kadm5_destroy(handle_);
    }
  }

  ScopedKadm5Handle(const ScopedKadm5Handle&) = delete;
  ScopedKadm5Handle& operator=(const ScopedKadm5Handle&) = delete;

  ScopedKadm5Handle(ScopedKadm5Handle&&) = delete;
  ScopedKadm5Handle& operator=(ScopedKadm5Handle&&) = delete;

  void** out() noexcept { return &handle_; }
  void* get() const noexcept { return handle_; }

 private:
  void* handle_ = nullptr;
};

}  // namespace

Kadm5Client::Kadm5Client(Kadm5Config cfg) : cfg_(std::move(cfg)) {}

core::Result<void> Kadm5Client::CreatePrincipal(
    const std::string& new_principal,
    const std::string& new_password,
    const std::string& ldap_dn) const {
  if (cfg_.realm.empty()) {
    return core::Result<void>::Err(
        core::Status::Error(
            core::StatusCode::kFailedPrecondition,
            "Kadm5 config incomplete: 'realm' is empty "
            "(did you pass --realm <REALM>?)"));
  }
  if (cfg_.admin_principal.empty()) {
    return core::Result<void>::Err(
        core::Status::Error(
            core::StatusCode::kFailedPrecondition,
            "Kadm5 config incomplete: 'admin_principal' is empty "
            "(GATEHOUSE_KADM5_ADMIN_PRINC missing)"));
  }
  if (cfg_.admin_password.empty()) {
    return core::Result<void>::Err(
        core::Status::Error(
            core::StatusCode::kFailedPrecondition,
            "Kadm5 config incomplete: 'admin_password' is empty "
            "(GATEHOUSE_KADM5_ADMIN_PASS missing)"));
  }

  auto ctx_result = MakeKrb5Context();
  if (!ctx_result.ok()) {
    return core::Result<void>::Err(ctx_result.status());
  }
  auto ctx = std::move(ctx_result.value());

  kadm5_config_params params;
  std::memset(&params, 0, sizeof(params));
  params.mask = KADM5_CONFIG_REALM;
  params.realm = const_cast<char*>(cfg_.realm.c_str());

  if (!cfg_.admin_server.empty()) {
    params.mask |= KADM5_CONFIG_ADMIN_SERVER;
    params.admin_server = const_cast<char*>(cfg_.admin_server.c_str());
  }

  ScopedKadm5Handle handle;
  char* db_args[] = {nullptr};

  const kadm5_ret_t init_ret = kadm5_init_with_password(
      ctx.get(),
      const_cast<char*>(cfg_.admin_principal.c_str()),
      const_cast<char*>(cfg_.admin_password.c_str()),
      const_cast<char*>("kadmin/admin"),
      &params,
      KADM5_STRUCT_VERSION,
      KADM5_API_VERSION_4,
      db_args,
      handle.out());
  if (init_ret != 0) {
    return core::Result<void>::Err(
        Kadm5ErrorStatus("kadm5_init_with_password", ctx.get(),init_ret));
  }

  auto principal_result = ParseKrb5Principal(ctx.get(), new_principal);
  if (!principal_result.ok()) {
    return core::Result<void>::Err(principal_result.status());
  }
  auto principal = std::move(principal_result.value());

  kadm5_principal_ent_rec ent;
  std::memset(&ent, 0, sizeof(ent));
  ent.principal = principal.get();

  long mask = KADM5_PRINCIPAL;

  krb5_tl_data tl;
  std::memset(&tl, 0, sizeof(tl));
  std::vector<unsigned char> tl_contents;

  if (!ldap_dn.empty()) {
    const std::string dbarg = "dn=" + ldap_dn;
    tl_contents.assign(dbarg.begin(), dbarg.end());
    tl_contents.push_back('\0');

    tl.tl_data_type = KRB5_TL_DB_ARGS;
    tl.tl_data_length = static_cast<short unsigned int> (tl_contents.size());
    tl.tl_data_contents = reinterpret_cast<krb5_octet*>(tl_contents.data());
    tl.tl_data_next = nullptr;

    ent.tl_data = &tl;
    ent.n_tl_data = 1;
    mask |= KADM5_TL_DATA;
  }

  const kadm5_ret_t create_ret = kadm5_create_principal(
      handle.get(),
      &ent,
      mask,
      const_cast<char*>(new_password.c_str()));

  if (create_ret != 0) {
    return core::Result<void>::Err(
        Kadm5ErrorStatus("kadm5_create_principal",ctx.get(), create_ret));
  }

  return core::Result<void>::Ok();
}

}  // namespace gatehouse::infra