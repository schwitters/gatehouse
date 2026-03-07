#include "infra/kadm5_client.h"

#include <krb5.h>
#include <kadm5/admin.h>
#include <kdb.h>

#include <cstring>
#include <vector>

namespace gatehouse::infra {
namespace {

core::Status KErr(krb5_context ctx, int code, const char* what) {
  const char* msg = (ctx ? krb5_get_error_message(ctx, code) : nullptr);
  std::string s = std::string(what) + " (code=" + std::to_string(code) + "): " + (msg ? msg : "");
  if (ctx && msg) krb5_free_error_message(ctx, msg);
  return core::Status::Error(core::StatusCode::kInternal, std::move(s));
}

}  // namespace

Kadm5Client::Kadm5Client(Kadm5Config cfg) : cfg_(std::move(cfg)) {}

core::Result<void> Kadm5Client::CreatePrincipal(
    const std::string& new_principal,
    const std::string& new_password,
    const std::string& ldap_dn) const {
  
  if (cfg_.realm.empty()) {
    return core::Result<void>::Err(core::Status::Error(core::StatusCode::kFailedPrecondition, "Kadm5 config incomplete: 'realm' is empty (did you pass --realm CATUNO.LAB?)"));
  }
  if (cfg_.admin_principal.empty()) {
    return core::Result<void>::Err(core::Status::Error(core::StatusCode::kFailedPrecondition, "Kadm5 config incomplete: 'admin_principal' is empty (GATEHOUSE_KADM5_ADMIN_PRINC missing)"));
  }
  if (cfg_.admin_password.empty()) {
    return core::Result<void>::Err(core::Status::Error(core::StatusCode::kFailedPrecondition, "Kadm5 config incomplete: 'admin_password' is empty (GATEHOUSE_KADM5_ADMIN_PASS missing)"));
  }

  krb5_context ctx = nullptr;
  krb5_error_code kret = krb5_init_context(&ctx);
  if (kret) return core::Result<void>::Err(KErr(ctx, kret, "krb5_init_context"));

  kadm5_config_params params;
  std::memset(&params, 0, sizeof(params));
  params.mask = KADM5_CONFIG_REALM;
  params.realm = const_cast<char*>(cfg_.realm.c_str());

  if (!cfg_.admin_server.empty()) {
    params.mask |= KADM5_CONFIG_ADMIN_SERVER;
    params.admin_server = const_cast<char*>(cfg_.admin_server.c_str());
  }

  void* handle = nullptr;
  char* db_args[] = { nullptr };

  kadm5_ret_t ret = kadm5_init_with_password(
      ctx,
      const_cast<char*>(cfg_.admin_principal.c_str()),
      const_cast<char*>(cfg_.admin_password.c_str()),
      const_cast<char*>("kadmin/admin"),
      &params,
      KADM5_STRUCT_VERSION,
      KADM5_API_VERSION_4,
      db_args,
      &handle
  );
  if (ret) {
    auto err = KErr(ctx, ret, "kadm5_init_with_password");
    krb5_free_context(ctx);
    return core::Result<void>::Err(err);
  }

  krb5_principal newprinc = nullptr;
  kret = krb5_parse_name(ctx, new_principal.c_str(), &newprinc);
  if (kret) {
    kadm5_destroy(handle);
    auto err = KErr(ctx, kret, "krb5_parse_name");
    krb5_free_context(ctx);
    return core::Result<void>::Err(err);
  }

  kadm5_principal_ent_rec ent;
  std::memset(&ent, 0, sizeof(ent));
  ent.principal = newprinc;

  long mask = KADM5_PRINCIPAL;

  krb5_tl_data tl;
  std::memset(&tl, 0, sizeof(tl));
  std::vector<unsigned char> tl_contents;

  if (!ldap_dn.empty()) {
    const std::string dbarg = "dn=" + ldap_dn;
    tl_contents.assign(dbarg.begin(), dbarg.end());
    tl_contents.push_back('\0');

    tl.tl_data_type = KRB5_TL_DB_ARGS;
    tl.tl_data_length = static_cast<unsigned int>(tl_contents.size());
    tl.tl_data_contents = reinterpret_cast<krb5_octet*>(tl_contents.data());
    tl.tl_data_next = nullptr;

    ent.tl_data = &tl;
    ent.n_tl_data = 1;
    mask |= KADM5_TL_DATA;
  }

  ret = kadm5_create_principal(handle, &ent, mask, const_cast<char*>(new_password.c_str()));
  
  kadm5_destroy(handle);
  krb5_free_principal(ctx, newprinc);
  krb5_free_context(ctx);

  if (ret) {
    // Falls der Principal schon existiert, ist das oft kein harter Fehler im Flow, wir könnten ein Password-Update machen.
    // Aber wir geben es hier als sauberen Fehler zurück.
    return core::Result<void>::Err(core::Status::Error(core::StatusCode::kInternal, "kadm5_create_principal failed: code " + std::to_string(ret)));
  }

  return core::Result<void>::Ok();
}

}  // namespace gatehouse::infra
