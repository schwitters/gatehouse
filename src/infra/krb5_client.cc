#include "infra/krb5_client.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#include <krb5.h>
#include <unistd.h>

namespace gatehouse::infra {
namespace {

core::Status KErr(const char* what, krb5_context ctx, krb5_error_code code) {
  const char* msg = (ctx != nullptr) ? krb5_get_error_message(ctx, code) : nullptr;
  std::string s = std::string(what) + " (krb5=" + std::to_string(static_cast<int>(code)) + ")";
  if (msg != nullptr) {
    s += ": ";
    s += msg;
  }
  if (ctx != nullptr && msg != nullptr) {
    krb5_free_error_message(ctx, msg);
  }
  return core::Status::Error(core::StatusCode::kUnauthenticated, std::move(s));
}

core::Result<std::vector<std::uint8_t>> ReadAll(const std::string& path) {
  FILE* f = std::fopen(path.c_str(), "rb");
  if (f == nullptr) {
    return core::Result<std::vector<std::uint8_t>>::Err(
        core::Status::Error(core::StatusCode::kNotFound,
                            "fopen failed: " + path + " errno=" + std::to_string(errno)));
  }
  std::vector<std::uint8_t> buf;
  std::fseek(f, 0, SEEK_END);
  const long sz = std::ftell(f);
  if (sz < 0) {
    std::fclose(f);
    return core::Result<std::vector<std::uint8_t>>::Err(
        core::Status::Error(core::StatusCode::kInternal, "ftell failed"));
  }
  std::rewind(f);
  buf.resize(static_cast<std::size_t>(sz));
  if (sz > 0) {
    const std::size_t got = std::fread(buf.data(), 1, buf.size(), f);
    if (got != buf.size()) {
      std::fclose(f);
      return core::Result<std::vector<std::uint8_t>>::Err(
          core::Status::Error(core::StatusCode::kInternal, "fread failed"));
    }
  }
  std::fclose(f);
  return core::Result<std::vector<std::uint8_t>>::Ok(std::move(buf));
}

}  // namespace

Krb5Client::Krb5Client(Krb5Config cfg) : cfg_(std::move(cfg)) {}

std::string Krb5Client::MakePrincipal(const std::string& username) const {
  if (username.find('@') != std::string::npos) return username;
  if (cfg_.realm.empty()) return username;
  return username + "@" + cfg_.realm;
}

core::Result<Krb5VerifyResult> Krb5Client::VerifyPasswordAndGetCcache(
    const std::string& username, const std::string& password) const {
  if (username.empty() || password.empty()) {
    return core::Result<Krb5VerifyResult>::Err(
        core::Status::Error(core::StatusCode::kInvalidArgument, "missing username/password"));
  }

  krb5_context ctx = nullptr;
  krb5_error_code rc = krb5_init_context(&ctx);
  if (rc != 0) {
    return core::Result<Krb5VerifyResult>::Err(
        core::Status::Error(core::StatusCode::kUnavailable, "krb5_init_context failed"));
  }

  const std::string principal_str = MakePrincipal(username);

  krb5_principal princ = nullptr;
  rc = krb5_parse_name(ctx, principal_str.c_str(), &princ);
  if (rc != 0) {
    krb5_free_context(ctx);
    return core::Result<Krb5VerifyResult>::Err(KErr("krb5_parse_name", ctx, rc));
  }

  krb5_get_init_creds_opt* opt = nullptr;
  rc = krb5_get_init_creds_opt_alloc(ctx, &opt);
  if (rc != 0) {
    krb5_free_principal(ctx, princ);
    krb5_free_context(ctx);
    return core::Result<Krb5VerifyResult>::Err(KErr("krb5_get_init_creds_opt_alloc", ctx, rc));
  }

  krb5_creds creds{};
  std::memset(&creds, 0, sizeof(creds));

  rc = krb5_get_init_creds_password(
      ctx, &creds, princ, password.c_str(),
      /*prompter=*/nullptr, /*data=*/nullptr,
      /*start_time=*/0,
      /*in_tkt_service=*/nullptr, opt);

  krb5_get_init_creds_opt_free(ctx, opt);

  if (rc != 0) {
    krb5_free_cred_contents(ctx, &creds);
    krb5_free_principal(ctx, princ);
    krb5_free_context(ctx);
    return core::Result<Krb5VerifyResult>::Err(KErr("krb5_get_init_creds_password", ctx, rc));
  }

  char* unparsed = nullptr;
  rc = krb5_unparse_name(ctx, princ, &unparsed);
  if (rc != 0 || unparsed == nullptr) {
    krb5_free_cred_contents(ctx, &creds);
    krb5_free_principal(ctx, princ);
    krb5_free_context(ctx);
    return core::Result<Krb5VerifyResult>::Err(KErr("krb5_unparse_name", ctx, rc));
  }

  // Write creds to a unique FILE ccache, then read bytes and delete the file.
  krb5_ccache cc = nullptr;
  rc = krb5_cc_new_unique(ctx, "FILE", nullptr, &cc);
  if (rc != 0) {
    krb5_free_unparsed_name(ctx, unparsed);
    krb5_free_cred_contents(ctx, &creds);
    krb5_free_principal(ctx, princ);
    krb5_free_context(ctx);
    return core::Result<Krb5VerifyResult>::Err(KErr("krb5_cc_new_unique(FILE)", ctx, rc));
  }

  rc = krb5_cc_initialize(ctx, cc, princ);
  if (rc != 0) {
    krb5_cc_destroy(ctx, cc);
    krb5_free_unparsed_name(ctx, unparsed);
    krb5_free_cred_contents(ctx, &creds);
    krb5_free_principal(ctx, princ);
    krb5_free_context(ctx);
    return core::Result<Krb5VerifyResult>::Err(KErr("krb5_cc_initialize", ctx, rc));
  }

  rc = krb5_cc_store_cred(ctx, cc, &creds);
  if (rc != 0) {
    krb5_cc_destroy(ctx, cc);
    krb5_free_unparsed_name(ctx, unparsed);
    krb5_free_cred_contents(ctx, &creds);
    krb5_free_principal(ctx, princ);
    krb5_free_context(ctx);
    return core::Result<Krb5VerifyResult>::Err(KErr("krb5_cc_store_cred", ctx, rc));
  }

  char* full = nullptr;
  rc = krb5_cc_get_full_name(ctx, cc, &full);
  if (rc != 0 || full == nullptr) {
    krb5_cc_destroy(ctx, cc);
    krb5_free_unparsed_name(ctx, unparsed);
    krb5_free_cred_contents(ctx, &creds);
    krb5_free_principal(ctx, princ);
    krb5_free_context(ctx);
    return core::Result<Krb5VerifyResult>::Err(KErr("krb5_cc_get_full_name", ctx, rc));
  }

  // full looks like "FILE:/tmp/krb5cc_XXXXXX". Extract path after "FILE:".
  std::string full_name = full;
  krb5_free_string(ctx, full);

  const std::string prefix = "FILE:";
  std::string path = full_name;
  if (path.rfind(prefix, 0) == 0) path = path.substr(prefix.size());

  // Close and destroy the ccache; for FILE, destroy removes the file.
  // But we need file bytes -> read BEFORE destroy. Close keeps file.
  rc = krb5_cc_close(ctx, cc);
  if (rc != 0) {
    krb5_free_unparsed_name(ctx, unparsed);
    krb5_free_cred_contents(ctx, &creds);
    krb5_free_principal(ctx, princ);
    krb5_free_context(ctx);
    return core::Result<Krb5VerifyResult>::Err(KErr("krb5_cc_close", ctx, rc));
  }

  auto blob = ReadAll(path);

  // Best-effort delete file.
  (void)::unlink(path.c_str());

  if (!blob.ok()) {
    krb5_free_unparsed_name(ctx, unparsed);
    krb5_free_cred_contents(ctx, &creds);
    krb5_free_principal(ctx, princ);
    krb5_free_context(ctx);
    return core::Result<Krb5VerifyResult>::Err(blob.status());
  }

  Krb5VerifyResult out;
  out.principal = unparsed;
  out.tgt_expires_at = static_cast<std::int64_t>(creds.times.endtime);
  out.ccache_blob = std::move(blob.value());

  krb5_free_unparsed_name(ctx, unparsed);
  krb5_free_cred_contents(ctx, &creds);
  krb5_free_principal(ctx, princ);
  krb5_free_context(ctx);

  return core::Result<Krb5VerifyResult>::Ok(std::move(out));
}

}  // namespace gatehouse::infra
