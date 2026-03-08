#include "infra/krb5_client.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#include <unistd.h>

#include "krb5_helpers.h"

namespace gatehouse::infra {
namespace {

core::Result<std::vector<std::uint8_t>> ReadAll(const std::string& path) {
  FILE* f = std::fopen(path.c_str(), "rb");
  if (f == nullptr) {
    return core::Result<std::vector<std::uint8_t>>::Err(
        core::Status::Error(core::StatusCode::kNotFound,
                            "fopen failed: " + path + " errno=" +
                                std::to_string(errno)));
  }

  if (std::fseek(f, 0, SEEK_END) != 0) {
    std::fclose(f);
    return core::Result<std::vector<std::uint8_t>>::Err(
        core::Status::Error(core::StatusCode::kInternal, "fseek failed"));
  }

  const long size = std::ftell(f);
  if (size < 0) {
    std::fclose(f);
    return core::Result<std::vector<std::uint8_t>>::Err(
        core::Status::Error(core::StatusCode::kInternal, "ftell failed"));
  }

  std::rewind(f);

  std::vector<std::uint8_t> buffer;
  buffer.resize(static_cast<std::size_t>(size));

  if (size > 0) {
    const std::size_t got = std::fread(buffer.data(), 1, buffer.size(), f);
    if (got != buffer.size()) {
      std::fclose(f);
      return core::Result<std::vector<std::uint8_t>>::Err(
          core::Status::Error(core::StatusCode::kInternal, "fread failed"));
    }
  }

  std::fclose(f);
  return core::Result<std::vector<std::uint8_t>>::Ok(std::move(buffer));
}

}  // namespace

Krb5Client::Krb5Client(Krb5Config cfg) : cfg_(std::move(cfg)) {}

std::string Krb5Client::MakePrincipal(const std::string& username) const {
  if (username.find('@') != std::string::npos) {
    return username;
  }
  if (cfg_.realm.empty()) {
    return username;
  }
  return username + "@" + cfg_.realm;
}

core::Result<Krb5VerifyResult> Krb5Client::VerifyPasswordAndGetCcache(
    const std::string& username, const std::string& password) const {
  if (username.empty() || password.empty()) {
    return core::Result<Krb5VerifyResult>::Err(
        core::Status::Error(core::StatusCode::kInvalidArgument,
                            "missing username/password"));
  }

  auto ctx_result = MakeKrb5Context();
  if (!ctx_result.ok()) {
    return core::Result<Krb5VerifyResult>::Err(ctx_result.status());
  }
  auto ctx = std::move(ctx_result.value());

  const std::string principal_name = MakePrincipal(username);

  auto principal_result = ParseKrb5Principal(ctx.get(), principal_name);
  if (!principal_result.ok()) {
    return core::Result<Krb5VerifyResult>::Err(principal_result.status());
  }
  auto principal = std::move(principal_result.value());

  auto opt_result = MakeKrb5InitCredsOpt(ctx.get());
  if (!opt_result.ok()) {
    return core::Result<Krb5VerifyResult>::Err(opt_result.status());
  }
  auto opt = std::move(opt_result.value());

  ScopedKrb5Creds creds(ctx.get());

  auto acquire_result = AcquireKrb5TgtWithPassword(
      ctx.get(), creds.get(), principal.get(), password, opt.get());
  if (!acquire_result.ok()) {
    return core::Result<Krb5VerifyResult>::Err(acquire_result.status());
  }

  auto unparsed_result = UnparseKrb5Principal(ctx.get(), principal.get());
  if (!unparsed_result.ok()) {
    return core::Result<Krb5VerifyResult>::Err(unparsed_result.status());
  }
  auto unparsed = std::move(unparsed_result.value());

  auto ccache_result = MakeUniqueFileCcache(ctx.get());
  if (!ccache_result.ok()) {
    return core::Result<Krb5VerifyResult>::Err(ccache_result.status());
  }
  auto ccache = std::move(ccache_result.value());

  krb5_error_code rc = krb5_cc_initialize(ctx.get(), ccache.get(), principal.get());
  if (rc != 0) {
    return core::Result<Krb5VerifyResult>::Err(
        Krb5ErrorStatus("krb5_cc_initialize", ctx.get(), rc));
  }

  rc = krb5_cc_store_cred(ctx.get(), ccache.get(), creds.get());
  if (rc != 0) {
    return core::Result<Krb5VerifyResult>::Err(
        Krb5ErrorStatus("krb5_cc_store_cred", ctx.get(), rc));
  }

  auto full_name_result = GetKrb5CcacheFullName(ctx.get(), ccache.get());
  if (!full_name_result.ok()) {
    return core::Result<Krb5VerifyResult>::Err(full_name_result.status());
  }
  auto full_name = std::move(full_name_result.value());

  std::string path = full_name.get();
  constexpr char kFilePrefix[] = "FILE:";
  if (path.rfind(kFilePrefix, 0) == 0) {
    path.erase(0, sizeof(kFilePrefix) - 1);
  }

  rc = krb5_cc_close(ctx.get(), ccache.release());
  if (rc != 0) {
    return core::Result<Krb5VerifyResult>::Err(
        Krb5ErrorStatus("krb5_cc_close", ctx.get(), rc));
  }

  auto blob_result = ReadAll(path);

  // Best effort cleanup of the temp FILE ccache.
  (void)::unlink(path.c_str());

  if (!blob_result.ok()) {
    return core::Result<Krb5VerifyResult>::Err(blob_result.status());
  }

  Krb5VerifyResult out;
  out.principal = unparsed.get();
  out.tgt_expires_at = static_cast<std::int64_t>(creds.get()->times.endtime);
  out.ccache_blob = std::move(blob_result.value());

  return core::Result<Krb5VerifyResult>::Ok(std::move(out));
}

core::Result<void> Krb5Client::ChangePassword(
    const std::string& username,
    const std::string& old_password,
    const std::string& new_password) const {
  if (username.empty() || old_password.empty() || new_password.empty()) {
    return core::Result<void>::Err(
        core::Status::Error(core::StatusCode::kInvalidArgument,
                            "missing credentials"));
  }

  auto ctx_result = MakeKrb5Context();
  if (!ctx_result.ok()) {
    return core::Result<void>::Err(ctx_result.status());
  }
  auto ctx = std::move(ctx_result.value());

  const std::string principal_name = MakePrincipal(username);

  auto principal_result = ParseKrb5Principal(ctx.get(), principal_name);
  if (!principal_result.ok()) {
    return core::Result<void>::Err(principal_result.status());
  }
  auto principal = std::move(principal_result.value());

  auto opt_result = MakeKrb5InitCredsOpt(ctx.get());
  if (!opt_result.ok()) {
    return core::Result<void>::Err(opt_result.status());
  }
  auto opt = std::move(opt_result.value());

  ScopedKrb5Creds creds(ctx.get());

  auto acquire_result = AcquireKrb5ChangePasswordCreds(
      ctx.get(), creds.get(), principal.get(), old_password, opt.get());
  if (!acquire_result.ok()) {
    return core::Result<void>::Err(acquire_result.status());
  }

  int result_code = 0;
  ScopedKrb5Data result_code_string(ctx.get());
  ScopedKrb5Data result_string(ctx.get());

  const krb5_error_code rc = krb5_change_password(
      ctx.get(),
      creds.get(),
      const_cast<char*>(new_password.c_str()),
      &result_code,
      result_code_string.get(),
      result_string.get());

  std::string rejection_message = "Unknown rejection";
  if (result_code != 0) {
    const std::string result_text = result_string.ToString();
    const std::string result_code_text = result_code_string.ToString();

    if (!result_text.empty()) {
      rejection_message = result_text;
    } else if (!result_code_text.empty()) {
      rejection_message = result_code_text;
    }
  }

  if (rc != 0) {
    return core::Result<void>::Err(
        Krb5ErrorStatus("krb5_change_password failed", ctx.get(), rc));
  }

  if (result_code != 0) {
    return core::Result<void>::Err(
        core::Status::Error(core::StatusCode::kInvalidArgument,
                            "Password rejected by policy: " +
                                rejection_message));
  }

  return core::Result<void>::Ok();
}

}  // namespace gatehouse::infra