#pragma once

#include <cstring>
#include <memory>
#include <string>
#include <type_traits>

#include <krb5.h>
#include <kadm5/admin.h>
/*
extern "C" {
     #include <com_err.h> failed
    extern const char* error_message(long);
}
*/
#include "core/result.h"
#include "core/status.h"

namespace gatehouse::infra {

inline core::Status Krb5ErrorStatus(const char* what,
                                    krb5_context ctx,
                                    krb5_error_code code) {
  const char* msg = (ctx != nullptr) ? krb5_get_error_message(ctx, code) : nullptr;

  std::string text =
      std::string(what) + " (krb5=" + std::to_string(static_cast<int>(code)) + ")";
  if (msg != nullptr) {
    text += ": ";
    text += msg;
  }

  if (ctx != nullptr && msg != nullptr) {
    krb5_free_error_message(ctx, msg);
  }

  return core::Status::Error(core::StatusCode::kUnauthenticated, std::move(text));
}
inline core::Status Kadm5ErrorStatus(const char* what,
                                     krb5_context ctx,
                                     kadm5_ret_t code) {
  const char* msg = krb5_get_error_message(ctx, static_cast<krb5_error_code>(code));

  std::string text =
      std::string(what) + " (kadm5=" + std::to_string(static_cast<int>(code)) + ")";
  if (msg != nullptr) {
    text += ": ";
    text += msg;
    krb5_free_error_message(ctx, msg);
  }
  return core::Status::Error(core::StatusCode::kInternal, std::move(text));
}
struct ContextDeleter {
  void operator()(krb5_context ctx) const noexcept {
    if (ctx != nullptr) {
      krb5_free_context(ctx);
    }
  }
};

using UniqueKrb5Context =
    std::unique_ptr<std::remove_pointer_t<krb5_context>, ContextDeleter>;

inline core::Result<UniqueKrb5Context> MakeKrb5Context() {
  krb5_context raw = nullptr;
  const krb5_error_code rc = krb5_init_context(&raw);
  if (rc != 0) {
    return core::Result<UniqueKrb5Context>::Err(
        core::Status::Error(core::StatusCode::kUnavailable,
                            "krb5_init_context failed"));
  }
  return core::Result<UniqueKrb5Context>::Ok(UniqueKrb5Context(raw));
}

struct PrincipalDeleter {
  krb5_context ctx = nullptr;

  void operator()(krb5_principal principal) const noexcept {
    if (ctx != nullptr && principal != nullptr) {
      krb5_free_principal(ctx, principal);
    }
  }
};

using UniqueKrb5Principal =
    std::unique_ptr<std::remove_pointer_t<krb5_principal>, PrincipalDeleter>;

inline core::Result<UniqueKrb5Principal> ParseKrb5Principal(
    krb5_context ctx, const std::string& principal_name) {
  if (ctx == nullptr) {
    return core::Result<UniqueKrb5Principal>::Err(
        core::Status::Error(core::StatusCode::kInvalidArgument,
                            "ParseKrb5Principal: ctx is null"));
  }

  krb5_principal raw = nullptr;
  const krb5_error_code rc = krb5_parse_name(ctx, principal_name.c_str(), &raw);
  if (rc != 0) {
    return core::Result<UniqueKrb5Principal>::Err(
        Krb5ErrorStatus("krb5_parse_name", ctx, rc));
  }

  return core::Result<UniqueKrb5Principal>::Ok(
      UniqueKrb5Principal(raw, PrincipalDeleter{ctx}));
}

struct InitCredsOptDeleter {
  krb5_context ctx = nullptr;

  void operator()(krb5_get_init_creds_opt* opt) const noexcept {
    if (ctx != nullptr && opt != nullptr) {
      krb5_get_init_creds_opt_free(ctx, opt);
    }
  }
};

using UniqueKrb5InitCredsOpt =
    std::unique_ptr<krb5_get_init_creds_opt, InitCredsOptDeleter>;

inline core::Result<UniqueKrb5InitCredsOpt> MakeKrb5InitCredsOpt(krb5_context ctx) {
  if (ctx == nullptr) {
    return core::Result<UniqueKrb5InitCredsOpt>::Err(
        core::Status::Error(core::StatusCode::kInvalidArgument,
                            "MakeKrb5InitCredsOpt: ctx is null"));
  }

  krb5_get_init_creds_opt* raw = nullptr;
  const krb5_error_code rc = krb5_get_init_creds_opt_alloc(ctx, &raw);
  if (rc != 0) {
    return core::Result<UniqueKrb5InitCredsOpt>::Err(
        Krb5ErrorStatus("krb5_get_init_creds_opt_alloc", ctx, rc));
  }

  return core::Result<UniqueKrb5InitCredsOpt>::Ok(
      UniqueKrb5InitCredsOpt(raw, InitCredsOptDeleter{ctx}));
}

struct UnparsedNameDeleter {
  krb5_context ctx = nullptr;

  void operator()(char* value) const noexcept {
    if (ctx != nullptr && value != nullptr) {
      krb5_free_unparsed_name(ctx, value);
    }
  }
};

using UniqueKrb5UnparsedName = std::unique_ptr<char, UnparsedNameDeleter>;

inline core::Result<UniqueKrb5UnparsedName> UnparseKrb5Principal(
    krb5_context ctx, krb5_principal principal) {
  if (ctx == nullptr || principal == nullptr) {
    return core::Result<UniqueKrb5UnparsedName>::Err(
        core::Status::Error(core::StatusCode::kInvalidArgument,
                            "UnparseKrb5Principal: invalid argument"));
  }

  char* raw = nullptr;
  const krb5_error_code rc = krb5_unparse_name(ctx, principal, &raw);
  if (rc != 0 || raw == nullptr) {
    return core::Result<UniqueKrb5UnparsedName>::Err(
        Krb5ErrorStatus("krb5_unparse_name", ctx, rc));
  }

  return core::Result<UniqueKrb5UnparsedName>::Ok(
      UniqueKrb5UnparsedName(raw, UnparsedNameDeleter{ctx}));
}

struct StringDeleter {
  krb5_context ctx = nullptr;

  void operator()(char* value) const noexcept {
    if (ctx != nullptr && value != nullptr) {
      krb5_free_string(ctx, value);
    }
  }
};

using UniqueKrb5String = std::unique_ptr<char, StringDeleter>;

inline core::Result<UniqueKrb5String> GetKrb5CcacheFullName(krb5_context ctx,
                                                            krb5_ccache ccache) {
  if (ctx == nullptr || ccache == nullptr) {
    return core::Result<UniqueKrb5String>::Err(
        core::Status::Error(core::StatusCode::kInvalidArgument,
                            "GetKrb5CcacheFullName: invalid argument"));
  }

  char* raw = nullptr;
  const krb5_error_code rc = krb5_cc_get_full_name(ctx, ccache, &raw);
  if (rc != 0 || raw == nullptr) {
    return core::Result<UniqueKrb5String>::Err(
        Krb5ErrorStatus("krb5_cc_get_full_name", ctx, rc));
  }

  return core::Result<UniqueKrb5String>::Ok(
      UniqueKrb5String(raw, StringDeleter{ctx}));
}

inline core::Result<void> GetKrb5InitCredsPassword(
    krb5_context ctx,
    krb5_creds* creds,
    krb5_principal principal,
    const std::string& password,
    krb5_get_init_creds_opt* options,
    const char* service = nullptr,
    const char* operation_name = "krb5_get_init_creds_password") {
  if (ctx == nullptr || creds == nullptr || principal == nullptr) {
    return core::Result<void>::Err(
        core::Status::Error(core::StatusCode::kInvalidArgument,
                            "GetKrb5InitCredsPassword: invalid argument"));
  }

  // CRIT-04: Copy password into a mutable buffer; const_cast on std::string
  // internal storage is UB if the library modifies the buffer.
  std::vector<char> password_buf(password.begin(), password.end());
  password_buf.push_back('\0');
  char* service_mut = const_cast<char*>(service);

  const krb5_error_code rc = krb5_get_init_creds_password(
      ctx,
      creds,
      principal,
      password_buf.data(),
      /*prompter=*/nullptr,
      /*data=*/nullptr,
      /*start_time=*/0,
      service_mut,
      options);

  if (rc != 0) {
    return core::Result<void>::Err(Krb5ErrorStatus(operation_name, ctx, rc));
  }

  return core::Result<void>::Ok();
}

inline core::Result<void> AcquireKrb5TgtWithPassword(
    krb5_context ctx,
    krb5_creds* creds,
    krb5_principal principal,
    const std::string& password,
    krb5_get_init_creds_opt* options) {
  return GetKrb5InitCredsPassword(ctx,
                                  creds,
                                  principal,
                                  password,
                                  options,
                                  /*service=*/nullptr,
                                  "krb5_get_init_creds_password");
}

inline core::Result<void> AcquireKrb5ChangePasswordCreds(
    krb5_context ctx,
    krb5_creds* creds,
    krb5_principal principal,
    const std::string& old_password,
    krb5_get_init_creds_opt* options) {
  return GetKrb5InitCredsPassword(ctx,
                                  creds,
                                  principal,
                                  old_password,
                                  options,
                                  "kadmin/changepw",
                                  "Authentication failed (Old password incorrect?)");
}

class ScopedKrb5Creds {
 public:
  explicit ScopedKrb5Creds(krb5_context ctx) noexcept : ctx_(ctx) {
    std::memset(&creds_, 0, sizeof(creds_));
  }

  ~ScopedKrb5Creds() {
    if (ctx_ != nullptr) {
      krb5_free_cred_contents(ctx_, &creds_);
    }
  }

  ScopedKrb5Creds(const ScopedKrb5Creds&) = delete;
  ScopedKrb5Creds& operator=(const ScopedKrb5Creds&) = delete;

  ScopedKrb5Creds(ScopedKrb5Creds&&) = delete;
  ScopedKrb5Creds& operator=(ScopedKrb5Creds&&) = delete;

  krb5_creds* get() noexcept { return &creds_; }
  const krb5_creds* get() const noexcept { return &creds_; }

 private:
  krb5_context ctx_ = nullptr;
  krb5_creds creds_{};
};

enum class Krb5CcacheCleanupMode {
  kClose,
  kDestroy,
};

struct CcacheDeleter {
  krb5_context ctx = nullptr;
  Krb5CcacheCleanupMode mode = Krb5CcacheCleanupMode::kClose;

  void operator()(krb5_ccache ccache) const noexcept {
    if (ctx == nullptr || ccache == nullptr) {
      return;
    }

    if (mode == Krb5CcacheCleanupMode::kDestroy) {
      (void)krb5_cc_destroy(ctx, ccache);
      return;
    }

    (void)krb5_cc_close(ctx, ccache);
  }
};

using UniqueKrb5Ccache =
    std::unique_ptr<std::remove_pointer_t<krb5_ccache>, CcacheDeleter>;

inline core::Result<UniqueKrb5Ccache> MakeUniqueFileCcache(krb5_context ctx) {
  if (ctx == nullptr) {
    return core::Result<UniqueKrb5Ccache>::Err(
        core::Status::Error(core::StatusCode::kInvalidArgument,
                            "MakeUniqueFileCcache: ctx is null"));
  }

  krb5_ccache raw = nullptr;
  const krb5_error_code rc = krb5_cc_new_unique(ctx, "FILE", nullptr, &raw);
  if (rc != 0) {
    return core::Result<UniqueKrb5Ccache>::Err(
        Krb5ErrorStatus("krb5_cc_new_unique(FILE)", ctx, rc));
  }

  return core::Result<UniqueKrb5Ccache>::Ok(
      UniqueKrb5Ccache(raw, CcacheDeleter{ctx, Krb5CcacheCleanupMode::kDestroy}));
}

class ScopedKrb5Data {
 public:
  explicit ScopedKrb5Data(krb5_context ctx) noexcept : ctx_(ctx) {}

  ~ScopedKrb5Data() {
    if (ctx_ != nullptr && data_.data != nullptr) {
      krb5_free_data_contents(ctx_, &data_);
    }
  }

  ScopedKrb5Data(const ScopedKrb5Data&) = delete;
  ScopedKrb5Data& operator=(const ScopedKrb5Data&) = delete;

  ScopedKrb5Data(ScopedKrb5Data&&) = delete;
  ScopedKrb5Data& operator=(ScopedKrb5Data&&) = delete;

  krb5_data* get() noexcept { return &data_; }
  const krb5_data* get() const noexcept { return &data_; }

  std::string ToString() const {
    if (data_.data == nullptr || data_.length <= 0) {
      return {};
    }
    return std::string(data_.data, static_cast<std::size_t>(data_.length));
  }

 private:
  krb5_context ctx_ = nullptr;
  krb5_data data_{0, 0, nullptr};
};

}  // namespace gatehouse::infra