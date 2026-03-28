#pragma once

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "app/auth.h"
#include "app/email_sender.h"
#include "app/http_server.h"
#include "core/result.h"
#include "crow.h"
#include "infra/invite_otp_repo.h"
#include "infra/invite_repo.h"
#include "infra/invite_session_repo.h"
#include "infra/ldap_directory.h"
#include "infra/ldif_directory.h"
#include "infra/session_repo.h"
#include "infra/sqlite_db.h"
#include "infra/cred_fetch_token_repo.h"
#include "infra/ticket_vault_read.h"
#include "infra/ticket_vault_repo.h"

namespace gatehouse::app {

// Cookie name for the invite-flow session (shared across route files).
constexpr const char* kInviteCookie = "gh_inv_sid";

// Per-IP login rate limiter.  Max 10 attempts per 5-minute window.
// MED-07: Hard cap on map size to prevent memory exhaustion from IP spoofing.
struct LoginRateLimiter {
  static constexpr int kMaxAttempts = 10;
  static constexpr std::int64_t kWindowSecs = 300;
  static constexpr std::size_t kMapMaxSize = 100000;

  std::mutex mu;
  std::unordered_map<std::string, std::pair<int, std::int64_t>> attempts;

  // Returns true if the request is within the allowed rate.
  bool Check(const std::string& ip);
};

// All shared server state passed to route-registration functions.
// All members are references/pointers into locals of HttpServer::Run(),
// which outlives the server because Run() blocks until shutdown.
struct ServerContext {
  HttpServerConfig& cfg;
  infra::SqliteDb& db;
  std::optional<infra::LdapDirectory>& ldap_dir;
  infra::LdifDirectory& ldif_dir;
  infra::SessionRepo& sessions;
  infra::TicketVaultRepo& vault;
  infra::InviteRepo& invites;
  infra::InviteSessionRepo& invite_sessions;
  infra::InviteProfileRepo& invite_profiles;
  infra::InviteOtpRepo& invite_otps;
  infra::CredFetchTokenRepo& cred_fetch_tokens;
  infra::TicketVaultReadRepo& ticket_vault_read;
  AuthService& auth;
  IEmailSender& email;
  const std::vector<std::uint8_t>& master_key;
  LoginRateLimiter& rate_limiter;
};

// ---- Auth / session helpers ----

// Returns the authenticated SessionRow if the request carries a valid session
// cookie, or nullopt if unauthenticated / expired / IP mismatch.
std::optional<infra::SessionRow> RequireAuth(ServerContext& ctx,
                                             const crow::request& req);

// Returns the InviteSessionRow for an active invite-flow session, or nullopt.
std::optional<infra::InviteSessionRow> RequireInviteSession(
    ServerContext& ctx, const crow::request& req);

// Returns true if `uid` is in the configured admin list or LDAP admin group.
bool IsAdminUid(ServerContext& ctx, const std::string& uid);

// CSRF validation: hidden form field "_csrf".
bool CsrfOkForm(const crow::request& req, const infra::SessionRow& s);

// CSRF validation: "X-CSRF-Token" request header.
bool CsrfOkHeader(const crow::request& req, const infra::SessionRow& s);

// Sets the JS-readable gh_csrf cookie (no HttpOnly, intentional).
void SetCsrfCookie(crow::response& r, const std::string& csrf_hex,
                   std::int64_t max_age);

// SHA-256 of a remote IP string (for session IP binding).
std::vector<std::uint8_t> HashRemoteIp(const std::string& ip);

// Encrypts and stores a Kerberos ccache in the ticket vault (noop if empty).
core::Result<std::string> StoreTicketIfPresent(ServerContext& ctx,
                                               const LoginPrincipal& principal);

}  // namespace gatehouse::app
