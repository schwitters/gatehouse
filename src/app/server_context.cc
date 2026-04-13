#include "app/server_context.h"

#include <cstdio>
#include <mutex>
#include <string>
#include <vector>

#include "app/http_utils.h"
#include "core/crypto_aead.h"
#include "core/hex.h"
#include "core/random.h"
#include "core/sha256.h"
#include "core/time.h"
#include "core/url.h"

namespace gatehouse::app {

// ---- LoginRateLimiter ----

bool LoginRateLimiter::Check(const std::string& ip) {
  std::lock_guard<std::mutex> lk(mu);
  if (attempts.size() >= kMapMaxSize && attempts.find(ip) == attempts.end()) {
    return false;
  }
  auto& entry = attempts[ip];
  const std::int64_t now_ts = core::UnixNow();
  if (now_ts - entry.second > kWindowSecs) {
    entry = {0, now_ts};
  }
  entry.first++;
  return entry.first <= kMaxAttempts;
}

// ---- Helpers ----

std::vector<std::uint8_t> HashRemoteIp(const std::string& ip) {
  if (ip.empty()) return {};
  const std::vector<std::uint8_t> ip_bytes(ip.begin(), ip.end());
  auto h = core::Sha256(ip_bytes);
  return h.ok() ? h.value() : std::vector<std::uint8_t>{};
}

static void GcSessions(ServerContext& ctx) {
  (void)ctx.sessions.DeleteExpired(core::UnixNow());
  (void)ctx.invite_sessions.DeleteExpired(core::UnixNow());
}

std::optional<infra::SessionRow> RequireAuth(ServerContext& ctx,
                                             const crow::request& req) {
  GcSessions(ctx);
  const std::string sid = CookieValueFromHeader(req, ctx.cfg.session_cookie_name);
  if (sid.empty()) return std::nullopt;
  auto got = ctx.sessions.GetBySid(sid);
  if (!got.ok() || !got.value().has_value()) return std::nullopt;
  const infra::SessionRow& row = *got.value();
  if (row.expires_at <= core::UnixNow()) return std::nullopt;
  // IP binding: validate that the request comes from the same IP as the login.
  if (!row.ip_hash_hex.empty()) {
    const std::vector<std::uint8_t> req_ip_hash = HashRemoteIp(req.remote_ip_address);
    if (req_ip_hash.empty() ||
        core::HexEncode(req_ip_hash) != row.ip_hash_hex) {
      std::fprintf(stderr, "[gatehouse][security] Session IP mismatch for uid=%s\n",
                   row.uid.c_str());
      return std::nullopt;
    }
  }
  return row;
}

std::optional<infra::InviteSessionRow> RequireInviteSession(
    ServerContext& ctx, const crow::request& req) {
  GcSessions(ctx);
  const std::string sid = CookieValueFromHeader(req, kInviteCookie);
  if (sid.empty()) return std::nullopt;
  auto got = ctx.invite_sessions.GetBySid(sid);
  if (!got.ok() || !got.value().has_value()) return std::nullopt;
  const infra::InviteSessionRow& row = *got.value();
  if (row.expires_at <= core::UnixNow()) return std::nullopt;
  if (row.consumed_at != 0) return std::nullopt;
  return row;
}

bool IsAdminUid(ServerContext& ctx, const std::string& uid) {
  if (!ctx.cfg.ldap_admin_group.empty() && ctx.ldap_dir.has_value()) {
    auto rc = ctx.ldap_dir->IsUserInGroup(uid, ctx.cfg.ldap_admin_group);
    if (rc.ok() && rc.value()) return true;
  }
  for (const auto& a : ctx.cfg.admin_uids) {
    if (a == uid) return true;
  }
  return false;
}

bool CsrfOkForm(const crow::request& req, const infra::SessionRow& s) {
  auto tok = core::FormGet(req.body, "_csrf");
  return tok.has_value() && !tok->empty() && *tok == s.csrf_secret_hex;
}

bool CsrfOkHeader(const crow::request& req, const infra::SessionRow& s) {
  const std::string tok = req.get_header_value("X-CSRF-Token");
  return !tok.empty() && tok == s.csrf_secret_hex;
}

void SetCsrfCookie(crow::response& r, const std::string& csrf_hex,
                   std::int64_t max_age, const std::string& base_uri) {
  const std::string path = base_uri.empty() ? "/" : base_uri + "/";
  r.add_header("Set-Cookie",
               "gh_csrf=" + csrf_hex + "; Path=" + path + "; Max-Age=" +
                   std::to_string(max_age) + "; SameSite=Strict");
}

core::Result<std::string> StoreTicketIfPresent(ServerContext& ctx,
                                               const LoginPrincipal& principal) {
  if (principal.ccache_blob.empty()) return core::Result<std::string>::Ok(std::string{});

  auto ticket_id_bytes = core::RandomBytes(16);
  if (!ticket_id_bytes.ok()) return core::Result<std::string>::Err(ticket_id_bytes.status());
  const std::string ticket_id = core::HexEncode(ticket_id_bytes.value());

  auto nonce = core::RandomBytes(12);
  if (!nonce.ok()) return core::Result<std::string>::Err(nonce.status());

  const std::string aad_str = principal.uid + "|" + principal.tenant_id + "|" + ticket_id;
  auto enc = core::Aes256GcmEncrypt(ctx.master_key, nonce.value(), aad_str, principal.ccache_blob);
  if (!enc.ok()) return core::Result<std::string>::Err(enc.status());

  infra::TicketVaultRow row;
  row.ticket_id = ticket_id;
  row.uid = principal.uid;
  row.tenant_id = principal.tenant_id;
  row.created_at = core::UnixNow();
  row.expires_at = principal.tgt_expires_at;
  row.enc_alg = "AES-256-GCM";
  row.enc_key_id = "env:v1";
  row.nonce = std::move(nonce.value());
  row.aad.assign(aad_str.begin(), aad_str.end());
  row.ccache_blob_enc = std::move(enc.value());

  auto rc = ctx.vault.Insert(row);
  if (!rc.ok()) return core::Result<std::string>::Err(rc.status());
  return core::Result<std::string>::Ok(ticket_id);
}

}  // namespace gatehouse::app
