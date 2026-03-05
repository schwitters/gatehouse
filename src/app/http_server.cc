#include "app/http_server.h"

#include <cstdint>
#include <cstdlib>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "app/auth.h"
#include "core/crypto_aead.h"
#include "core/hex.h"
#include "core/random.h"
#include "core/time.h"
#include "core/url.h"
#include "crow.h"
#include "crow/json.h"
#include "infra/cred_fetch_token_repo.h"
#include "infra/session_repo.h"
#include "infra/sqlite_db.h"
#include "infra/ticket_vault_read.h"
#include "infra/ticket_vault_repo.h"
#include "infra/xrdp_otp_repo.h"

namespace gatehouse::core {

std::string Status::ToString() const {
  if (ok()) return "OK";
  return "ERR(" + std::to_string(static_cast<std::uint32_t>(code_)) + "): " + message_;
}

}  // namespace gatehouse::core

namespace gatehouse::app {
namespace {

constexpr const char* kHtmlLogin = R"(<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Gatehouse Login</title>
  <style>
    body{font-family:system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:40px;max-width:520px}
    label{display:block;margin-top:16px}
    input{width:100%;padding:10px;margin-top:6px}
    button{margin-top:16px;padding:10px 14px}
    .err{color:#b00020;margin-top:10px}
    .hint{color:#555;margin-top:8px;font-size:0.9em}
    code{background:#f4f4f4;padding:2px 6px;border-radius:6px}
  </style>
</head>
<body>
  <h1>Gatehouse</h1>
  <p class="hint">Temporary demo login: <code>demo</code> / <code>demo</code></p>

  <form method="post" action="/auth/login">
    <label>Username
      <input name="username" autocomplete="username" required>
    </label>
    <label>Password
      <input name="password" type="password" autocomplete="current-password" required>
    </label>
    <button type="submit">Sign in</button>
  </form>

  %ERROR%
</body>
</html>)";

std::string CookieValueFromHeader(const crow::request& req, const std::string& cookie_name) {
  const std::string cookie = req.get_header_value("Cookie");
  if (cookie.empty()) return {};
  const std::string needle = cookie_name + "=";
  const std::size_t pos = cookie.find(needle);
  if (pos == std::string::npos) return {};
  std::size_t start = pos + needle.size();
  std::size_t end = cookie.find(';', start);
  if (end == std::string::npos) end = cookie.size();
  return cookie.substr(start, end - start);
}

crow::response HtmlPage(int code, const std::string& html) {
  crow::response r;
  r.code = code;
  r.set_header("Content-Type", "text/html; charset=utf-8");
  r.body = html;
  return r;
}

crow::response RedirectTo(const std::string& where) {
  crow::response r;
  r.code = 302;
  r.set_header("Location", where);
  return r;
}

crow::response Json(int code, const crow::json::wvalue& v) {
  crow::response r;
  r.code = code;
  r.set_header("Content-Type", "application/json; charset=utf-8");
  r.body = v.dump();
  return r;
}

core::Result<std::vector<std::uint8_t>> LoadMasterKeyFromEnv() {
  const char* p = std::getenv("GATEHOUSE_MASTER_KEY_HEX");
  if (p == nullptr || std::string(p).empty()) {
    return core::Result<std::vector<std::uint8_t>>::Err(core::Status::Error(
        core::StatusCode::kFailedPrecondition,
        "GATEHOUSE_MASTER_KEY_HEX not set (need 64 hex chars for 32-byte key)"));
  }
  auto key = core::HexDecode(p);
  if (!key.ok()) return key;
  if (key.value().size() != 32) {
    return core::Result<std::vector<std::uint8_t>>::Err(core::Status::Error(
        core::StatusCode::kInvalidArgument,
        "GATEHOUSE_MASTER_KEY_HEX must decode to 32 bytes"));
  }
  return key;
}

core::Result<std::string> LoadInternalSecretFromEnv() {
  const char* p = std::getenv("GATEHOUSE_INTERNAL_SECRET");
  if (p == nullptr || std::string(p).empty()) {
    return core::Result<std::string>::Err(core::Status::Error(
        core::StatusCode::kFailedPrecondition,
        "GATEHOUSE_INTERNAL_SECRET not set (shared secret for internal XRDP endpoints)"));
  }
  return core::Result<std::string>::Ok(std::string(p));
}

core::Result<std::string> StoreTicketIfPresent(
    infra::TicketVaultRepo& vault,
    const std::vector<std::uint8_t>& master_key,
    const LoginPrincipal& principal) {
  if (principal.ccache_blob.empty()) return core::Result<std::string>::Ok(std::string{});

  auto ticket_id_bytes = core::RandomBytes(16);
  if (!ticket_id_bytes.ok()) return core::Result<std::string>::Err(ticket_id_bytes.status());
  const std::string ticket_id = core::HexEncode(ticket_id_bytes.value());

  auto nonce = core::RandomBytes(12);
  if (!nonce.ok()) return core::Result<std::string>::Err(nonce.status());

  const std::string aad_str = principal.uid + "|" + principal.tenant_id + "|" + ticket_id;
  auto enc = core::Aes256GcmEncrypt(master_key, nonce.value(), aad_str, principal.ccache_blob);
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

  auto rc = vault.Insert(row);
  if (!rc.ok()) return core::Result<std::string>::Err(rc.status());
  return core::Result<std::string>::Ok(ticket_id);
}

bool ConstantTimeEq(const std::string& a, const std::string& b) {
  if (a.size() != b.size()) return false;
  unsigned char v = 0;
  for (std::size_t i = 0; i < a.size(); ++i) v |= static_cast<unsigned char>(a[i] ^ b[i]);
  return v == 0;
}

}  // namespace

HttpServer::HttpServer(HttpServerConfig cfg, std::shared_ptr<infra::SqliteDb> db)
    : cfg_(std::move(cfg)), db_(std::move(db)) {}

core::Result<void> HttpServer::Run() {
  try {
    crow::SimpleApp app;
    app.loglevel(crow::LogLevel::Warning);

    if (db_ == nullptr || !db_->is_open()) {
      return core::Result<void>::Err(
          core::Status::Error(core::StatusCode::kFailedPrecondition, "DB not open"));
    }

    auto mk = LoadMasterKeyFromEnv();
    if (!mk.ok()) return core::Result<void>::Err(mk.status());
    const std::vector<std::uint8_t> master_key = std::move(mk.value());

    auto isec = LoadInternalSecretFromEnv();
    if (!isec.ok()) return core::Result<void>::Err(isec.status());
    const std::string internal_secret = std::move(isec.value());

    AuthService auth(cfg_.auth_cfg);

    infra::SessionRepo sessions(*db_);
    infra::TicketVaultRepo vault(*db_);
    infra::TicketVaultReadRepo vault_read(*db_);
    infra::CredFetchTokenRepo cft_repo(*db_);
    infra::XrdpOtpRepo xrdp_otp_repo(*db_);

    auto gc_sessions = [&sessions] { (void)sessions.DeleteExpired(core::UnixNow()); };

    auto require_auth = [&](const crow::request& req) -> std::optional<infra::SessionRow> {
      gc_sessions();
      const std::string sid = CookieValueFromHeader(req, cfg_.session_cookie_name);
      if (sid.empty()) return std::nullopt;
      auto got = sessions.GetBySid(sid);
      if (!got.ok() || !got.value().has_value()) return std::nullopt;
      const infra::SessionRow& row = *got.value();
      if (row.expires_at <= core::UnixNow()) return std::nullopt;
      return row;
    };

    // ---------------- Public ----------------
    CROW_ROUTE(app, "/favicon.ico").methods("GET"_method)([] { return crow::response(204); });

    CROW_ROUTE(app, "/healthz").methods("GET"_method)([this] {
      crow::json::wvalue v;
      v["status"] = "ok";
      v["db"] = (db_ != nullptr) && db_->is_open();
      return Json(200, v);
    });

    CROW_ROUTE(app, "/api/healthz").methods("GET"_method)([this] {
      crow::json::wvalue v;
      v["status"] = "ok";
      v["db"] = (db_ != nullptr) && db_->is_open();
      return Json(200, v);
    });

    CROW_ROUTE(app, "/login").methods("GET"_method)([](const crow::request& req) {
      const std::string err = req.url_params.get("err") ? req.url_params.get("err") : "";
      std::string page = kHtmlLogin;
      if (!err.empty()) {
        const std::string block = std::string("<div class=\"err\">") + crow::json::escape(err) + "</div>";
        const std::size_t pos = page.find("%ERROR%");
        if (pos != std::string::npos) page.replace(pos, 7, block);
      } else {
        const std::size_t pos = page.find("%ERROR%");
        if (pos != std::string::npos) page.replace(pos, 7, "");
      }
      return HtmlPage(200, page);
    });

    CROW_ROUTE(app, "/auth/logout").methods("POST"_method)([&](const crow::request& req) {
      const std::string sid = CookieValueFromHeader(req, cfg_.session_cookie_name);
      if (!sid.empty()) (void)sessions.DeleteBySid(sid);
      crow::response r = RedirectTo("/login");
      r.add_header("Set-Cookie", cfg_.session_cookie_name + "=deleted; Path=/; Max-Age=0; HttpOnly; SameSite=Lax");
      return r;
    });

    CROW_ROUTE(app, "/auth/login").methods("POST"_method)([&](const crow::request& req) {
      const std::optional<std::string> u = core::FormGet(req.body, "username");
      const std::optional<std::string> p = core::FormGet(req.body, "password");

      LoginRequest lr;
      lr.username = u.value_or("");
      lr.password = p.value_or("");

      auto vr = auth.Verify(lr);
      if (!vr.ok() || !vr.value().has_value()) return RedirectTo("/login?err=Invalid+credentials");
      const LoginPrincipal& principal = *vr.value();

      auto ticket_id = StoreTicketIfPresent(vault, master_key, principal);
      if (!ticket_id.ok()) return RedirectTo("/login?err=Internal+error");

      auto sid_bytes = core::RandomBytes(32);
      auto csrf_bytes = core::RandomBytes(32);
      if (!sid_bytes.ok() || !csrf_bytes.ok()) return RedirectTo("/login?err=Internal+error");

      infra::SessionRow row;
      row.sid = core::HexEncode(sid_bytes.value());
      row.uid = principal.uid;
      row.tenant_id = principal.tenant_id;
      row.created_at = core::UnixNow();
      row.expires_at = row.created_at + cfg_.session_ttl_seconds;
      row.mfa_state = 0;
      row.ticket_id = ticket_id.value();

      auto ins = sessions.Insert(row, csrf_bytes.value());
      if (!ins.ok()) return RedirectTo("/login?err=Internal+error");

      crow::response r = RedirectTo("/portal");
      r.add_header("Set-Cookie",
                   cfg_.session_cookie_name + "=" + row.sid +
                       "; Path=/; Max-Age=" + std::to_string(cfg_.session_ttl_seconds) +
                       "; HttpOnly; SameSite=Lax");
      return r;
    });

    // ---------------- Protected UI ----------------
    CROW_ROUTE(app, "/portal").methods("GET"_method)([&](const crow::request& req) {
      auto s = require_auth(req);
      if (!s.has_value()) return RedirectTo("/login");
      crow::response r;
      r.code = 200;
      r.set_header("Content-Type", "text/html; charset=utf-8");
      r.body =
          "<!doctype html><html><head><meta charset=\"utf-8\"><title>Gatehouse</title></head>"
          "<body><h1>Gatehouse Portal</h1>"
          "<p>Signed in as <b>" + crow::json::escape(s->uid) + "</b></p>"
          "<p>Session ticket_id: <code>" + crow::json::escape(s->ticket_id) + "</code></p>"
          "<form method=\"post\" action=\"/auth/logout\"><button type=\"submit\">Logout</button></form>"
          "<p>New: XRDP OTP Gate -> <code>/api/portal/connect</code> returns otp + fetch token.</p>"
          "</body></html>";
      return r;
    });

    CROW_ROUTE(app, "/").methods("GET"_method)([&](const crow::request& req) {
      auto s = require_auth(req);
      if (!s.has_value()) return RedirectTo("/login");
      return RedirectTo("/portal");
    });

    // ---------------- JSON API ----------------
    CROW_ROUTE(app, "/api/me").methods("GET"_method)([&](const crow::request& req) {
      auto s = require_auth(req);
      if (!s.has_value()) {
        crow::json::wvalue v;
        v["ok"] = false;
        v["error"] = "unauthenticated";
        return Json(401, v);
      }
      crow::json::wvalue v;
      v["ok"] = true;
      v["uid"] = s->uid;
      v["tenant_id"] = s->tenant_id;
      v["expires_at"] = s->expires_at;
      v["ticket_id"] = s->ticket_id;
      return Json(200, v);
    });

    // Login (JSON)
    CROW_ROUTE(app, "/api/auth/login").methods("POST"_method)([&](const crow::request& req) {
      auto body = crow::json::load(req.body);
      if (!body) {
        crow::json::wvalue v;
        v["ok"] = false;
        v["error"] = "invalid json";
        return Json(400, v);
      }

      LoginRequest lr;
      if (body.has("username")) lr.username = std::string(body["username"].s());
      if (body.has("password")) lr.password = std::string(body["password"].s());

      auto vr = auth.Verify(lr);
      if (!vr.ok() || !vr.value().has_value()) {
        crow::json::wvalue v;
        v["ok"] = false;
        v["error"] = "invalid credentials";
        return Json(401, v);
      }
      const LoginPrincipal& principal = *vr.value();

      auto ticket_id = StoreTicketIfPresent(vault, master_key, principal);
      if (!ticket_id.ok()) {
        crow::json::wvalue v;
        v["ok"] = false;
        v["error"] = "internal error";
        return Json(500, v);
      }

      auto sid_bytes = core::RandomBytes(32);
      auto csrf_bytes = core::RandomBytes(32);
      if (!sid_bytes.ok() || !csrf_bytes.ok()) {
        crow::json::wvalue v;
        v["ok"] = false;
        v["error"] = "internal error";
        return Json(500, v);
      }

      infra::SessionRow row;
      row.sid = core::HexEncode(sid_bytes.value());
      row.uid = principal.uid;
      row.tenant_id = principal.tenant_id;
      row.created_at = core::UnixNow();
      row.expires_at = row.created_at + cfg_.session_ttl_seconds;
      row.mfa_state = 0;
      row.ticket_id = ticket_id.value();

      auto ins = sessions.Insert(row, csrf_bytes.value());
      if (!ins.ok()) {
        crow::json::wvalue v;
        v["ok"] = false;
        v["error"] = "internal error";
        return Json(500, v);
      }

      crow::json::wvalue v;
      v["ok"] = true;
      v["uid"] = row.uid;
      v["tenant_id"] = row.tenant_id;
      v["expires_at"] = row.expires_at;
      v["ticket_id"] = row.ticket_id;

      auto resp = Json(200, v);
      resp.add_header("Set-Cookie",
                      cfg_.session_cookie_name + "=" + row.sid +
                          "; Path=/; Max-Age=" + std::to_string(cfg_.session_ttl_seconds) +
                          "; HttpOnly; SameSite=Lax");
      return resp;
    });

    CROW_ROUTE(app, "/api/auth/logout").methods("POST"_method)([&](const crow::request& req) {
      const std::string sid = CookieValueFromHeader(req, cfg_.session_cookie_name);
      if (!sid.empty()) (void)sessions.DeleteBySid(sid);

      crow::json::wvalue v;
      v["ok"] = true;

      auto resp = Json(200, v);
      resp.add_header("Set-Cookie",
                      cfg_.session_cookie_name + "=deleted; Path=/; Max-Age=0; HttpOnly; SameSite=Lax");
      return resp;
    });

    // Connect Desktop:
    // - creates XRDP OTP (one-time)
    // - creates Kerberos fetch token (one-time)
    // Input: { "host_id": "xrdp-u-1234" }
    // Output: { ok, uid, host_id, otp, otp_expires_at, token, token_expires_at }
    CROW_ROUTE(app, "/api/portal/connect").methods("POST"_method)([&](const crow::request& req) {
      auto s = require_auth(req);
      if (!s.has_value()) {
        crow::json::wvalue v;
        v["ok"] = false;
        v["error"] = "unauthenticated";
        return Json(401, v);
      }
      if (s->ticket_id.empty()) {
        crow::json::wvalue v;
        v["ok"] = false;
        v["error"] = "no kerberos ticket in session (need --auth krb5)";
        return Json(409, v);
      }

      auto body = crow::json::load(req.body);
      if (!body || !body.has("host_id")) {
        crow::json::wvalue v;
        v["ok"] = false;
        v["error"] = "invalid json (need host_id)";
        return Json(400, v);
      }
      const std::string host_id = std::string(body["host_id"].s());
      if (host_id.empty()) {
        crow::json::wvalue v;
        v["ok"] = false;
        v["error"] = "host_id empty";
        return Json(400, v);
      }

      const std::int64_t now = core::UnixNow();

      // XRDP OTP: 16 bytes -> hex, TTL 60s
      auto otp_bytes = core::RandomBytes(16);
      auto otp_id_bytes = core::RandomBytes(16);
      if (!otp_bytes.ok() || !otp_id_bytes.ok()) {
        crow::json::wvalue v;
        v["ok"] = false;
        v["error"] = "internal error";
        return Json(500, v);
      }
      const std::string otp_hex = core::HexEncode(otp_bytes.value());
      const std::string xrdp_otp_id = core::HexEncode(otp_id_bytes.value());
      const std::int64_t otp_exp = now + 60;

      infra::XrdpOtpRow otp_row;
      otp_row.xrdp_otp_id = xrdp_otp_id;
      otp_row.uid = s->uid;
      otp_row.tenant_id = s->tenant_id;
      otp_row.host_id = host_id;
      otp_row.otp_hash = otp_bytes.value();  // NOTE: treat as hash for now
      otp_row.issued_at = now;
      otp_row.expires_at = otp_exp;
      otp_row.max_attempts = 3;
      otp_row.attempts = 0;
      otp_row.issued_by_sid = s->sid;
      otp_row.ticket_id = s->ticket_id;

      auto ins_otp = xrdp_otp_repo.Insert(otp_row);
      if (!ins_otp.ok()) {
        crow::json::wvalue v;
        v["ok"] = false;
        v["error"] = "internal error";
        return Json(500, v);
      }

      // Credential fetch token: 32 bytes -> hex, TTL 120s
      auto tok_bytes = core::RandomBytes(32);
      auto id_bytes = core::RandomBytes(16);
      if (!tok_bytes.ok() || !id_bytes.ok()) {
        crow::json::wvalue v;
        v["ok"] = false;
        v["error"] = "internal error";
        return Json(500, v);
      }
      const std::string token_hex = core::HexEncode(tok_bytes.value());
      const std::string cft_id = core::HexEncode(id_bytes.value());
      const std::int64_t tok_exp = now + 120;

      infra::CredFetchTokenRow trow;
      trow.cft_id = cft_id;
      trow.uid = s->uid;
      trow.tenant_id = s->tenant_id;
      trow.host_id = host_id;
      trow.token_hash = tok_bytes.value();  // NOTE: treat as hash for now
      trow.issued_at = now;
      trow.expires_at = tok_exp;
      trow.ticket_id = s->ticket_id;

      auto ins = cft_repo.Insert(trow);
      if (!ins.ok()) {
        crow::json::wvalue v;
        v["ok"] = false;
        v["error"] = "internal error";
        return Json(500, v);
      }

      crow::json::wvalue v;
      v["ok"] = true;
      v["uid"] = s->uid;
      v["host_id"] = host_id;
      v["otp"] = otp_hex;
      v["otp_expires_at"] = otp_exp;
      v["token"] = token_hex;
      v["token_expires_at"] = tok_exp;
      return Json(200, v);
    });

    // XRDP OTP verify (internal): PAM helper will call this.
    // Header: X-Gatehouse-Internal-Secret: <GATEHOUSE_INTERNAL_SECRET>
    // Input JSON: { "uid":"...", "host_id":"...", "otp":"<hex>" }
    // Output JSON: { ok:true } or 401/403/400
    CROW_ROUTE(app, "/xrdp/otp/verify").methods("POST"_method)([&](const crow::request& req) {
      const std::string hdr = req.get_header_value("X-Gatehouse-Internal-Secret");
      if (hdr.empty() || !ConstantTimeEq(hdr, internal_secret)) {
        crow::json::wvalue v;
        v["ok"] = false;
        v["error"] = "forbidden";
        return Json(403, v);
      }

      auto body = crow::json::load(req.body);
      if (!body || !body.has("uid") || !body.has("host_id") || !body.has("otp")) {
        crow::json::wvalue v;
        v["ok"] = false;
        v["error"] = "invalid json";
        return Json(400, v);
      }

      const std::string uid = std::string(body["uid"].s());
      const std::string host_id = std::string(body["host_id"].s());
      const std::string otp_hex = std::string(body["otp"].s());

      auto otp_bytes = core::HexDecode(otp_hex);
      if (!otp_bytes.ok()) {
        crow::json::wvalue v;
        v["ok"] = false;
        v["error"] = "invalid otp";
        return Json(400, v);
      }

      const std::int64_t now = core::UnixNow();
      auto ok = xrdp_otp_repo.VerifyAndConsume(uid, host_id, otp_bytes.value(), now);
      if (!ok.ok()) {
        crow::json::wvalue v;
        v["ok"] = false;
        v["error"] = "internal error";
        return Json(500, v);
      }
      if (!ok.value()) {
        crow::json::wvalue v;
        v["ok"] = false;
        v["error"] = "unauthorized";
        return Json(401, v);
      }

      crow::json::wvalue v;
      v["ok"] = true;
      return Json(200, v);
    });

    // Kerberos ticket fetch (internal) – unchanged
    CROW_ROUTE(app, "/xrdp/krb/fetch").methods("POST"_method)([&](const crow::request& req) {
      const std::string hdr = req.get_header_value("X-Gatehouse-Internal-Secret");
      if (hdr.empty() || !ConstantTimeEq(hdr, internal_secret)) {
        crow::json::wvalue v;
        v["ok"] = false;
        v["error"] = "forbidden";
        return Json(403, v);
      }

      auto body = crow::json::load(req.body);
      if (!body || !body.has("uid") || !body.has("host_id") || !body.has("token")) {
        crow::json::wvalue v;
        v["ok"] = false;
        v["error"] = "invalid json";
        return Json(400, v);
      }

      const std::string uid = std::string(body["uid"].s());
      const std::string host_id = std::string(body["host_id"].s());
      const std::string token_hex = std::string(body["token"].s());

      auto token_bytes = core::HexDecode(token_hex);
      if (!token_bytes.ok()) {
        crow::json::wvalue v;
        v["ok"] = false;
        v["error"] = "invalid token";
        return Json(400, v);
      }

      const std::int64_t now = core::UnixNow();
      auto ticket_id = cft_repo.VerifyAndConsume(uid, host_id, token_bytes.value(), now);
      if (!ticket_id.ok()) {
        crow::json::wvalue v;
        v["ok"] = false;
        v["error"] = "internal error";
        return Json(500, v);
      }
      if (!ticket_id.value().has_value()) {
        crow::json::wvalue v;
        v["ok"] = false;
        v["error"] = "unauthorized";
        return Json(401, v);
      }

      auto tv = vault_read.GetById(*ticket_id.value());
      if (!tv.ok() || !tv.value().has_value()) {
        crow::json::wvalue v;
        v["ok"] = false;
        v["error"] = "not found";
        return Json(404, v);
      }

      const infra::TicketVaultReadRow& row = *tv.value();
      if (row.expires_at <= now) {
        crow::json::wvalue v;
        v["ok"] = false;
        v["error"] = "ticket expired";
        return Json(401, v);
      }

      const std::string aad_str(row.aad.begin(), row.aad.end());
      auto pt = core::Aes256GcmDecrypt(master_key, row.nonce, aad_str, row.ccache_blob_enc);
      if (!pt.ok()) {
        crow::json::wvalue v;
        v["ok"] = false;
        v["error"] = "decrypt failed";
        return Json(401, v);
      }

      crow::response r;
      r.code = 200;
      r.set_header("Content-Type", "application/octet-stream");
      r.body.assign(reinterpret_cast<const char*>(pt.value().data()),
                    reinterpret_cast<const char*>(pt.value().data() + pt.value().size()));
      return r;
    });

    app.bindaddr(cfg_.bind_addr)
        .port(static_cast<std::uint16_t>(cfg_.port))
        .concurrency(cfg_.threads)
        .run();

    return core::Result<void>::Ok();
  } catch (...) {
    return core::Result<void>::Err(
        core::Status::Error(core::StatusCode::kInternal, "HTTP server crashed"));
  }
}

}  // namespace gatehouse::app
