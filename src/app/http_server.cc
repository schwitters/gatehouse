#include "app/http_server.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "app/auth.h"
#include "app/email_sender.h"
#include "core/crypto_aead.h"
#include "core/hex.h"
#include "core/random.h"
#include "core/sha256.h"
#include "core/time.h"
#include "core/url.h"
#include "crow.h"
#include "crow/json.h"
#include "infra/invite_repo.h"
#include "infra/invite_session_repo.h"
#include "infra/invite_otp_repo.h"
#include "infra/ldap_directory.h"
#include "infra/ldif_directory.h"
#include "infra/session_repo.h"
#include "infra/sqlite_db.h"
#include "infra/ticket_vault_repo.h"

namespace gatehouse::core {
std::string Status::ToString() const {
  if (ok()) return "OK";
  return "ERR(" + std::to_string(static_cast<std::uint32_t>(code_)) + "): " + message_;
}
}  // namespace gatehouse::core

namespace gatehouse::app {
namespace {

constexpr const char* kInviteCookie = "gh_inv_sid";

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

bool IsAdminUid(const std::vector<std::string>& allow, const std::string& uid) {
  for (const auto& a : allow) {
    if (a == uid) return true;
  }
  return false;
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

core::Result<std::string> StoreTicketIfPresent(infra::TicketVaultRepo& vault,
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

std::string InviteStatusName(infra::InviteStatus s) {
  switch (s) {
    case infra::InviteStatus::kInvited: return "Invited";
    case infra::InviteStatus::kLinkVerified: return "LinkVerified";
    case infra::InviteStatus::kStepupSent: return "StepupSent";
    case infra::InviteStatus::kStepupVerified: return "StepupVerified";
    case infra::InviteStatus::kCompleted: return "Completed";
    case infra::InviteStatus::kExpired: return "Expired";
    case infra::InviteStatus::kRevoked: return "Revoked";
  }
  return "Unknown";
}

const char* kLoginPageTemplate = R"LOGIN(<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Gatehouse Login</title>
<style>
body{font-family:system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:40px;max-width:640px}
label{display:block;margin-top:16px} input{width:100%;padding:10px;margin-top:6px}
button{margin-top:16px;padding:10px 14px}
.err{color:#b00020;margin-top:10px}
.hint{color:#555;margin-top:8px;font-size:0.9em}
code{background:#f4f4f4;padding:2px 6px;border-radius:6px}
</style></head>
<body>
<h1>Gatehouse</h1>
<p class="hint">Temporary demo login: <code>demo</code> / <code>demo</code></p>
<form method="post" action="/auth/login">
  <label>Username <input name="username" autocomplete="username" required></label>
  <label>Password <input name="password" type="password" autocomplete="current-password" required></label>
  <button type="submit">Sign in</button>
</form>
%ERROR%
</body></html>)LOGIN";

const char* kAdminInvitesPage = R"ADMIN(<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Gatehouse Admin – Invitations</title>
  <style>
    body{font-family:system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:40px;max-width:980px}
    label{display:block;margin-top:14px}
    input{width:100%;padding:10px;margin-top:6px}
    button{margin-top:12px;padding:10px 14px}
    .row{display:grid;grid-template-columns:1fr 1fr;gap:16px}
    .card{padding:16px;border:1px solid #ddd;border-radius:12px;margin-top:18px}
    code{background:#f4f4f4;padding:2px 6px;border-radius:6px}
    pre{background:#0b1020;color:#e6e6e6;padding:12px;border-radius:12px;overflow:auto}
    .ok{color:#0a7a2f}
    .err{color:#b00020}
    a{color:#0b57d0}
    table{width:100%;border-collapse:collapse}
    th,td{padding:8px;border-bottom:1px solid #eee;text-align:left;font-size:14px}
    th{font-weight:600}
    .pill{display:inline-block;padding:2px 8px;border-radius:999px;background:#f4f4f4}
  </style>
</head>
<body>
  <h1>Invitations</h1>
  <p><a href="/portal">Back to portal</a></p>

  <div class="card">
    <h2>Create invite</h2>
    <div class="row">
      <div>
        <label>Tenant OU (e.g. <code>k8s-20260118</code>)
          <input id="tenant_ou" placeholder="k8s-20260118" autocomplete="off">
        </label>
      </div>
      <div>
        <label>User UID (e.g. <code>krm</code>)
          <input id="uid" placeholder="krm" autocomplete="off">
        </label>
      </div>
    </div>
    <button id="btnCreate">Create invite</button>
    <p id="statusCreate"></p>
    <div id="outCreate"></div>
  </div>

  <div class="card">
    <h2>Latest invites</h2>
    <div class="row">
      <div>
        <label>Filter tenant_ou
          <input id="fltTenant" placeholder="(optional)">
        </label>
      </div>
      <div>
        <label>Filter uid
          <input id="fltUid" placeholder="(optional)">
        </label>
      </div>
    </div>
    <button id="btnRefresh">Refresh list</button>
    <p id="statusList"></p>
    <div id="list"></div>
  </div>

<script>
async function apiJson(method, path, body) {
  const opt = {method, headers: {"Content-Type":"application/json"}};
  if (body !== undefined) opt.body = JSON.stringify(body);
  const r = await fetch(path, opt);
  const t = await r.text();
  let j = null;
  try { j = JSON.parse(t); } catch(e) {}
  return {ok: r.ok, status: r.status, json: j, text: t};
}

function setStatus(id, kind, msg) {
  const el = document.getElementById(id);
  el.className = kind;
  el.textContent = msg;
}

function renderJson(where, obj) {
  const out = document.getElementById(where);
  out.innerHTML = "";
  const pre = document.createElement("pre");
  pre.textContent = JSON.stringify(obj, null, 2);
  out.appendChild(pre);
  if (obj && obj.invite_url) {
    const p = document.createElement("p");
    const a = document.createElement("a");
    a.href = obj.invite_url;
    a.textContent = "Open invite link";
    a.target = "_blank";
    p.appendChild(a);
    out.appendChild(p);
  }
}

function renderList(items) {
  const root = document.getElementById("list");
  root.innerHTML = "";
  if (!items || items.length === 0) {
    root.textContent = "No invites.";
    return;
  }
  const table = document.createElement("table");
  const thead = document.createElement("thead");
  thead.innerHTML = "<tr><th>created</th><th>tenant</th><th>uid</th><th>email</th><th>status</th><th>expires</th><th>actions</th></tr>";
  table.appendChild(thead);
  const tbody = document.createElement("tbody");
  for (const it of items) {
    const tr = document.createElement("tr");
    const created = new Date(it.created_at * 1000).toLocaleString();
    const expires = new Date(it.expires_at * 1000).toLocaleString();
    tr.innerHTML =
      "<td>" + created + "</td>" +
      "<td><code>" + it.tenant_id + "</code></td>" +
      "<td><code>" + (it.invited_uid||"") + "</code></td>" +
      "<td>" + it.invited_email + "</td>" +
      "<td><span class='pill'>" + it.status_name + "</span></td>" +
      "<td>" + expires + "</td>" +
      "<td></td>";
    const td = tr.querySelectorAll("td")[6];

    const btnRevoke = document.createElement("button");
    btnRevoke.textContent = "Revoke";
    btnRevoke.style.marginRight = "8px";
    btnRevoke.onclick = async () => {
      const r = await apiJson("POST", "/api/admin/invites/revoke", {invite_id: it.invite_id});
      if (!r.ok) { alert("Revoke failed: " + (r.json && r.json.error ? r.json.error : r.text)); return; }
      await refresh();
    };
    td.appendChild(btnRevoke);

    const btnResend = document.createElement("button");
    btnResend.textContent = "Resend (new invite)";
    btnResend.onclick = async () => {
      const r = await apiJson("POST", "/api/admin/invites", {tenant_ou: it.tenant_id, uid: it.invited_uid});
      if (!r.ok) { alert("Resend failed: " + (r.json && r.json.error ? r.json.error : r.text)); return; }
      renderJson("outCreate", r.json || {});
      setStatus("statusCreate", "ok", "Resent as new invite.");
      await refresh();
    };
    td.appendChild(btnResend);

    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  root.appendChild(table);
}

async function refresh() {
  setStatus("statusList", "", "Loading...");
  const t = document.getElementById("fltTenant").value.trim();
  const u = document.getElementById("fltUid").value.trim();
  const q = new URLSearchParams();
  if (t) q.set("tenant_id", t);
  if (u) q.set("invited_uid", u);
  const r = await fetch("/api/admin/invites/list?" + q.toString());
  const j = await r.json().catch(() => null);
  if (!r.ok) {
    setStatus("statusList", "err", "Error (" + r.status + ")");
    return;
  }
  setStatus("statusList", "ok", "Loaded " + (j.items ? j.items.length : 0) + " invite(s).");
  renderList(j.items || []);
}

document.getElementById("btnCreate").addEventListener("click", async () => {
  const tenant_ou = document.getElementById("tenant_ou").value.trim();
  const uid = document.getElementById("uid").value.trim();
  if (!tenant_ou || !uid) { setStatus("statusCreate","err","tenant_ou and uid are required"); return; }
  setStatus("statusCreate","", "Working...");
  const r = await apiJson("POST", "/api/admin/invites", {tenant_ou, uid});
  if (!r.ok) {
    setStatus("statusCreate","err","Error ("+r.status+"): " + (r.json && r.json.error ? r.json.error : r.text));
    if (r.json) renderJson("outCreate", r.json);
    return;
  }
  setStatus("statusCreate","ok","Invite created and email queued/sent.");
  renderJson("outCreate", r.json || {});
  await refresh();
});

document.getElementById("btnRefresh").addEventListener("click", refresh);
refresh();
</script>
</body>
</html>)ADMIN";

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

    // Directory (LDAP preferred)
    std::optional<infra::LdapDirectory> ldap_dir;
    infra::LdifDirectory ldif_dir;
    if (!cfg_.ldap_url.empty()) {
      infra::LdapConfig lc;
      lc.url = cfg_.ldap_url;
      lc.bind_dn = cfg_.ldap_bind_dn;
      lc.bind_pw = cfg_.ldap_bind_pw;
      lc.base_dn = cfg_.ldap_base_dn;
      lc.starttls = cfg_.ldap_starttls;
      ldap_dir.emplace(lc);
    } else if (!cfg_.ldif_path.empty()) {
      auto rc = ldif_dir.LoadFile(cfg_.ldif_path);
      if (!rc.ok()) return core::Result<void>::Err(rc.status());
    }

    std::unique_ptr<IEmailSender> email;
    if (cfg_.email_backend == "curl") {
      email = std::make_unique<CurlSmtpsEmailSender>();
    } else {
      email = std::make_unique<ConsoleEmailSender>();
    }

    AuthService auth(cfg_.auth_cfg);

    infra::SessionRepo sessions(*db_);
    infra::TicketVaultRepo vault(*db_);
    infra::InviteRepo invites(*db_);
    infra::InviteSessionRepo invite_sessions(*db_);
    infra::InviteProfileRepo invite_profiles(*db_);
    infra::InviteOtpRepo invite_otps(*db_);

    auto gc_sessions = [&] {
      (void)sessions.DeleteExpired(core::UnixNow());
      (void)invite_sessions.DeleteExpired(core::UnixNow());
    };

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

    auto require_invite_session = [&](const crow::request& req) -> std::optional<infra::InviteSessionRow> {
      gc_sessions();
      const std::string sid = CookieValueFromHeader(req, kInviteCookie);
      if (sid.empty()) return std::nullopt;
      auto got = invite_sessions.GetBySid(sid);
      if (!got.ok() || !got.value().has_value()) return std::nullopt;
      const infra::InviteSessionRow& row = *got.value();
      if (row.expires_at <= core::UnixNow()) return std::nullopt;
      if (row.consumed_at != 0) return std::nullopt;
      return row;
    };

    // ---- health ----
    CROW_ROUTE(app, "/api/healthz").methods("GET"_method)([this] {
      crow::json::wvalue v;
      v["status"] = "ok";
      v["db"] = (db_ != nullptr) && db_->is_open();
      return Json(200, v);
    });

    // ---- HTML login ----
    CROW_ROUTE(app, "/login").methods("GET"_method)([](const crow::request& req) {
      const std::string err = req.url_params.get("err") ? req.url_params.get("err") : "";
      std::string page = kLoginPageTemplate;
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
      auto r = RedirectTo("/login");
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

      auto r = RedirectTo("/portal");
      r.add_header("Set-Cookie",
                   cfg_.session_cookie_name + "=" + row.sid +
                       "; Path=/; Max-Age=" + std::to_string(cfg_.session_ttl_seconds) +
                       "; HttpOnly; SameSite=Lax");
      return r;
    });

    // ---- portal ----
    CROW_ROUTE(app, "/portal").methods("GET"_method)([&](const crow::request& req) {
      auto s = require_auth(req);
      if (!s.has_value()) return RedirectTo("/login");

      const bool is_admin = IsAdminUid(cfg_.admin_uids, s->uid);
      std::string admin_block;
      if (is_admin) {
        admin_block = "<p><b>Admin</b>: <a href=\"/admin/invites\">Create & manage invitations</a></p>";
      }

      const std::string html =
          "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
          "<title>Gatehouse</title></head>"
          "<body style=\"font-family:system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:40px;max-width:760px\">"
          "<h1>Gatehouse Portal</h1>"
          "<p>Signed in as <b>" + crow::json::escape(s->uid) + "</b></p>"
          "<p>Tenant: <b>" + crow::json::escape(s->tenant_id) + "</b></p>" +
          admin_block +
          "<form method=\"post\" action=\"/auth/logout\"><button type=\"submit\" style=\"padding:10px 14px\">Logout</button></form>"
          "</body></html>";
      return HtmlPage(200, html);
    });

    CROW_ROUTE(app, "/").methods("GET"_method)([&](const crow::request& req) {
      auto s = require_auth(req);
      if (!s.has_value()) return RedirectTo("/login");
      return RedirectTo("/portal");
    });

    // ---- admin ui ----
    CROW_ROUTE(app, "/admin/invites").methods("GET"_method)([&](const crow::request& req) {
      auto s = require_auth(req);
      if (!s.has_value()) return RedirectTo("/login");
      if (!IsAdminUid(cfg_.admin_uids, s->uid)) return HtmlPage(403, "<h1>Forbidden</h1>");
      return HtmlPage(200, kAdminInvitesPage);
    });

    // ---- invite accept -> invite_session cookie -> /invite/complete ----
    CROW_ROUTE(app, "/invite/accept").methods("GET"_method)([&](const crow::request& req) {
      const char* t = req.url_params.get("token");
      if (t == nullptr) return HtmlPage(400, "<h1>Invalid invitation</h1>");
      const std::string token_hex = t;

      auto token_bytes = core::HexDecode(token_hex);
      if (!token_bytes.ok()) return HtmlPage(400, "<h1>Invalid invitation token</h1>");

      auto hash = core::Sha256(token_bytes.value());
      if (!hash.ok()) return HtmlPage(500, "<h1>Internal error</h1>");

      auto row = invites.GetByTokenHash(hash.value());
      if (!row.ok() || !row.value().has_value()) return HtmlPage(404, "<h1>Invitation not found</h1>");

      const auto now = core::UnixNow();
      const auto& inv = *row.value();

      if (inv.revoked_at != 0 || inv.status == infra::InviteStatus::kRevoked) return HtmlPage(410, "<h1>Invitation revoked</h1>");
      if (inv.expires_at <= now) return HtmlPage(410, "<h1>Invitation expired</h1>");

      (void)invites.UpdateStatus(inv.invite_id, infra::InviteStatus::kLinkVerified, now);

      auto sid_bytes = core::RandomBytes(32);
      if (!sid_bytes.ok()) return HtmlPage(500, "<h1>Internal error</h1>");

      infra::InviteSessionRow s;
      s.sid = core::HexEncode(sid_bytes.value());
      s.invite_id = inv.invite_id;
      s.created_at = now;
      s.expires_at = now + 1800;

      auto ins = invite_sessions.Insert(s);
      if (!ins.ok()) return HtmlPage(500, "<h1>Internal error</h1>");

      auto r = RedirectTo("/invite/complete");
      r.add_header("Set-Cookie", std::string(kInviteCookie) + "=" + s.sid +
                                "; Path=/; Max-Age=1800; HttpOnly; SameSite=Lax");
      return r;
    });

    // ---- invite complete GET/POST ----

    // ---- invite complete GET (with email OTP step-up) ----
    CROW_ROUTE(app, "/invite/complete").methods("GET"_method)([&](const crow::request& req) {
      auto is = require_invite_session(req);
      if (!is.has_value()) return HtmlPage(401, "<h1>Invitation session expired</h1><p>Please open your invite link again.</p>");

      auto inv = invites.GetById(is->invite_id);
      if (!inv.ok() || !inv.value().has_value()) return HtmlPage(404, "<h1>Invitation not found</h1>");
      const auto& row = *inv.value();
      if (row.status == infra::InviteStatus::kRevoked) return HtmlPage(410, "<h1>Invitation revoked</h1>");

      auto prof = invite_profiles.GetByInviteId(row.invite_id);
      std::string display;
      if (prof.ok() && prof.value().has_value()) display = prof.value()->display_name;

      const bool verified = invite_otps.IsVerified(is->sid).ok() ? invite_otps.IsVerified(is->sid).value() : false;

      const std::string sent = req.url_params.get("sent") ? req.url_params.get("sent") : "";
      const std::string err = req.url_params.get("err") ? req.url_params.get("err") : "";
      const std::string ok = req.url_params.get("ok") ? req.url_params.get("ok") : "";

      std::string msg;
      if (!err.empty()) msg = "<p style='color:#b00020'>Error: " + crow::json::escape(err) + "</p>";
      else if (!ok.empty()) msg = "<p style='color:#0a7a2f'>Verified.</p>";
      else if (!sent.empty()) msg = "<p style='color:#555'>Code sent. Check your email.</p>";

      std::string html;
      html += "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'>";
      html += "<title>Complete invitation</title><style>";
      html += "body{font-family:system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:40px;max-width:760px}";
      html += "label{display:block;margin-top:14px} input{width:100%;padding:10px;margin-top:6px}";
      html += "button{margin-top:12px;padding:10px 14px} .card{padding:16px;border:1px solid #ddd;border-radius:12px}";
      html += ".muted{color:#555} code{background:#f4f4f4;padding:2px 6px;border-radius:6px}";
      html += "</style></head><body>";
      html += "<h1>Complete invitation</h1>";
      html += "<div class='card'>";
      html += "<p class='muted'>Tenant: <b>" + crow::json::escape(row.tenant_id) + "</b></p>";
      html += "<p class='muted'>User: <b>" + crow::json::escape(row.invited_uid) + "</b></p>";
      html += "<p class='muted'>Email: <b>" + crow::json::escape(row.invited_email) + "</b></p>";
      html += msg;

      if (!verified) {
        html += "<h3>Verify email</h3>";
        html += "<form method='post' action='/invite/otp/send'><button type='submit'>Send code</button></form>";
        html += "<form method='post' action='/invite/otp/verify'>";
        html += "<label>Code<input name='code' placeholder='123456' autocomplete='one-time-code'></label>";
        html += "<button type='submit'>Verify</button></form>";
      } else {
        html += "<h3>Profile</h3>";
        html += "<form method='post' action='/invite/complete'>";
        html += "<label>Display name (optional)<input name='display_name' value='" + crow::json::escape(display) + "'></label>";
        html += "<button type='submit'>Finish</button></form>";
      }

      html += "</div></body></html>";
      return HtmlPage(200, html);
    });

    CROW_ROUTE(app, "/invite/complete").methods("POST"_method)([&](const crow::request& req) {
      auto is = require_invite_session(req);
      if (!is.has_value()) return HtmlPage(401, "<h1>Invitation session expired</h1>");

      auto inv = invites.GetById(is->invite_id);
      if (!inv.ok() || !inv.value().has_value()) return HtmlPage(404, "<h1>Invitation not found</h1>");

      const auto now = core::UnixNow();
      const std::optional<std::string> dn = core::FormGet(req.body, "display_name");
      const std::string display = dn.value_or("");

      infra::InviteProfileRow pr;
      pr.invite_id = is->invite_id;
      pr.display_name = display;
      pr.created_at = now;
      pr.updated_at = now;

      (void)invite_profiles.Upsert(pr);
      (void)invites.UpdateStatus(is->invite_id, infra::InviteStatus::kCompleted, now);
      (void)invite_sessions.Consume(is->sid, now);

      auto r = HtmlPage(200, "<h1>Done</h1><p>Your invitation is completed.</p><p><a href=\"/login\">Login</a></p>");
      r.add_header("Set-Cookie", std::string(kInviteCookie) + "=deleted; Path=/; Max-Age=0; HttpOnly; SameSite=Lax");
      return r;
    });

    
    // ---- invite OTP step-up (email) ----
    CROW_ROUTE(app, "/invite/otp/send").methods("POST"_method)([&](const crow::request& req) {
      auto is = require_invite_session(req);
      if (!is.has_value()) return HtmlPage(401, "<h1>Invitation session expired</h1>");

      auto inv = invites.GetById(is->invite_id);
      if (!inv.ok() || !inv.value().has_value()) return HtmlPage(404, "<h1>Invitation not found</h1>");
      const auto& row = *inv.value();

      // Create 6-digit OTP.
      auto rnd = core::RandomBytes(4);
      if (!rnd.ok()) return HtmlPage(500, "<h1>Internal error</h1>");
      const unsigned int v = (static_cast<unsigned int>(rnd.value()[0]) << 24) |
                             (static_cast<unsigned int>(rnd.value()[1]) << 16) |
                             (static_cast<unsigned int>(rnd.value()[2]) << 8) |
                             (static_cast<unsigned int>(rnd.value()[3]) << 0);
      const unsigned int code = (v % 900000U) + 100000U;
      const std::string otp = std::to_string(code);

      // Hash OTP.
      std::vector<std::uint8_t> otp_bytes(otp.begin(), otp.end());
      auto h = core::Sha256(otp_bytes);
      if (!h.ok()) return HtmlPage(500, "<h1>Internal error</h1>");

      // Replace older OTPs for this sid.
      (void)invite_otps.DeleteBySid(is->sid);

      auto otp_id_bytes = core::RandomBytes(16);
      if (!otp_id_bytes.ok()) return HtmlPage(500, "<h1>Internal error</h1>");

      const std::int64_t now = core::UnixNow();
      infra::InviteOtpRow o;
      o.otp_id = core::HexEncode(otp_id_bytes.value());
      o.sid = is->sid;
      o.otp_hash = std::move(h.value());
      o.issued_at = now;
      o.expires_at = now + 600;  // 10 min
      o.attempts = 0;
      o.max_attempts = 5;

      auto ins = invite_otps.Insert(o);
      if (!ins.ok()) return HtmlPage(500, "<h1>Internal error</h1>");

      const std::string subject = "Gatehouse verification code";
      const std::string body_txt =
          "Your Gatehouse verification code is:\n\n" + otp + "\n\n"
          "It expires in 10 minutes.\n";

      auto mail_rc = email->SendText(row.invited_email, subject, body_txt);
      if (!mail_rc.ok()) return HtmlPage(502, "<h1>Mail send failed</h1>");

      return RedirectTo("/invite/complete?sent=1");
    });

    CROW_ROUTE(app, "/invite/otp/verify").methods("POST"_method)([&](const crow::request& req) {
      auto is = require_invite_session(req);
      if (!is.has_value()) return HtmlPage(401, "<h1>Invitation session expired</h1>");

      const std::optional<std::string> c = core::FormGet(req.body, "code");
      const std::string code = c.value_or("");
      if (code.size() < 4 || code.size() > 10) return RedirectTo("/invite/complete?err=invalid+code");

      std::vector<std::uint8_t> otp_bytes(code.begin(), code.end());
      auto h = core::Sha256(otp_bytes);
      if (!h.ok()) return HtmlPage(500, "<h1>Internal error</h1>");

      const std::int64_t now = core::UnixNow();
      auto ok = invite_otps.VerifyAndConsume(is->sid, h.value(), now);
      if (!ok.ok()) return HtmlPage(500, "<h1>Internal error</h1>");
      if (!ok.value()) return RedirectTo("/invite/complete?err=wrong+code");

      return RedirectTo("/invite/complete?ok=1");
    });

// ---- JSON auth + me ----
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
      return Json(200, v);
    });

    CROW_ROUTE(app, "/api/auth/login").methods("POST"_method)([&](const crow::request& req) {
      auto body = crow::json::load(req.body);
      if (!body) {
        crow::json::wvalue v; v["ok"]=false; v["error"]="invalid json"; return Json(400, v);
      }

      LoginRequest lr;
      if (body.has("username")) lr.username = std::string(body["username"].s());
      if (body.has("password")) lr.password = std::string(body["password"].s());

      auto vr = auth.Verify(lr);
      if (!vr.ok() || !vr.value().has_value()) {
        crow::json::wvalue v; v["ok"]=false; v["error"]="invalid credentials"; return Json(401, v);
      }

      const LoginPrincipal& principal = *vr.value();
      auto ticket_id = StoreTicketIfPresent(vault, master_key, principal);
      if (!ticket_id.ok()) {
        crow::json::wvalue v; v["ok"]=false; v["error"]="internal error"; return Json(500, v);
      }

      auto sid_bytes = core::RandomBytes(32);
      auto csrf_bytes = core::RandomBytes(32);
      if (!sid_bytes.ok() || !csrf_bytes.ok()) {
        crow::json::wvalue v; v["ok"]=false; v["error"]="internal error"; return Json(500, v);
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
        crow::json::wvalue v; v["ok"]=false; v["error"]="internal error"; return Json(500, v);
      }

      crow::json::wvalue v;
      v["ok"] = true;
      v["uid"] = row.uid;
      v["tenant_id"] = row.tenant_id;
      v["expires_at"] = row.expires_at;

      auto resp = Json(200, v);
      resp.add_header("Set-Cookie",
                      cfg_.session_cookie_name + "=" + row.sid +
                          "; Path=/; Max-Age=" + std::to_string(cfg_.session_ttl_seconds) +
                          "; HttpOnly; SameSite=Lax");
      return resp;
    });

    // ---- Admin APIs ----
    CROW_ROUTE(app, "/api/admin/invites/list").methods("GET"_method)([&](const crow::request& req) {
      auto s = require_auth(req);
      if (!s.has_value()) { crow::json::wvalue v; v["ok"]=false; v["error"]="unauthenticated"; return Json(401, v); }
      if (!IsAdminUid(cfg_.admin_uids, s->uid)) { crow::json::wvalue v; v["ok"]=false; v["error"]="forbidden"; return Json(403, v); }

      const std::string tenant = req.url_params.get("tenant_id") ? req.url_params.get("tenant_id") : "";
      const std::string uid = req.url_params.get("invited_uid") ? req.url_params.get("invited_uid") : "";

      auto rows = invites.ListLatest(50, tenant, uid);
      if (!rows.ok()) { crow::json::wvalue v; v["ok"]=false; v["error"]=rows.status().ToString(); return Json(500, v); }

      crow::json::wvalue v;
      v["ok"] = true;
      v["items"] = crow::json::wvalue::list();

      unsigned int idx = 0;
      for (const auto& r : rows.value()) {
        crow::json::wvalue it;
        it["invite_id"] = r.invite_id;
        it["tenant_id"] = r.tenant_id;
        it["invited_uid"] = r.invited_uid;
        it["invited_email"] = r.invited_email;
        it["status"] = static_cast<int>(r.status);
        it["status_name"] = InviteStatusName(r.status);
        it["created_at"] = r.created_at;
        it["expires_at"] = r.expires_at;
        it["revoked_at"] = r.revoked_at;
        it["created_by"] = r.created_by;
        v["items"][idx++] = std::move(it);
      }
      return Json(200, v);
    });

    CROW_ROUTE(app, "/api/admin/invites/revoke").methods("POST"_method)([&](const crow::request& req) {
      auto s = require_auth(req);
      if (!s.has_value()) { crow::json::wvalue v; v["ok"]=false; v["error"]="unauthenticated"; return Json(401, v); }
      if (!IsAdminUid(cfg_.admin_uids, s->uid)) { crow::json::wvalue v; v["ok"]=false; v["error"]="forbidden"; return Json(403, v); }

      auto body = crow::json::load(req.body);
      if (!body || !body.has("invite_id")) { crow::json::wvalue v; v["ok"]=false; v["error"]="invalid json (need invite_id)"; return Json(400, v); }
      const std::string invite_id = std::string(body["invite_id"].s());
      if (invite_id.empty()) { crow::json::wvalue v; v["ok"]=false; v["error"]="invite_id empty"; return Json(400, v); }

      auto rc = invites.Revoke(invite_id, core::UnixNow());
      if (!rc.ok()) { crow::json::wvalue v; v["ok"]=false; v["error"]=rc.status().ToString(); return Json(500, v); }
      crow::json::wvalue v; v["ok"]=true; return Json(200, v);
    });

    CROW_ROUTE(app, "/api/admin/invites").methods("POST"_method)([&](const crow::request& req) {
      try {
        auto s = require_auth(req);
        if (!s.has_value()) { crow::json::wvalue v; v["ok"]=false; v["error"]="unauthenticated"; return Json(401, v); }
        if (!IsAdminUid(cfg_.admin_uids, s->uid)) { crow::json::wvalue v; v["ok"]=false; v["error"]="forbidden"; return Json(403, v); }

        auto body = crow::json::load(req.body);
        if (!body || !body.has("tenant_ou") || !body.has("uid")) {
          crow::json::wvalue v; v["ok"]=false; v["error"]="invalid json (need tenant_ou, uid)"; return Json(400, v);
        }
        const std::string tenant_ou = std::string(body["tenant_ou"].s());
        const std::string uid = std::string(body["uid"].s());
        if (tenant_ou.empty() || uid.empty()) {
          crow::json::wvalue v; v["ok"]=false; v["error"]="tenant_ou/uid empty"; return Json(400, v);
        }

        std::optional<std::string> mail;
        if (ldap_dir.has_value()) {
          auto rc = ldap_dir->LookupMail(tenant_ou, uid);
          if (!rc.ok()) { crow::json::wvalue v; v["ok"]=false; v["error"]=rc.status().ToString(); return Json(502, v); }
          mail = rc.value();
        } else if (!cfg_.ldif_path.empty()) {
          mail = ldif_dir.LookupMail(tenant_ou, uid);
        } else {
          crow::json::wvalue v; v["ok"]=false; v["error"]="no directory configured"; return Json(409, v);
        }

        if (!mail.has_value() || mail->empty()) {
          crow::json::wvalue v; v["ok"]=false; v["error"]="user not found or missing mail"; return Json(404, v);
        }

        auto token_bytes = core::RandomBytes(32);
        auto invite_id_bytes = core::RandomBytes(16);
        if (!token_bytes.ok() || !invite_id_bytes.ok()) {
          crow::json::wvalue v; v["ok"]=false; v["error"]="internal error"; return Json(500, v);
        }
        const std::string token_hex = core::HexEncode(token_bytes.value());

        auto token_hash = core::Sha256(token_bytes.value());
        if (!token_hash.ok()) { crow::json::wvalue v; v["ok"]=false; v["error"]="internal error"; return Json(500, v); }

        infra::InviteRow row;
        row.invite_id = core::HexEncode(invite_id_bytes.value());
        row.tenant_id = tenant_ou;
        row.invited_email = *mail;
        row.invited_uid = uid;
        row.token_hash = std::move(token_hash.value());
        row.status = infra::InviteStatus::kInvited;
        row.created_at = core::UnixNow();
        row.expires_at = row.created_at + cfg_.invite_ttl_seconds;
        row.created_by = s->uid;

        auto ins = invites.Insert(row);
        if (!ins.ok()) { crow::json::wvalue v; v["ok"]=false; v["error"]=ins.status().ToString(); return Json(500, v); }

        const std::string invite_url = cfg_.public_base_url + "/invite/accept?token=" + token_hex;
        const std::string subject = "Gatehouse invitation (" + tenant_ou + ")";
        const std::string body_txt =
            "Hello,\n\n"
            "you have been invited to Gatehouse.\n\n"
            "Tenant: " + tenant_ou + "\n"
            "User: " + uid + "\n\n"
            "Accept invitation:\n" + invite_url + "\n\n";

        auto mail_rc = email->SendText(*mail, subject, body_txt);
        if (!mail_rc.ok()) { crow::json::wvalue v; v["ok"]=false; v["error"]="mail send failed: " + mail_rc.status().ToString(); return Json(502, v); }

        crow::json::wvalue v;
        v["ok"] = true;
        v["tenant_ou"] = tenant_ou;
        v["uid"] = uid;
        v["invited_email"] = *mail;
        v["invite_url"] = invite_url;
        v["expires_at"] = row.expires_at;
        return Json(200, v);
      } catch (const std::exception& e) {
        crow::json::wvalue v; v["ok"]=false; v["error"]=std::string("exception: ") + e.what(); return Json(500, v);
      } catch (...) {
        crow::json::wvalue v; v["ok"]=false; v["error"]="unknown exception"; return Json(500, v);
      }
    });

    app.bindaddr(cfg_.bind_addr)
        .port(static_cast<std::uint16_t>(cfg_.port))
        .concurrency(cfg_.threads)
        .run();

    return core::Result<void>::Ok();
  } catch (...) {
    return core::Result<void>::Err(core::Status::Error(core::StatusCode::kInternal, "HTTP server crashed"));
  }
}

}  // namespace gatehouse::app
