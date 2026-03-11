#include "app/http_server.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <unordered_map>
#include <vector>

#include "app/auth.h"
#include "infra/krb5_client.h"
#include "app/email_sender.h"
#include "core/crypto_aead.h"
#include "core/hex.h"
#include "core/random.h"
#include "core/sha256.h"
#include "core/time.h"
#include "core/url.h"
#include "crow.h"
#include "crow/json.h"
#include "infra/kadm5_client.h"
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

std::string ApplyTitle(const char* tmpl, const std::string& title) {
  std::string out = tmpl;
  const std::string placeholder = "%TITLE%";
  std::size_t pos = 0;
  while ((pos = out.find(placeholder, pos)) != std::string::npos) {
    out.replace(pos, placeholder.size(), title);
    pos += title.size();
  }
  return out;
}

// LOW-05: Strip non-printable / control characters before writing to logs
// to prevent ANSI escape injection in terminals or log-management systems.
std::string SanitizeForLog(const std::string& s) {
  std::string out;
  out.reserve(s.size());
  for (char ch : s) {
    const auto c = static_cast<unsigned char>(ch);
    if (c >= 0x20u && c != 0x7fu) {
      out += ch;
    } else {
      out += '?';
    }
  }
  return out;
}

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
  r.set_header("X-Content-Type-Options", "nosniff");
  r.set_header("X-Frame-Options", "DENY");
  r.set_header("Referrer-Policy", "strict-origin-when-cross-origin");
  // HIGH-05: Minimal Content-Security-Policy. Inline scripts/styles are used
  // throughout so 'unsafe-inline' is required until they are extracted.
  r.set_header("Content-Security-Policy",
               "default-src 'self'; "
               "script-src 'self' 'unsafe-inline'; "
               "style-src 'self' 'unsafe-inline'; "
               "img-src 'self' data:");
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
  r.set_header("X-Content-Type-Options", "nosniff");
  r.body = v.dump();
  return r;
}

bool IsAdminUid(const HttpServerConfig& cfg, std::optional<infra::LdapDirectory>& ldap, const std::string& uid) {
  if (!cfg.ldap_admin_group.empty() && ldap.has_value()) {
    auto rc = ldap->IsUserInGroup(uid, cfg.ldap_admin_group);
    if (rc.ok() && rc.value()) return true;
  }
  for (const auto& a : cfg.admin_uids) {
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
<title>%TITLE% Login</title>
<style>
body{font-family:system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:40px;max-width:640px}
label{display:block;margin-top:16px} input{width:100%;padding:10px;margin-top:6px}
button{margin-top:16px;padding:10px 14px}
.err{color:#b00020;margin-top:10px}
.hint{color:#555;margin-top:8px;font-size:0.9em}
code{background:#f4f4f4;padding:2px 6px;border-radius:6px}
</style></head>
<body>
<h1>%TITLE%</h1>
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
  <title>%TITLE% – Invitations</title>
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
    <h2>Uninvited LDAP Users</h2>
    <div class="row">
      <div>
        <label>Target Tenant OU
          <input id="uninvTenant" placeholder="k8s-20260118">
        </label>
      </div>
    </div>
    <button id="btnSearchUninvited">Find Users</button>
    <p id="statusUninvited"></p>
    <div id="uninvitedList"></div>
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
function getCsrfToken() {
  const m = document.cookie.match(/(?:^|;\s*)gh_csrf=([^;]+)/);
  return m ? m[1] : '';
}

async function apiJson(method, path, body) {
  const opt = {method, headers: {"Content-Type":"application/json", "X-CSRF-Token": getCsrfToken()}};
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
  thead.innerHTML = "<tr><th>created / dates</th><th>tenant</th><th>uid</th><th>email</th><th>status</th><th>actions</th></tr>";
  table.appendChild(thead);
  const tbody = document.createElement("tbody");
  for (const it of items) {
    const tr = document.createElement("tr");
    
    // Dates formatting
    const created = new Date(it.created_at * 1000).toLocaleString();
    const expires = new Date(it.expires_at * 1000).toLocaleString();
    let datesHtml = "<div>" + created + "</div><div style='color:#555;font-size:0.85em;margin-top:4px'>Expires: " + expires + "</div>";
    
    if (it.consumed_at && it.consumed_at > 0) {
        datesHtml += "<div style='color:#0a7a2f;font-size:0.85em'>Completed: " + new Date(it.consumed_at * 1000).toLocaleString() + "</div>";
    }
    if (it.revoked_at && it.revoked_at > 0) {
        datesHtml += "<div style='color:#b00020;font-size:0.85em'>Revoked: " + new Date(it.revoked_at * 1000).toLocaleString() + "</div>";
    }

    // Pill color logic based on status string
    let pillColor = "#f4f4f4";
    let textColor = "#000";
    if (it.status_name === "Completed") { pillColor = "#e6f4ea"; textColor = "#137333"; }
    else if (it.status_name === "Revoked" || it.status_name === "Expired") { pillColor = "#fce8e6"; textColor = "#c5221f"; }
    else if (it.status_name === "StepupVerified") { pillColor = "#e8f0fe"; textColor = "#1a73e8"; }

    tr.innerHTML =
      "<td>" + datesHtml + "</td>" +
      "<td><code>" + it.tenant_id + "</code></td>" +
      "<td><code>" + (it.invited_uid||"") + "</code></td>" +
      "<td>" + it.invited_email + "</td>" +
      "<td><span class='pill' style='background:" + pillColor + ";color:" + textColor + ";font-weight:500'>" + it.status_name + "</span></td>" +
      "<td></td>";
    const td = tr.querySelectorAll("td")[5];

    // Status codes: 4=Completed, 5=Expired, 6=Revoked
    const canRevoke = it.status !== 4 && it.status !== 5 && it.status !== 6;
    
    if (canRevoke) {
      const btnRevoke = document.createElement("button");
      btnRevoke.textContent = "Revoke";
      btnRevoke.style.marginRight = "8px";
      btnRevoke.onclick = async () => {
        if (!confirm("Are you sure you want to revoke this invitation for " + it.invited_email + "?")) return;
        const r = await apiJson("POST", "/api/admin/invites/revoke", {invite_id: it.invite_id});
        if (!r.ok) { alert("Revoke failed: " + (r.json && r.json.error ? r.json.error : r.text)); return; }
        await refresh();
      };
      td.appendChild(btnRevoke);
    } else if (it.invited_uid && it.tenant_id) {
      checkAndAddResetBtn(td, it.tenant_id, it.invited_uid);
    }

    const btnResend = document.createElement("button");
    btnResend.textContent = "Resend";
    btnResend.onclick = async () => {
      if (!confirm("Generate a new invite link for " + it.invited_email + "?")) return;
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

async function checkAndAddResetBtn(td, tenant_id, uid) {
  try {
    const r = await apiJson("GET", "/api/admin/user/krb-status?tenant_id=" + encodeURIComponent(tenant_id) + "&uid=" + encodeURIComponent(uid));
    if (!r.ok || !r.json || !r.json.has_krb_attrs) return;
    const btn = document.createElement("button");
    btn.textContent = "Reset Kerberos";
    btn.style.cssText = "margin-right:8px;background:#d93025;";
    btn.onclick = async () => {
      if (!confirm("Delete Kerberos attributes for " + uid + "?\n\nThis removes: krbPrincipalName, krbPrincipalKey, krbExtraData, krbLastPwdChange, krbLoginFailedCount")) return;
      const res = await apiJson("POST", "/api/admin/user/reset-krb", {tenant_id, uid});
      if (!res.ok) { alert("Reset failed: " + (res.json && res.json.error ? res.json.error : res.text)); return; }
      btn.remove();
    };
    td.insertBefore(btn, td.firstChild);
  } catch(e) {}
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

async function searchUninvited() {
  setStatus("statusUninvited", "", "Searching LDAP...");
  const t = document.getElementById("uninvTenant").value.trim();
  if (!t) { setStatus("statusUninvited", "err", "Please enter a Tenant OU."); return; }
  
  const r = await fetch("/api/admin/uninvited?tenant_id=" + encodeURIComponent(t));
  const j = await r.json().catch(() => null);
  if (!r.ok) { setStatus("statusUninvited", "err", "Error: " + (j && j.error ? j.error : r.status)); return; }
  
  const items = j.items || [];
  setStatus("statusUninvited", "ok", "Found " + items.length + " uninvited user(s).");
  
  const root = document.getElementById("uninvitedList");
  root.innerHTML = "";
  if (items.length === 0) return;
  
  const table = document.createElement("table");
  table.innerHTML = "<thead><tr><th>uid</th><th>email</th><th>actions</th></tr></thead>";
  const tbody = document.createElement("tbody");
  
  for (const it of items) {
    const tr = document.createElement("tr");
    tr.innerHTML = "<td><code>" + it.uid + "</code></td><td>" + it.mail + "</td><td></td>";
    const td = tr.querySelectorAll("td")[2];
    
    const btn = document.createElement("button");
    btn.textContent = "Send Invite";
    btn.onclick = async () => {
      btn.disabled = true;
      btn.textContent = "Sending...";
      const res = await apiJson("POST", "/api/admin/invites", {tenant_ou: t, uid: it.uid});
      if (!res.ok) {
        alert("Failed: " + (res.json && res.json.error ? res.json.error : res.text));
        btn.disabled = false;
        btn.textContent = "Send Invite";
      } else {
        btn.textContent = "Sent!";
        await refresh(); // refresh the invites list below
      }
    };
    td.appendChild(btn);
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  root.appendChild(table);
}
document.getElementById("btnSearchUninvited").addEventListener("click", searchUninvited);

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

    // Login rate limiting: max 10 attempts per IP per 5 minutes.
    std::mutex login_rl_mutex;
    std::unordered_map<std::string, std::pair<int, std::int64_t>> login_attempts;
    constexpr int kLoginMaxAttempts = 10;
    constexpr std::int64_t kLoginWindowSecs = 300;
    // MED-07: Hard cap on map size to prevent memory exhaustion from IP spoofing.
    constexpr std::size_t kLoginMapMaxSize = 100000;
    auto check_login_rate_limit = [&](const std::string& ip) -> bool {
      std::lock_guard<std::mutex> lk(login_rl_mutex);
      // If the map is at capacity and this IP is new, reject the request.
      if (login_attempts.size() >= kLoginMapMaxSize &&
          login_attempts.find(ip) == login_attempts.end()) {
        return false;
      }
      auto& entry = login_attempts[ip];
      const std::int64_t now_ts = core::UnixNow();
      if (now_ts - entry.second > kLoginWindowSecs) {
        entry = {0, now_ts};
      }
      entry.first++;
      return entry.first <= kLoginMaxAttempts;
    };

    // Compute SHA256 of a remote IP string for session binding.
    auto hash_remote_ip = [](const std::string& ip) -> std::vector<std::uint8_t> {
      if (ip.empty()) return {};
      const std::vector<std::uint8_t> ip_bytes(ip.begin(), ip.end());
      auto h = core::Sha256(ip_bytes);
      return h.ok() ? h.value() : std::vector<std::uint8_t>{};
    };

    auto require_auth = [&](const crow::request& req) -> std::optional<infra::SessionRow> {
      gc_sessions();
      const std::string sid = CookieValueFromHeader(req, cfg_.session_cookie_name);
      if (sid.empty()) return std::nullopt;
      auto got = sessions.GetBySid(sid);
      if (!got.ok() || !got.value().has_value()) return std::nullopt;
      const infra::SessionRow& row = *got.value();
      if (row.expires_at <= core::UnixNow()) return std::nullopt;
      // IP binding: validate that the request comes from the same IP as the login.
      if (!row.ip_hash_hex.empty()) {
        const std::vector<std::uint8_t> req_ip_hash = hash_remote_ip(req.remote_ip_address);
        if (req_ip_hash.empty() ||
            core::HexEncode(req_ip_hash) != row.ip_hash_hex) {
          std::fprintf(stderr, "[gatehouse][security] Session IP mismatch for uid=%s\n",
                       row.uid.c_str());
          return std::nullopt;
        }
      }
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

    // CSRF validation helpers.
    // Form-POSTs: check hidden field "_csrf" in the urlencoded body.
    // JSON-API-POSTs: check "X-CSRF-Token" request header.
    auto csrf_ok_form = [](const crow::request& req, const infra::SessionRow& s) -> bool {
      auto tok = core::FormGet(req.body, "_csrf");
      return tok.has_value() && !tok->empty() && *tok == s.csrf_secret_hex;
    };
    auto csrf_ok_header = [](const crow::request& req, const infra::SessionRow& s) -> bool {
      const std::string tok = req.get_header_value("X-CSRF-Token");
      return !tok.empty() && tok == s.csrf_secret_hex;
    };

    // Sets the gh_csrf readable cookie (no HttpOnly so JS can read it for XHR requests).
    auto set_csrf_cookie = [&](crow::response& r, const std::string& csrf_hex,
                               std::int64_t max_age) {
      r.add_header("Set-Cookie",
                   "gh_csrf=" + csrf_hex + "; Path=/; Max-Age=" +
                       std::to_string(max_age) + "; SameSite=Strict");
    };

    // ---- robots.txt ----
    // LOW-07: Instruct crawlers to stay out of admin and API paths.
    CROW_ROUTE(app, "/robots.txt").methods("GET"_method)([] {
      crow::response r;
      r.code = 200;
      r.set_header("Content-Type", "text/plain");
      r.body = "User-agent: *\nDisallow: /admin\nDisallow: /api\nDisallow: /portal\nDisallow: /invite\n";
      return r;
    });

    // ---- health ----
    CROW_ROUTE(app, "/api/healthz").methods("GET"_method)([this] {
      crow::json::wvalue v;
      v["status"] = "ok";
      v["db"] = (db_ != nullptr) && db_->is_open();
      return Json(200, v);
    });

    // ---- HTML login ----
    CROW_ROUTE(app, "/login").methods("GET"_method)([&](const crow::request& req) {
      const std::string err = req.url_params.get("err") ? req.url_params.get("err") : "";
      std::string page = ApplyTitle(kLoginPageTemplate, cfg_.instance_title);
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
      auto s = require_auth(req);
      if (s.has_value() && !csrf_ok_form(req, *s)) {
        return HtmlPage(403, "<h1>Invalid CSRF token</h1>");
      }
      const std::string sid = CookieValueFromHeader(req, cfg_.session_cookie_name);
      if (!sid.empty()) (void)sessions.DeleteBySid(sid);
      auto r = RedirectTo("/login");
      r.add_header("Set-Cookie",
                   cfg_.session_cookie_name + "=deleted; Path=/; Max-Age=0; HttpOnly; SameSite=Lax");
      r.add_header("Set-Cookie", "gh_csrf=deleted; Path=/; Max-Age=0; SameSite=Strict");
      return r;
    });

    CROW_ROUTE(app, "/auth/login").methods("POST"_method)([&](const crow::request& req) {
      if (!check_login_rate_limit(req.remote_ip_address)) {
        return RedirectTo("/login?err=Too+many+login+attempts.+Please+try+again+in+5+minutes.");
      }

      const std::optional<std::string> u = core::FormGet(req.body, "username");
      const std::optional<std::string> p = core::FormGet(req.body, "password");

      LoginRequest lr;
      lr.username = u.value_or("");
      lr.password = p.value_or("");

      auto vr = auth.Verify(lr);
      if (!vr.ok() || !vr.value().has_value()) return RedirectTo("/login?err=Invalid+credentials");

      LoginPrincipal principal = *vr.value();
      if (ldap_dir.has_value()) {
        auto t_res = ldap_dir->ResolveTenantByUid(principal.uid);
        if (t_res.ok() && t_res.value().has_value()) {
          principal.tenant_id = t_res.value().value();
        }
      }
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

      const std::vector<std::uint8_t> ip_hash = hash_remote_ip(req.remote_ip_address);
      auto ins = sessions.Insert(row, csrf_bytes.value(), ip_hash);
      if (!ins.ok()) return RedirectTo("/login?err=Internal+error");

      auto r = RedirectTo("/portal");
      r.add_header("Set-Cookie",
                   cfg_.session_cookie_name + "=" + row.sid +
                       "; Path=/; Max-Age=" + std::to_string(cfg_.session_ttl_seconds) +
                       "; HttpOnly; SameSite=Lax" +
                       (cfg_.secure_cookies ? "; Secure" : ""));
      set_csrf_cookie(r, core::HexEncode(csrf_bytes.value()), cfg_.session_ttl_seconds);
      return r;
    });

    // ---- portal ----
    CROW_ROUTE(app, "/portal").methods("GET"_method)([&](const crow::request& req) {
      auto s = require_auth(req);
      if (!s.has_value()) return RedirectTo("/login");

      const bool is_admin = IsAdminUid(cfg_, ldap_dir, s->uid);
      std::string admin_block;
      if (is_admin) {
        admin_block = "<p><b>Admin</b>: ";
        admin_block += "<a href=\"/admin/invites\">Invitations</a>";
        admin_block += " &nbsp;|&nbsp; ";
        admin_block += "<a href=\"/admin/tenants\">Tenant &amp; User Overview</a>";
        admin_block += "</p>";
      }

            std::string html = "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">";
      html += "<title>" + cfg_.instance_title + " Portal</title>";
      html += "<style>body{font-family:system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:40px;max-width:760px;background:#f9f9f9;color:#222}";
      html += ".card{background:#fff;padding:24px;border-radius:12px;box-shadow:0 2px 8px rgba(0,0,0,0.05);margin-bottom:24px}";
      html += "h1{margin-top:0} .host-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:16px;margin-top:16px}";
      html += ".host-card{padding:16px;border:1px solid #e0e0e0;border-radius:8px;background:#fafafa}";
      html += ".host-card b{display:block;font-size:1.1em;color:#0b57d0} .host-card code{font-size:0.9em;color:#555;background:#eee;padding:2px 6px;border-radius:4px}";
      html += "button{padding:10px 16px;border:none;border-radius:6px;background:#0b57d0;color:#fff;cursor:pointer;font-weight:600}";
      html += "button:hover{background:#0842a0} a{color:#0b57d0;text-decoration:none;font-weight:600} a:hover{text-decoration:underline}";
      html += "</style></head><body>";
      html += "<h1>" + cfg_.instance_title + " Portal</h1>";
      
      // Card: User Info
      html += "<div class=\"card\"><h3>Identity</h3>";
      html += "<p>Signed in as <b>" + crow::json::escape(s->uid) + "</b><br>";
      html += "Tenant: <code>" + crow::json::escape(s->tenant_id) + "</code></p>";
      if (!admin_block.empty()) html += admin_block;
      html += "</div>";

      // Card: Hosts (populated via JS)
      html += "<div class=\"card\"><h3>My Infrastructure</h3>";
      html += "<div id=\"hostContainer\"><p style=\"color:#666\">Loading hosts...</p></div>";
      html += "</div>";

      // Card: Security
      html += "<div class=\"card\"><h3>Security</h3>";
      html += "<p style=\"color:#555\">Manage your Kerberos account credentials.</p>";
      html += "<a href=\"/portal/changepw\" style=\"display:inline-block;padding:10px 16px;background:#0b57d0;color:#fff;text-decoration:none;border-radius:6px;font-weight:600\">Change Password</a>";
      html += "</div>";

      // Card: Logout (CSRF token embedded)
      html += "<form method=\"post\" action=\"/auth/logout\">";
      html += "<input type=\"hidden\" name=\"_csrf\" value=\"" + s->csrf_secret_hex + "\">";
      html += "<button type=\"submit\">Logout</button></form>";

      // JavaScript to fetch and render hosts
      html += "<script>";
      // MED-08: Use DOM APIs with textContent to avoid innerHTML XSS from LDAP data.
      html += "function escH(s){if(!s)return '';return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\"/g,'&quot;');}";
      html += "async function loadHosts() {";
      html += "  const r = await fetch('/api/me/hosts');";
      html += "  const div = document.getElementById('hostContainer');";
      html += "  if (!r.ok) { div.innerHTML = '<p style=\"color:#b00020\">Failed to load hosts.</p>'; return; }";
      html += "  const j = await r.json();";
      html += "  if (!j.items || j.items.length === 0) { div.innerHTML = '<p>No managed hosts assigned to you.</p>'; return; }";
      html += "  const grid = document.createElement('div');";
      html += "  grid.className = 'host-grid';";
      html += "  for(const host of j.items) {";
      html += "    const card = document.createElement('div');";
      html += "    card.className = 'host-card';";
      html += "    const b = document.createElement('b');";
      html += "    b.textContent = host.hostname || 'Unknown Host';";
      html += "    const p = document.createElement('p');";
      html += "    p.style.cssText = 'margin:8px 0 0 0';";
      html += "    const code = document.createElement('code');";
      html += "    code.textContent = host.ip || 'No IP configured';";
      html += "    p.appendChild(code);";
      html += "    card.appendChild(b);";
      html += "    card.appendChild(p);";
      html += "    grid.appendChild(card);";
      html += "  }";
      html += "  div.innerHTML = '';";
      html += "  div.appendChild(grid);";
      html += "}";
      html += "loadHosts();";
      html += "</script>";

      html += "</body></html>";
      return HtmlPage(200, html);
    });

    // ---- GET & POST /portal/changepw ----
    CROW_ROUTE(app, "/portal/changepw").methods("GET"_method, "POST"_method)([&](const crow::request& req) {
      auto s = require_auth(req);
      if (!s.has_value()) return RedirectTo("/login");

      if (req.method == "GET"_method) {
        const std::string err = req.url_params.get("err") ? req.url_params.get("err") : "";
        std::string html = "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">";
        html += "<title>Change Password – " + cfg_.instance_title + "</title>";
        html += "<style>body{font-family:system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:40px;max-width:540px;background:#f9f9f9;color:#222}";
        html += ".card{background:#fff;padding:24px;border-radius:12px;box-shadow:0 2px 8px rgba(0,0,0,0.05)}";
        html += "label{display:block;margin-top:16px;font-weight:500;font-size:0.95em} input{width:100%;padding:10px;margin-top:6px;border:1px solid #ccc;border-radius:6px;box-sizing:border-box}";
        html += "button{margin-top:24px;padding:12px 16px;border:none;border-radius:6px;background:#0b57d0;color:#fff;cursor:pointer;font-weight:600;width:100%;font-size:1em}";
        html += "button:hover{background:#0842a0} a{color:#0b57d0;text-decoration:none;font-weight:500} a:hover{text-decoration:underline}";
        html += "</style></head><body>";
        html += "<p><a href=\"/portal\">&larr; Back to Dashboard</a></p>";
        html += "<h1>Change Password</h1>";
        html += "<div class=\"card\">";
        if (!err.empty()) html += "<div style=\"color:#b00020;background:#fce8e6;padding:12px;border-radius:8px;margin-bottom:16px\"><b>Error:</b> " + crow::json::escape(err) + "</div>";
        html += "<form method=\"post\" action=\"/portal/changepw\">";
        html += "<input type=\"hidden\" name=\"_csrf\" value=\"" + s->csrf_secret_hex + "\">";
        html += "<label>Old Password <input type=\"password\" name=\"old_password\" required autofocus></label>";
        html += "<label>New Password <input type=\"password\" name=\"new_password\" required minlength=\"8\"></label>";
        html += "<label>Confirm New Password <input type=\"password\" name=\"new_password_confirm\" required minlength=\"8\"></label>";
        html += "<button type=\"submit\">Update Password</button>";
        html += "</form></div></body></html>";
        return HtmlPage(200, html);
      } else {
        // --- POST Logic ---
        if (!csrf_ok_form(req, *s)) return HtmlPage(403, "<h1>Invalid CSRF token</h1>");

        const std::string old_pw = core::FormGet(req.body, "old_password").value_or("");
        const std::string new_pw = core::FormGet(req.body, "new_password").value_or("");
        const std::string conf_pw = core::FormGet(req.body, "new_password_confirm").value_or("");

        if (old_pw.empty() || new_pw.empty()) return RedirectTo("/portal/changepw?err=Missing+password+fields");
        if (new_pw != conf_pw) return RedirectTo("/portal/changepw?err=New+passwords+do+not+match");

        infra::Krb5Client krb(infra::Krb5Config{.realm = cfg_.auth_cfg.krb5_realm});
        auto rc = krb.ChangePassword(s->uid, old_pw, new_pw);
        
        if (!rc.ok()) {
          std::fprintf(stderr, "[gatehouse][changepw] KDC error for %s: %s\n",
                       s->uid.c_str(), rc.status().ToString().c_str());
          return RedirectTo("/portal/changepw?err=Password+change+failed."
                            "+Check+your+old+password+and+ensure+the+new+password+meets+policy.");
        }

        return RedirectTo("/portal?ok=Password+successfully+changed");
      }
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
      if (!IsAdminUid(cfg_, ldap_dir, s->uid)) return HtmlPage(403, "<h1>Forbidden</h1>");
      return HtmlPage(200, ApplyTitle(kAdminInvitesPage, cfg_.instance_title));
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

      // BEGIN IMMEDIATE transaction to prevent race condition: two concurrent requests
      // with the same token must not both create valid invite sessions.
      auto tx = db_->Exec("BEGIN IMMEDIATE;");
      if (!tx.ok()) return HtmlPage(500, "<h1>Internal error</h1>");

      auto row = invites.GetByTokenHash(hash.value());
      if (!row.ok() || !row.value().has_value()) {
        (void)db_->Exec("ROLLBACK;");
        return HtmlPage(404, "<h1>Invitation not found</h1>");
      }

      const auto now = core::UnixNow();
      const auto& inv = *row.value();

      if (inv.revoked_at != 0 || inv.status == infra::InviteStatus::kRevoked) {
        (void)db_->Exec("ROLLBACK;");
        return HtmlPage(410, "<h1>Invitation revoked</h1>");
      }
      if (inv.status == infra::InviteStatus::kCompleted) {
        (void)db_->Exec("ROLLBACK;");
        return HtmlPage(410, "<h1>Invitation already completed</h1>");
      }
      if (inv.expires_at <= now) {
        (void)invites.UpdateStatus(inv.invite_id, infra::InviteStatus::kExpired, now);
        (void)db_->Exec("COMMIT;");
        return HtmlPage(410, "<h1>Invitation expired</h1>");
      }

      (void)invites.UpdateStatus(inv.invite_id, infra::InviteStatus::kLinkVerified, now);

      auto sid_bytes = core::RandomBytes(32);
      if (!sid_bytes.ok()) {
        (void)db_->Exec("ROLLBACK;");
        return HtmlPage(500, "<h1>Internal error</h1>");
      }

      infra::InviteSessionRow s;
      s.sid = core::HexEncode(sid_bytes.value());
      s.invite_id = inv.invite_id;
      s.created_at = now;
      s.expires_at = now + 1800;

      auto ins = invite_sessions.Insert(s);
      if (!ins.ok()) {
        (void)db_->Exec("ROLLBACK;");
        return HtmlPage(500, "<h1>Internal error</h1>");
      }

      auto cm = db_->Exec("COMMIT;");
      if (!cm.ok()) return HtmlPage(500, "<h1>Internal error</h1>");

      auto r = RedirectTo("/invite/complete");
      r.add_header("Set-Cookie", std::string(kInviteCookie) + "=" + s.sid +
                                "; Path=/; Max-Age=1800; HttpOnly; SameSite=Lax");
      return r;
    });

    // ---- invite complete GET/POST ----

    // ---- invite complete GET (wizard) ----
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

      auto verified_res = invite_otps.IsVerified(is->sid);
      const bool verified = verified_res.ok() && verified_res.value();

      const std::string sent = req.url_params.get("sent") ? req.url_params.get("sent") : "";
      const std::string err  = req.url_params.get("err")  ? req.url_params.get("err")  : "";

      // Determine wizard step:
      // 1 = send code  2 = enter code  3 = set password
      const int wizard_step = verified ? 3 : (!sent.empty() ? 2 : 1);

      // Use the invite session SID as CSRF token: HttpOnly, embedded in HTML by server.
      const std::string inv_csrf = crow::json::escape(is->sid);

      auto wstep_class = [&](int n) -> std::string {
        if (n < wizard_step) return "wstep done";
        if (n == wizard_step) return "wstep active";
        return "wstep";
      };

      std::string html;
      html += "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>";
      html += "<title>Complete Invitation \xe2\x80\x93 " + cfg_.instance_title + "</title><style>";
      html += "body{font-family:system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:0;background:#f0f4f9;color:#222}";
      html += ".wrap{max-width:520px;margin:48px auto;padding:0 16px}";
      html += "h1{font-size:1.5rem;margin:0 0 4px}";
      html += ".subtitle{color:#555;font-size:.9em;margin:0 0 28px}";
      html += ".wizard{display:flex;margin-bottom:32px;border-radius:10px;overflow:hidden;background:#fff;box-shadow:0 1px 4px rgba(0,0,0,.08)}";
      html += ".wstep{flex:1;text-align:center;padding:12px 6px;font-size:12px;font-weight:500;color:#aaa;border-bottom:3px solid transparent;transition:all .2s}";
      html += ".wstep.done{color:#137333;border-bottom-color:#137333}";
      html += ".wstep.active{color:#0b57d0;border-bottom-color:#0b57d0;font-weight:700}";
      html += ".card{background:#fff;padding:28px 28px 24px;border-radius:12px;box-shadow:0 2px 8px rgba(0,0,0,.07);margin-bottom:20px}";
      html += "h2{margin:0 0 8px;font-size:1.15rem}";
      html += ".info-row{display:flex;gap:6px;align-items:center;font-size:.88em;color:#555;margin-bottom:4px}";
      html += ".info-row b{color:#222}";
      html += "label{display:block;margin-top:18px;font-size:.9em;font-weight:600;color:#333}";
      html += "input{width:100%;padding:11px 12px;margin-top:6px;border:1px solid #ccc;border-radius:7px;font-size:1em;box-sizing:border-box;transition:border-color .15s}";
      html += "input:focus{outline:none;border-color:#0b57d0;box-shadow:0 0 0 3px rgba(11,87,208,.12)}";
      html += ".code-input{letter-spacing:6px;font-size:1.6em;text-align:center}";
      html += ".btn{display:inline-block;margin-top:20px;padding:12px 20px;border:none;border-radius:7px;font-size:1em;font-weight:600;cursor:pointer;width:100%;text-align:center}";
      html += ".btn-primary{background:#0b57d0;color:#fff} .btn-primary:hover{background:#0842a0}";
      html += ".btn-ghost{background:#f0f0f0;color:#333;margin-top:12px} .btn-ghost:hover{background:#e0e0e0}";
      html += ".alert-err{background:#fce8e6;color:#c5221f;border-radius:7px;padding:10px 14px;margin-top:14px;font-size:.9em}";
      html += ".alert-info{background:#e8f0fe;color:#1a73e8;border-radius:7px;padding:10px 14px;margin-top:14px;font-size:.9em}";
      html += "a{color:#0b57d0;font-weight:600}";
      html += "</style></head><body><div class='wrap'>";

      html += "<h1>Complete Invitation</h1>";
      html += "<p class='subtitle'>Tenant: <b>" + crow::json::escape(row.tenant_id) + "</b> &nbsp;&middot;&nbsp; User: <b>" + crow::json::escape(row.invited_uid) + "</b></p>";

      html += "<div class='wizard'>";
      html += "<div class='" + wstep_class(1) + "'>1. Verify Email</div>";
      html += "<div class='" + wstep_class(2) + "'>2. Enter Code</div>";
      html += "<div class='" + wstep_class(3) + "'>3. Set Password</div>";
      html += "</div>";

      if (wizard_step == 1) {
        // Step 1: Send verification code
        html += "<div class='card'>";
        html += "<h2>Verify your email address</h2>";
        html += "<p style='color:#555;font-size:.93em;margin:8px 0 0'>We'll send a 6-digit code to:</p>";
        html += "<div class='info-row' style='margin-top:8px'><b>" + crow::json::escape(row.invited_email) + "</b></div>";
        if (!err.empty()) {
          html += "<div class='alert-err'>Error: " + crow::json::escape(err) + "</div>";
        }
        html += "<form method='post' action='/invite/otp/send'>";
        html += "<input type='hidden' name='_csrf' value='" + inv_csrf + "'>";
        html += "<button type='submit' class='btn btn-primary'>Send Verification Code</button>";
        html += "</form></div>";
      } else if (wizard_step == 2) {
        // Step 2: Enter code
        html += "<div class='card'>";
        html += "<h2>Enter verification code</h2>";
        html += "<p style='color:#555;font-size:.93em;margin:8px 0 0'>We sent a 6-digit code to <b>" + crow::json::escape(row.invited_email) + "</b>.<br>It expires in 10&nbsp;minutes.</p>";
        if (!err.empty()) {
          html += "<div class='alert-err'>Error: " + crow::json::escape(err) + "</div>";
        }
        html += "<form method='post' action='/invite/otp/verify'>";
        html += "<input type='hidden' name='_csrf' value='" + inv_csrf + "'>";
        html += "<label>Verification code";
        html += "<input name='code' class='code-input' placeholder='123456' autocomplete='one-time-code' inputmode='numeric' maxlength='6' required></label>";
        html += "<button type='submit' class='btn btn-primary'>Verify Code</button>";
        html += "</form>";
        html += "<form method='post' action='/invite/otp/send'>";
        html += "<input type='hidden' name='_csrf' value='" + inv_csrf + "'>";
        html += "<button type='submit' class='btn btn-ghost'>Resend Code</button>";
        html += "</form></div>";
      } else {
        // Step 3: Set password
        html += "<div class='card'>";
        html += "<h2>Set up your account</h2>";
        html += "<p style='color:#555;font-size:.93em;margin:8px 0 0'>Email verified. Choose a password to complete your registration.</p>";
        if (!err.empty()) {
          html += "<div class='alert-err'>Error: " + crow::json::escape(err) + "</div>";
        }
        html += "<form method='post' action='/invite/complete'>";
        html += "<input type='hidden' name='_csrf' value='" + inv_csrf + "'>";
        html += "<label>Display name <span style='color:#aaa;font-weight:400'>(optional)</span>";
        html += "<input name='display_name' placeholder='Your full name' value='" + crow::json::escape(display) + "'></label>";
        html += "<label>New password <span style='color:#b00020'>*</span>";
        html += "<input type='password' name='password' required minlength='8' autocomplete='new-password'></label>";
        html += "<label>Confirm password <span style='color:#b00020'>*</span>";
        html += "<input type='password' name='password_confirm' required minlength='8' autocomplete='new-password'></label>";
        html += "<button type='submit' class='btn btn-primary'>Complete Setup</button>";
        html += "</form></div>";
      }

      html += "</div></body></html>";
      return HtmlPage(200, html);
    });

    CROW_ROUTE(app, "/invite/complete").methods("POST"_method)([&](const crow::request& req) {
      auto is = require_invite_session(req);
      if (!is.has_value()) return HtmlPage(401, "<h1>Invitation session expired</h1>");

      const auto csrf_val = core::FormGet(req.body, "_csrf");
      if (!csrf_val.has_value() || *csrf_val != is->sid) {
        return HtmlPage(403, "<h1>Invalid CSRF token</h1>");
      }

      // HIGH-06: Verify OTP step-up before proceeding. Without this check an
      // attacker could POST directly to /invite/complete and skip email verification.
      auto verified_res = invite_otps.IsVerified(is->sid);
      if (!verified_res.ok() || !verified_res.value()) {
        return RedirectTo("/invite/complete?err=Email+verification+required");
      }

      auto inv = invites.GetById(is->invite_id);
      if (!inv.ok() || !inv.value().has_value()) return HtmlPage(404, "<h1>Invitation not found</h1>");

      const auto now = core::UnixNow();
      const std::optional<std::string> dn = core::FormGet(req.body, "display_name");
      const std::string display = dn.value_or("");
      
      const std::string pwd1 = core::FormGet(req.body, "password").value_or("");
      const std::string pwd2 = core::FormGet(req.body, "password_confirm").value_or("");
      
      if (pwd1.empty() || pwd1 != pwd2) {
        return RedirectTo("/invite/complete?err=Passwords+do+not+match");
      }

      const char* env_kadmin_princ = std::getenv("GATEHOUSE_KADM5_ADMIN_PRINC");
      const char* env_kadmin_pass = std::getenv("GATEHOUSE_KADM5_ADMIN_PASS");
      
      if (env_kadmin_princ && env_kadmin_pass && ldap_dir.has_value()) {
        infra::Kadm5Config kcfg;
        kcfg.realm = cfg_.auth_cfg.krb5_realm;
        kcfg.admin_principal = env_kadmin_princ;
        kcfg.admin_password = env_kadmin_pass;
        infra::Kadm5Client kadm(kcfg);

        auto dn_res = ldap_dir->GetUserDn(inv.value()->tenant_id, inv.value()->invited_uid);
        if (dn_res.ok() && dn_res.value().has_value()) {
           std::string new_princ = inv.value()->invited_uid + "@" + cfg_.auth_cfg.krb5_realm;
           auto krc = kadm.CreatePrincipal(new_princ, pwd1, dn_res.value().value());
           if (!krc.ok()) {
               std::fprintf(stderr, "[gatehouse][kadm5] Failed to create principal: %s\n",
                            SanitizeForLog(krc.status().ToString()).c_str());
               return RedirectTo("/invite/complete?err=Failed+to+create+Kerberos+principal");
           }
        }
      }

      infra::InviteProfileRow pr;
      pr.invite_id = is->invite_id;
      pr.display_name = display;
      pr.created_at = now;
      pr.updated_at = now;

      (void)invite_profiles.Upsert(pr);
      (void)invites.UpdateStatus(is->invite_id, infra::InviteStatus::kCompleted, now);
      (void)invite_sessions.Consume(is->sid, now);

      // --- P3: Activate User in LDAP ---
      if (ldap_dir.has_value() && inv.value()->invited_uid != "") {
        auto act_rc = ldap_dir->ActivateUser(inv.value()->tenant_id, inv.value()->invited_uid);
        if (!act_rc.ok()) {
          std::fprintf(stderr, "[gatehouse][activate] Warning: LDAP activation failed for %s: %s\n",
                       SanitizeForLog(inv.value()->invited_uid).c_str(),
                       SanitizeForLog(act_rc.status().ToString()).c_str());
          // Optional: You could redirect to an error page here if LDAP unlock is strictly required.
          // For now, we log the warning and let the user complete the flow.
        }
      }
      // ---------------------------------

      std::string done_html;
      done_html += "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>";
      done_html += "<title>Setup Complete \xe2\x80\x93 " + cfg_.instance_title + "</title><style>";
      done_html += "body{font-family:system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:0;background:#f0f4f9;color:#222}";
      done_html += ".wrap{max-width:520px;margin:48px auto;padding:0 16px}";
      done_html += "h1{font-size:1.5rem;margin:0 0 4px}";
      done_html += ".subtitle{color:#555;font-size:.9em;margin:0 0 28px}";
      done_html += ".wizard{display:flex;margin-bottom:32px;border-radius:10px;overflow:hidden;background:#fff;box-shadow:0 1px 4px rgba(0,0,0,.08)}";
      done_html += ".wstep{flex:1;text-align:center;padding:12px 6px;font-size:12px;font-weight:500;color:#137333;border-bottom:3px solid #137333}";
      done_html += ".card{background:#fff;padding:28px 28px 24px;border-radius:12px;box-shadow:0 2px 8px rgba(0,0,0,.07)}";
      done_html += ".check{font-size:3rem;text-align:center;margin-bottom:16px}";
      done_html += "h2{margin:0 0 12px;font-size:1.15rem;text-align:center}";
      done_html += ".btn{display:inline-block;margin-top:20px;padding:12px 20px;border:none;border-radius:7px;font-size:1em;font-weight:600;cursor:pointer;width:100%;text-align:center;text-decoration:none}";
      done_html += ".btn-primary{background:#0b57d0;color:#fff} .btn-primary:hover{background:#0842a0}";
      done_html += "</style></head><body><div class='wrap'>";
      done_html += "<h1>Complete Invitation</h1><p class='subtitle'>&nbsp;</p>";
      done_html += "<div class='wizard'>";
      done_html += "<div class='wstep'>1. Verify Email</div>";
      done_html += "<div class='wstep'>2. Enter Code</div>";
      done_html += "<div class='wstep'>3. Set Password</div>";
      done_html += "</div>";
      done_html += "<div class='card'>";
      done_html += "<div class='check'>\xe2\x9c\x93</div>";
      done_html += "<h2>You're all set!</h2>";
      done_html += "<p style='text-align:center;color:#555;font-size:.93em'>Your invitation has been completed. You can now sign in with your new credentials.</p>";
      done_html += "<a href='/login' class='btn btn-primary'>Sign In</a>";
      done_html += "</div></div></body></html>";

      auto r = HtmlPage(200, done_html);
      r.add_header("Set-Cookie", std::string(kInviteCookie) + "=deleted; Path=/; Max-Age=0; HttpOnly; SameSite=Lax");
      return r;
    });

    // ---- invite OTP step-up (email) ----
    CROW_ROUTE(app, "/invite/otp/send").methods("POST"_method)([&](const crow::request& req) {
      auto is = require_invite_session(req);
      if (!is.has_value()) return HtmlPage(401, "<h1>Invitation session expired</h1>");

      const auto csrf_val = core::FormGet(req.body, "_csrf");
      if (!csrf_val.has_value() || *csrf_val != is->sid) {
        return HtmlPage(403, "<h1>Invalid CSRF token</h1>");
      }

      const std::int64_t now = core::UnixNow();

      // Cooldown check (Rate Limiting)
      auto last_issued = invite_otps.GetLastIssuedAt(is->sid);
      if (!last_issued.ok()) return HtmlPage(500, "<h1>Internal error</h1>");
      if (last_issued.value().has_value()) {
        const std::int64_t diff = now - last_issued.value().value();
        if (diff < 60) {
          return RedirectTo("/invite/complete?err=Please+wait+60+seconds+before+requesting+a+new+code");
        }
      }

      auto inv = invites.GetById(is->invite_id);
      if (!inv.ok() || !inv.value().has_value()) return HtmlPage(404, "<h1>Invitation not found</h1>");
      const auto& row = *inv.value();

      // Create 6-digit OTP using rejection-sampling to eliminate modular bias.
      // HIGH-03: Without rejection-sampling, values 0..UINT_MAX%900000 have
      // a marginally higher probability than the rest.
      constexpr unsigned int kRange = 900000U;
      constexpr unsigned int kLimit = ((~0U) - (~0U) % kRange);
      unsigned int v = 0;
      for (int attempt = 0; attempt < 32; ++attempt) {
        auto rnd = core::RandomBytes(4);
        if (!rnd.ok()) return HtmlPage(500, "<h1>Internal error</h1>");
        v = (static_cast<unsigned int>(rnd.value()[0]) << 24) |
            (static_cast<unsigned int>(rnd.value()[1]) << 16) |
            (static_cast<unsigned int>(rnd.value()[2]) << 8) |
            (static_cast<unsigned int>(rnd.value()[3]) << 0);
        if (v < kLimit) break;
      }
      const unsigned int code = (v % kRange) + 100000U;
      const std::string otp = std::to_string(code);

      // Hash OTP.
      std::vector<std::uint8_t> otp_bytes(otp.begin(), otp.end());
      auto h = core::Sha256(otp_bytes);
      if (!h.ok()) return HtmlPage(500, "<h1>Internal error</h1>");

      // Replace older OTPs for this sid.
      (void)invite_otps.DeleteBySid(is->sid);

      auto otp_id_bytes = core::RandomBytes(16);
      if (!otp_id_bytes.ok()) return HtmlPage(500, "<h1>Internal error</h1>");

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

      const std::string subject = "[" + cfg_.instance_title + "] Your email verification code";
      const std::string body_txt =
          "Your " + cfg_.instance_title + " verification code is:\n\n" + otp + "\n\n"
          "It expires in 10 minutes.\n";

      auto mail_rc = email->SendText(row.invited_email, subject, body_txt);
      if (!mail_rc.ok()) return HtmlPage(502, "<h1>Mail send failed</h1>");

      (void)invites.UpdateStatus(row.invite_id, infra::InviteStatus::kStepupSent, now);
      return RedirectTo("/invite/complete?sent=1");
    });

    CROW_ROUTE(app, "/invite/otp/verify").methods("POST"_method)([&](const crow::request& req) {
      auto is = require_invite_session(req);
      if (!is.has_value()) return HtmlPage(401, "<h1>Invitation session expired</h1>");

      const auto csrf_val = core::FormGet(req.body, "_csrf");
      if (!csrf_val.has_value() || *csrf_val != is->sid) {
        return HtmlPage(403, "<h1>Invalid CSRF token</h1>");
      }

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

      // Mark step-up as verified in the invite status.
      auto inv_otp = invites.GetById(is->invite_id);
      if (inv_otp.ok() && inv_otp.value().has_value()) {
        (void)invites.UpdateStatus(is->invite_id, infra::InviteStatus::kStepupVerified, now);
      }
      return RedirectTo("/invite/complete?ok=1");
    });

    // ---- API: My Hosts ----
    CROW_ROUTE(app, "/api/me/hosts").methods("GET"_method)([&](const crow::request& req) {
      auto s = require_auth(req);
      if (!s.has_value()) { crow::json::wvalue v; v["ok"]=false; v["error"]="unauthenticated"; return Json(401, v); }
      if (!ldap_dir.has_value()) { crow::json::wvalue v; v["ok"]=false; v["error"]="LDAP not configured"; return Json(500, v); }

      auto hr = ldap_dir->GetUserHosts(s->tenant_id, s->uid);
      if (!hr.ok()) { crow::json::wvalue v; v["ok"]=false; v["error"]=hr.status().ToString(); return Json(502, v); }

      crow::json::wvalue v;
      v["ok"] = true;
      v["items"] = crow::json::wvalue::list();
      unsigned int idx = 0;
      for (const auto& h : hr.value()) {
        crow::json::wvalue it;
        it["hostname"] = h.hostname;
        it["ip"] = h.ip;
        it["dn"] = h.dn;
        v["items"][idx++] = std::move(it);
      }
      return Json(200, v);
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
      if (!check_login_rate_limit(req.remote_ip_address)) {
        crow::json::wvalue v; v["ok"]=false; v["error"]="too many login attempts"; return Json(429, v);
      }

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

      LoginPrincipal principal = *vr.value();
      if (ldap_dir.has_value()) {
        auto t_res = ldap_dir->ResolveTenantByUid(principal.uid);
        if (t_res.ok() && t_res.value().has_value()) {
          principal.tenant_id = t_res.value().value();
        }
      }
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

      const std::vector<std::uint8_t> ip_hash_api = hash_remote_ip(req.remote_ip_address);
      auto ins = sessions.Insert(row, csrf_bytes.value(), ip_hash_api);
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
                          "; HttpOnly; SameSite=Lax" +
                          (cfg_.secure_cookies ? "; Secure" : ""));
      set_csrf_cookie(resp, core::HexEncode(csrf_bytes.value()), cfg_.session_ttl_seconds);
      return resp;
    });

    // ---- Admin APIs ----

    // ---- API: List uninvited users ----
    CROW_ROUTE(app, "/api/admin/uninvited").methods("GET"_method)([&](const crow::request& req) {
      auto s = require_auth(req);
      if (!s.has_value()) { crow::json::wvalue v; v["ok"]=false; v["error"]="unauthenticated"; return Json(401, v); }
      if (!IsAdminUid(cfg_, ldap_dir, s->uid)) { crow::json::wvalue v; v["ok"]=false; v["error"]="forbidden"; return Json(403, v); }

      const std::string tenant = req.url_params.get("tenant_id") ? req.url_params.get("tenant_id") : "";
      if (tenant.empty()) { crow::json::wvalue v; v["ok"]=false; v["error"]="tenant_id required"; return Json(400, v); }
      if (!ldap_dir.has_value()) { crow::json::wvalue v; v["ok"]=false; v["error"]="LDAP not configured"; return Json(500, v); }

      auto ldap_res = ldap_dir->ListUsers(tenant);
      if (!ldap_res.ok()) {
        std::fprintf(stderr, "[gatehouse][ldap] ListUsers failed for %s: %s\n",
                     tenant.c_str(), ldap_res.status().ToString().c_str());
        crow::json::wvalue v; v["ok"]=false; v["error"]="directory lookup failed"; return Json(502, v);
      }

      auto inv_res = invites.GetInvitedUids(tenant, core::UnixNow());
      if (!inv_res.ok()) { crow::json::wvalue v; v["ok"]=false; v["error"]=inv_res.status().ToString(); return Json(500, v); }

      // Compute difference
      std::vector<std::string> invited = inv_res.value();
      auto is_invited = [&](const std::string& u) {
          for(const auto& x : invited) if(x == u) return true;
          return false;
      };

      crow::json::wvalue v;
      v["ok"] = true;
      v["items"] = crow::json::wvalue::list();
      unsigned int idx = 0;
      for (const auto& u : ldap_res.value()) {
          if (!is_invited(u.uid)) {
              crow::json::wvalue it;
              it["uid"] = u.uid;
              it["mail"] = u.mail;
              v["items"][idx++] = std::move(it);
          }
      }
      return Json(200, v);
    });

    CROW_ROUTE(app, "/api/admin/invites/list").methods("GET"_method)([&](const crow::request& req) {
      auto s = require_auth(req);
      if (!s.has_value()) { crow::json::wvalue v; v["ok"]=false; v["error"]="unauthenticated"; return Json(401, v); }
      if (!IsAdminUid(cfg_, ldap_dir, s->uid)) { crow::json::wvalue v; v["ok"]=false; v["error"]="forbidden"; return Json(403, v); }

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
        it["consumed_at"] = r.consumed_at;
        it["created_by"] = r.created_by;
        v["items"][idx++] = std::move(it);
      }
      return Json(200, v);
    });

    CROW_ROUTE(app, "/api/admin/invites/revoke").methods("POST"_method)([&](const crow::request& req) {
      auto s = require_auth(req);
      if (!s.has_value()) { crow::json::wvalue v; v["ok"]=false; v["error"]="unauthenticated"; return Json(401, v); }
      if (!csrf_ok_header(req, *s)) { crow::json::wvalue v; v["ok"]=false; v["error"]="invalid csrf token"; return Json(403, v); }
      if (!IsAdminUid(cfg_, ldap_dir, s->uid)) { crow::json::wvalue v; v["ok"]=false; v["error"]="forbidden"; return Json(403, v); }

      auto body = crow::json::load(req.body);
      if (!body || !body.has("invite_id")) { crow::json::wvalue v; v["ok"]=false; v["error"]="invalid json (need invite_id)"; return Json(400, v); }
      const std::string invite_id = std::string(body["invite_id"].s());
      if (invite_id.empty()) { crow::json::wvalue v; v["ok"]=false; v["error"]="invite_id empty"; return Json(400, v); }

      // Fetch invite data before revoking so we have tenant_id and uid for LDAP cleanup.
      std::string inv_tenant_id, inv_uid;
      {
        auto inv = invites.GetById(invite_id);
        if (inv.ok() && inv.value().has_value()) {
          inv_tenant_id = inv.value()->tenant_id;
          inv_uid = inv.value()->invited_uid;
        }
      }

      auto rc = invites.Revoke(invite_id, core::UnixNow());
      if (!rc.ok()) { crow::json::wvalue v; v["ok"]=false; v["error"]=rc.status().ToString(); return Json(500, v); }

      // Delete Kerberos principal attributes from LDAP when revoking.
      if (ldap_dir.has_value() && !inv_tenant_id.empty() && !inv_uid.empty()) {
        auto del_rc = ldap_dir->DeleteKrbAttributes(inv_tenant_id, inv_uid);
        if (!del_rc.ok()) {
          std::fprintf(stderr, "[gatehouse][ldap] revoke: DeleteKrbAttributes failed for %s/%s: %s\n",
                       inv_tenant_id.c_str(), inv_uid.c_str(),
                       del_rc.status().ToString().c_str());
        }
      }

      crow::json::wvalue v; v["ok"]=true; return Json(200, v);
    });

    CROW_ROUTE(app, "/api/admin/user/krb-status").methods("GET"_method)([&](const crow::request& req) {
      auto s = require_auth(req);
      if (!s.has_value()) { crow::json::wvalue v; v["ok"]=false; v["error"]="unauthenticated"; return Json(401, v); }
      if (!IsAdminUid(cfg_, ldap_dir, s->uid)) { crow::json::wvalue v; v["ok"]=false; v["error"]="forbidden"; return Json(403, v); }
      if (!ldap_dir.has_value()) { crow::json::wvalue v; v["ok"]=false; v["has_krb_attrs"]=false; return Json(200, v); }

      const std::string tenant_id = req.url_params.get("tenant_id") ? req.url_params.get("tenant_id") : "";
      const std::string uid = req.url_params.get("uid") ? req.url_params.get("uid") : "";
      if (tenant_id.empty() || uid.empty()) { crow::json::wvalue v; v["ok"]=false; v["error"]="tenant_id and uid required"; return Json(400, v); }

      auto has = ldap_dir->HasKrbAttributes(tenant_id, uid);
      if (!has.ok()) {
        crow::json::wvalue v; v["ok"]=false; v["error"]=has.status().ToString(); return Json(502, v);
      }

      crow::json::wvalue v;
      v["ok"] = true;
      v["has_krb_attrs"] = has.value();
      return Json(200, v);
    });

    CROW_ROUTE(app, "/api/admin/user/reset-krb").methods("POST"_method)([&](const crow::request& req) {
      auto s = require_auth(req);
      if (!s.has_value()) { crow::json::wvalue v; v["ok"]=false; v["error"]="unauthenticated"; return Json(401, v); }
      if (!csrf_ok_header(req, *s)) { crow::json::wvalue v; v["ok"]=false; v["error"]="invalid csrf token"; return Json(403, v); }
      if (!IsAdminUid(cfg_, ldap_dir, s->uid)) { crow::json::wvalue v; v["ok"]=false; v["error"]="forbidden"; return Json(403, v); }
      if (!ldap_dir.has_value()) { crow::json::wvalue v; v["ok"]=false; v["error"]="LDAP not configured"; return Json(500, v); }

      auto body = crow::json::load(req.body);
      if (!body || !body.has("tenant_id") || !body.has("uid")) {
        crow::json::wvalue v; v["ok"]=false; v["error"]="invalid json (need tenant_id, uid)"; return Json(400, v);
      }
      const std::string tenant_id = std::string(body["tenant_id"].s());
      const std::string uid = std::string(body["uid"].s());
      if (tenant_id.empty() || uid.empty()) { crow::json::wvalue v; v["ok"]=false; v["error"]="tenant_id/uid empty"; return Json(400, v); }

      auto rc = ldap_dir->DeleteKrbAttributes(tenant_id, uid);
      if (!rc.ok()) {
        std::fprintf(stderr, "[gatehouse][ldap] reset-krb failed for %s/%s: %s\n",
                     tenant_id.c_str(), uid.c_str(), rc.status().ToString().c_str());
        crow::json::wvalue v; v["ok"]=false; v["error"]=rc.status().ToString(); return Json(502, v);
      }

      crow::json::wvalue v; v["ok"]=true; return Json(200, v);
    });

    CROW_ROUTE(app, "/api/admin/invites").methods("POST"_method)([&](const crow::request& req) {
      try {
        auto s = require_auth(req);
        if (!s.has_value()) { crow::json::wvalue v; v["ok"]=false; v["error"]="unauthenticated"; return Json(401, v); }
        if (!csrf_ok_header(req, *s)) { crow::json::wvalue v; v["ok"]=false; v["error"]="invalid csrf token"; return Json(403, v); }
        if (!IsAdminUid(cfg_, ldap_dir, s->uid)) { crow::json::wvalue v; v["ok"]=false; v["error"]="forbidden"; return Json(403, v); }

        auto body = crow::json::load(req.body);
        if (!body || !body.has("tenant_ou") || !body.has("uid")) {
          crow::json::wvalue v; v["ok"]=false; v["error"]="invalid json (need tenant_ou, uid)"; return Json(400, v);
        }
        const std::string tenant_ou = std::string(body["tenant_ou"].s());
        const std::string uid = std::string(body["uid"].s());
        if (tenant_ou.empty() || uid.empty()) {
          crow::json::wvalue v; v["ok"]=false; v["error"]="tenant_ou/uid empty"; return Json(400, v);
        }
        // MED-04: Validate uid and tenant_ou against a strict allowlist to
        // prevent LDAP-DN-injection or malformed Kerberos principal names.
        auto is_safe_name = [](const std::string& name) -> bool {
          if (name.empty() || name.size() > 64) return false;
          for (char c : name) {
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                  c == '-' || c == '_' || c == '.')) {
              return false;
            }
          }
          return true;
        };
        if (!is_safe_name(uid)) {
          crow::json::wvalue v; v["ok"]=false;
          v["error"]="uid contains invalid characters (allowed: a-z 0-9 - _ .)";
          return Json(400, v);
        }
        if (!is_safe_name(tenant_ou)) {
          crow::json::wvalue v; v["ok"]=false;
          v["error"]="tenant_ou contains invalid characters (allowed: a-z 0-9 - _ .)";
          return Json(400, v);
        }

        std::optional<std::string> mail;
        if (ldap_dir.has_value()) {
          auto rc = ldap_dir->LookupMail(tenant_ou, uid);
          if (!rc.ok()) {
            std::fprintf(stderr, "[gatehouse][ldap] LookupMail failed for %s/%s: %s\n",
                         tenant_ou.c_str(), uid.c_str(), rc.status().ToString().c_str());
            crow::json::wvalue v; v["ok"]=false; v["error"]="directory lookup failed"; return Json(502, v);
          }
          mail = rc.value();
        } else if (!cfg_.ldif_path.empty()) {
          mail = ldif_dir.LookupMail(tenant_ou, uid);
        } else {
          crow::json::wvalue v; v["ok"]=false; v["error"]="no directory configured"; return Json(409, v);
        }

        if (!mail.has_value() || mail->empty()) {
          crow::json::wvalue v; v["ok"]=false; v["error"]="user not found or missing mail"; return Json(404, v);
        }

        // Revoke any existing pending invites for the same tenant+uid before creating a new one.
        (void)invites.RevokePending(tenant_ou, uid, core::UnixNow());

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
        const std::string subject = "[" + cfg_.instance_title + "] You have been invited to " + tenant_ou;
        const std::string body_txt =
            "Hello,\n\n"
            "you have been invited to " + cfg_.instance_title + ".\n\n"
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

    // ---- Admin: Tenant & User Overview ----

    CROW_ROUTE(app, "/admin/tenants").methods("GET"_method)([&](const crow::request& req) {
      auto s = require_auth(req);
      if (!s.has_value()) return RedirectTo("/login");
      if (!IsAdminUid(cfg_, ldap_dir, s->uid)) return HtmlPage(403, "<h1>Forbidden</h1>");

      const std::string csrf = s->csrf_secret_hex;
      std::string html = "<!doctype html><html><head><meta charset='utf-8'>"
                         "<meta name='viewport' content='width=device-width,initial-scale=1'>"
                         "<title>" + cfg_.instance_title + " – Tenant Overview</title>"
                         "<style>"
                         "body{font-family:system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:40px;max-width:1100px;background:#f9f9f9;color:#222}"
                         ".card{background:#fff;padding:20px 24px;border-radius:12px;box-shadow:0 2px 8px rgba(0,0,0,.05);margin-bottom:20px}"
                         "h1,h2,h3{margin-top:0} a{color:#0b57d0;font-weight:600;text-decoration:none} a:hover{text-decoration:underline}"
                         "table{width:100%;border-collapse:collapse;margin-top:12px}"
                         "th,td{padding:8px 10px;border-bottom:1px solid #eee;text-align:left;font-size:14px;vertical-align:top}"
                         "th{font-weight:600;background:#fafafa}"
                         "code{background:#f0f0f0;padding:2px 6px;border-radius:4px;font-size:0.88em}"
                         ".host-pill{display:inline-block;background:#e8f0fe;color:#1a73e8;padding:2px 8px;border-radius:999px;font-size:12px;margin:2px 2px 2px 0}"
                         ".err{color:#b00020} .muted{color:#777;font-size:13px}"
                         "select{padding:8px;border-radius:6px;border:1px solid #ccc;font-size:14px;margin-right:8px}"
                         "button{padding:9px 16px;border:none;border-radius:6px;background:#0b57d0;color:#fff;cursor:pointer;font-weight:600}"
                         "button:hover{background:#0842a0}"
                         "</style></head><body>"
                         "<h1>Tenant &amp; User Overview</h1>"
                         "<p><a href='/portal'>&larr; Back to portal</a></p>"
                         "<div class='card'>"
                         "<h2>Select Tenant</h2>"
                         "<select id='tenantSel'><option value=''>Loading...</option></select>"
                         "<button id='btnLoad'>Load Users &amp; Hosts</button>"
                         "<p id='status' class='muted'></p>"
                         "</div>"
                         "<div id='result'></div>"
                         "<script>";

      html += "const CSRF = '" + csrf + "';\n";
      html += R"JS(
const STATUS_NAMES = {
  '-1': {label:'None',      bg:'#f0f0f0', fg:'#555'},
   '0': {label:'Invited',   bg:'#fff3cd', fg:'#856404'},
   '1': {label:'LinkVerified', bg:'#cfe2ff', fg:'#0a58ca'},
   '2': {label:'StepupSent',   bg:'#cfe2ff', fg:'#0a58ca'},
   '3': {label:'StepupVerified', bg:'#d1ecf1', fg:'#0c5460'},
   '4': {label:'Completed', bg:'#d1e7dd', fg:'#0f5132'},
   '5': {label:'Expired',   bg:'#f8d7da', fg:'#842029'},
   '6': {label:'Revoked',   bg:'#f8d7da', fg:'#842029'},
};

function statusPill(status, expiresAt) {
  const s = String(status);
  const info = STATUS_NAMES[s] || {label:'Unknown', bg:'#eee', fg:'#333'};
  let label = info.label;
  // Mark as expired if past expiry but status is not yet set
  if ((status === 0 || status === 1 || status === 2 || status === 3) && expiresAt > 0 && expiresAt < Date.now()/1000) {
    label = 'Expired'; return '<span style="display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:500;background:#f8d7da;color:#842029">' + label + '</span>';
  }
  return '<span style="display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:500;background:' + info.bg + ';color:' + info.fg + '">' + label + '</span>';
}

async function loadTenants() {
  const r = await fetch('/api/admin/tenants');
  const j = await r.json().catch(() => null);
  const sel = document.getElementById('tenantSel');
  if (!r.ok || !j || !j.items) { sel.innerHTML = '<option>Error loading tenants</option>'; return; }
  sel.innerHTML = '<option value="">-- choose tenant --</option>';
  for (const t of j.items) {
    const o = document.createElement('option');
    o.value = t; o.textContent = t;
    sel.appendChild(o);
  }
}

async function sendInvite(tenantId, uid, btnEl) {
  btnEl.disabled = true;
  const orig = btnEl.textContent;
  btnEl.textContent = 'Sending...';
  const r = await fetch('/api/admin/invites', {
    method: 'POST',
    headers: {'Content-Type':'application/json','X-CSRF-Token': CSRF},
    body: JSON.stringify({tenant_ou: tenantId, uid})
  });
  const j = await r.json().catch(() => null);
  if (!r.ok) {
    alert('Failed: ' + (j && j.error ? j.error : r.status));
    btnEl.disabled = false;
    btnEl.textContent = orig;
    return;
  }
  // Refresh the table to show updated status
  await loadUsers();
}

async function loadUsers() {
  const t = document.getElementById('tenantSel').value;
  if (!t) { document.getElementById('status').textContent = 'Please select a tenant.'; return; }
  document.getElementById('status').textContent = 'Loading...';
  document.getElementById('result').innerHTML = '';
  const r = await fetch('/api/admin/tenant-users?tenant_id=' + encodeURIComponent(t),
                        {headers: {'X-CSRF-Token': CSRF}});
  const j = await r.json().catch(() => null);
  if (!r.ok || !j) {
    document.getElementById('status').textContent = 'Error: ' + (j && j.error ? j.error : r.status);
    return;
  }
  const users = j.users || [];
  document.getElementById('status').textContent = users.length + ' user(s) found.';

  if (users.length === 0) {
    document.getElementById('result').innerHTML = '<div class="card"><p>No users found in this tenant.</p></div>';
    return;
  }

  const card = document.createElement('div');
  card.className = 'card';
  card.innerHTML = '<h2>Users in <code>' + escHtml(t) + '</code></h2>';

  const table = document.createElement('table');
  table.innerHTML =
    '<thead><tr><th>UID</th><th>First Name</th><th>Last Name</th><th>Email</th>' +
    '<th>Invitation</th><th>Managed Hosts</th><th>Actions</th></tr></thead>';
  const tbody = document.createElement('tbody');

  for (const u of users) {
    const tr = document.createElement('tr');

    // Hosts
    let hostsHtml = '';
    if (u.hosts && u.hosts.length > 0) {
      for (const h of u.hosts) {
        hostsHtml += '<span class="host-pill" title="' + escHtml(h.dn) + '">';
        hostsHtml += escHtml(h.hostname || h.dn);
        if (h.ip) hostsHtml += ' <code>' + escHtml(h.ip) + '</code>';
        hostsHtml += '</span>';
      }
    } else {
      hostsHtml = '<span class="muted">—</span>';
    }

    // Invite status
    const st = u.invite_status;
    let invHtml = statusPill(st, u.invite_expires_at);
    if (st >= 0 && u.invite_created_at > 0) {
      invHtml += '<br><span class="muted">' + new Date(u.invite_created_at * 1000).toLocaleDateString() + '</span>';
    }
    if (u.invite_expires_at > 0 && st !== 4) {
      const exp = new Date(u.invite_expires_at * 1000);
      invHtml += '<br><span class="muted" title="Expires">exp: ' + exp.toLocaleDateString() + '</span>';
    }

    tr.innerHTML =
      '<td><code>' + escHtml(u.uid) + '</code></td>' +
      '<td>' + escHtml(u.given_name) + '</td>' +
      '<td>' + escHtml(u.surname) + '</td>' +
      '<td>' + escHtml(u.mail) + '</td>' +
      '<td>' + invHtml + '</td>' +
      '<td>' + hostsHtml + '</td>' +
      '<td></td>';

    // Action button
    const td = tr.querySelectorAll('td')[6];
    const isActive = st === 0 || st === 1 || st === 2 || st === 3;
    const isCompleted = st === 4;
    if (!isCompleted) {
      const btn = document.createElement('button');
      btn.textContent = isActive ? 'Resend' : 'Send Invite';
      btn.style.cssText = 'padding:5px 10px;font-size:13px;';
      btn.onclick = () => sendInvite(t, u.uid, btn);
      td.appendChild(btn);
    }

    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  card.appendChild(table);
  document.getElementById('result').appendChild(card);
}

function escHtml(s) {
  if (!s) return '';
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

document.getElementById('btnLoad').addEventListener('click', loadUsers);
loadTenants();
)JS";
      html += "</script></body></html>";
      return HtmlPage(200, html);
    });

    CROW_ROUTE(app, "/api/admin/tenants").methods("GET"_method)([&](const crow::request& req) {
      auto s = require_auth(req);
      if (!s.has_value()) { crow::json::wvalue v; v["ok"]=false; v["error"]="unauthenticated"; return Json(401, v); }
      if (!IsAdminUid(cfg_, ldap_dir, s->uid)) { crow::json::wvalue v; v["ok"]=false; v["error"]="forbidden"; return Json(403, v); }
      if (!ldap_dir.has_value()) { crow::json::wvalue v; v["ok"]=false; v["error"]="LDAP not configured"; return Json(500, v); }

      auto res = ldap_dir->ListTenants();
      if (!res.ok()) {
        std::fprintf(stderr, "[gatehouse][ldap] ListTenants failed: %s\n",
                     res.status().ToString().c_str());
        crow::json::wvalue v; v["ok"]=false; v["error"]="directory lookup failed"; return Json(502, v);
      }

      crow::json::wvalue v;
      v["ok"] = true;
      v["items"] = crow::json::wvalue::list();
      unsigned int idx = 0;
      for (const auto& t : res.value()) {
        v["items"][idx++] = t;
      }
      return Json(200, v);
    });

    CROW_ROUTE(app, "/api/admin/tenant-users").methods("GET"_method)([&](const crow::request& req) {
      auto s = require_auth(req);
      if (!s.has_value()) { crow::json::wvalue v; v["ok"]=false; v["error"]="unauthenticated"; return Json(401, v); }
      if (!csrf_ok_header(req, *s)) { crow::json::wvalue v; v["ok"]=false; v["error"]="invalid csrf token"; return Json(403, v); }
      if (!IsAdminUid(cfg_, ldap_dir, s->uid)) { crow::json::wvalue v; v["ok"]=false; v["error"]="forbidden"; return Json(403, v); }
      if (!ldap_dir.has_value()) { crow::json::wvalue v; v["ok"]=false; v["error"]="LDAP not configured"; return Json(500, v); }

      const std::string tenant = req.url_params.get("tenant_id") ? req.url_params.get("tenant_id") : "";
      if (tenant.empty()) { crow::json::wvalue v; v["ok"]=false; v["error"]="tenant_id required"; return Json(400, v); }

      auto res = ldap_dir->ListUsersWithHosts(tenant);
      if (!res.ok()) {
        std::fprintf(stderr, "[gatehouse][ldap] ListUsersWithHosts failed for %s: %s\n",
                     tenant.c_str(), res.status().ToString().c_str());
        crow::json::wvalue v; v["ok"]=false; v["error"]="directory lookup failed"; return Json(502, v);
      }

      // Build uid -> latest invite map.
      auto inv_res = invites.GetLatestPerUid(tenant);
      std::unordered_map<std::string, infra::InviteRow> inv_map;
      if (inv_res.ok()) {
        for (auto& row : inv_res.value()) {
          inv_map[row.invited_uid] = std::move(row);
        }
      }

      crow::json::wvalue v;
      v["ok"] = true;
      v["tenant_id"] = tenant;
      v["users"] = crow::json::wvalue::list();
      unsigned int idx = 0;
      for (const auto& u : res.value()) {
        crow::json::wvalue uj;
        uj["uid"]        = u.uid;
        uj["given_name"] = u.given_name;
        uj["surname"]    = u.surname;
        uj["mail"]       = u.mail;

        auto it = inv_map.find(u.uid);
        if (it != inv_map.end()) {
          const auto& inv = it->second;
          uj["invite_id"]          = inv.invite_id;
          uj["invite_status"]      = static_cast<int>(inv.status);
          uj["invite_status_name"] = InviteStatusName(inv.status);
          uj["invite_expires_at"]  = inv.expires_at;
          uj["invite_created_at"]  = inv.created_at;
        } else {
          uj["invite_status"]      = -1;
          uj["invite_status_name"] = "None";
          uj["invite_expires_at"]  = 0;
          uj["invite_created_at"]  = 0;
        }

        uj["hosts"] = crow::json::wvalue::list();
        unsigned int hidx = 0;
        for (const auto& h : u.hosts) {
          crow::json::wvalue hj;
          hj["dn"]       = h.dn;
          hj["hostname"] = h.hostname;
          hj["ip"]       = h.ip;
          uj["hosts"][hidx++] = std::move(hj);
        }
        v["users"][idx++] = std::move(uj);
      }
      return Json(200, v);
    });

        app.concurrency(cfg_.threads);

        if (!cfg_.unix_socket.empty()) {
          app.local_socket_path(cfg_.unix_socket).run();
        } else {
          app.bindaddr(cfg_.bind_addr)
              .port(static_cast<std::uint16_t>(cfg_.port))
              .run();
        }

    return core::Result<void>::Ok();
  } catch (...) {
    return core::Result<void>::Err(core::Status::Error(core::StatusCode::kInternal, "HTTP server crashed"));
  }
}

}  // namespace gatehouse::app
