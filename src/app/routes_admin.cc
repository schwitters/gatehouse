#include "app/routes.h"
#include "web_assets.h"

#include <cstdio>
#include <string>
#include <unordered_map>
#include <vector>

#include "app/http_utils.h"
#include "core/hex.h"
#include "core/random.h"
#include "core/sha256.h"
#include "core/time.h"
#include "crow.h"
#include "crow/json.h"
#include "infra/invite_repo.h"

namespace gatehouse::app {

namespace {

const char* kAdminInvitesPage = assets::k_admin_invites;

}  // namespace

void RegisterAdminRoutes(crow::SimpleApp& app, ServerContext& ctx) {
  const std::string& base_uri = ctx.cfg.base_uri;

  // ---- Admin invitations page ----
  app.route_dynamic(base_uri + "/admin/invites").methods("GET"_method)([&ctx](const crow::request& req) {
    const auto connection = ctx.db.ConnectForThread();
    if (!connection.ok()) return HtmlPage(503, "<h1>Database unavailable</h1>");
    const std::string& B = ctx.cfg.base_uri;
    auto s = RequireAuth(ctx, req);
    if (!s.has_value()) return RedirectTo(B + "/login");
    if (!IsAdminUid(ctx, s->uid)) return HtmlPage(403, "<h1>Forbidden</h1>");
    // ApplyTitle also substitutes %B% with base_uri
    std::string page = ApplyTitle(kAdminInvitesPage, ctx.cfg.instance_title);
    std::size_t pos = 0;
    while ((pos = page.find("%B%", pos)) != std::string::npos) {
      page.replace(pos, 3, B);
      pos += B.size();
    }
    return HtmlPage(200, page);
  });

  // ---- Admin tenant/user overview page ----
  app.route_dynamic(base_uri + "/admin/tenants").methods("GET"_method)([&ctx](const crow::request& req) {
    const auto connection = ctx.db.ConnectForThread();
    if (!connection.ok()) return HtmlPage(503, "<h1>Database unavailable</h1>");
    const std::string& B = ctx.cfg.base_uri;
    auto s = RequireAuth(ctx, req);
    if (!s.has_value()) return RedirectTo(B + "/login");
    if (!IsAdminUid(ctx, s->uid)) return HtmlPage(403, "<h1>Forbidden</h1>");

    const std::string csrf = s->csrf_secret_hex;
    std::string html = "<!doctype html><html><head><meta charset='utf-8'>"
                       "<meta name='viewport' content='width=device-width,initial-scale=1'>"
                       "<title>" + HtmlEscape(ctx.cfg.instance_title) + " \xe2\x80\x93 Tenant Overview</title>"
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
                       "<p><a href='" + B + "/portal'>&larr; Back to portal</a></p>"
                       "<div class='card'>"
                       "<h2>Select Tenant</h2>"
                       "<select id='tenantSel'><option value=''>Loading...</option></select>"
                       "<button id='btnLoad'>Load Users &amp; Hosts</button>"
                       "<p id='status' class='muted'></p>"
                       "</div>"
                       "<div id='result'></div>"
                       "<script>";

    html += "const _B='" + B + "';\n";
    html += "const CSRF = '" + csrf + "';\n";
    html += "</script><script src=\"" + HtmlEscape(B) + "/assets/admin-tenants.js\"></script><script>";

    html += "</script></body></html>";
    return HtmlPage(200, html);
  });

  // ---- API: List uninvited users ----
  app.route_dynamic(base_uri + "/api/admin/uninvited").methods("GET"_method)([&ctx](const crow::request& req) {
    const auto connection = ctx.db.ConnectForThread();
    if (!connection.ok()) return HtmlPage(503, "<h1>Database unavailable</h1>");
    auto s = RequireAuth(ctx, req);
    if (!s.has_value()) { crow::json::wvalue v; v["ok"]=false; v["error"]="unauthenticated"; return Json(401, v); }
    if (!IsAdminUid(ctx, s->uid)) { crow::json::wvalue v; v["ok"]=false; v["error"]="forbidden"; return Json(403, v); }

    const std::string tenant = req.url_params.get("tenant_id") ? req.url_params.get("tenant_id") : "";
    if (tenant.empty()) { crow::json::wvalue v; v["ok"]=false; v["error"]="tenant_id required"; return Json(400, v); }
    if (!ctx.ldap_dir.has_value()) { crow::json::wvalue v; v["ok"]=false; v["error"]="LDAP not configured"; return Json(500, v); }

    auto ldap_res = ctx.ldap_dir->ListUsers(tenant);
    if (!ldap_res.ok()) {
      std::fprintf(stderr, "[gatehouse][ldap] ListUsers failed for %s: %s\n",
                   tenant.c_str(), ldap_res.status().ToString().c_str());
      crow::json::wvalue v; v["ok"]=false; v["error"]="directory lookup failed"; return Json(502, v);
    }

    auto inv_res = ctx.invites.GetInvitedUids(tenant, core::UnixNow());
    if (!inv_res.ok()) { crow::json::wvalue v; v["ok"]=false; v["error"]=inv_res.status().ToString(); return Json(500, v); }

    const std::vector<std::string> invited = inv_res.value();
    auto is_invited = [&](const std::string& u) {
      for (const auto& x : invited) if (x == u) return true;
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

  // ---- API: List latest invites (with optional filters) ----
  app.route_dynamic(base_uri + "/api/admin/invites/list").methods("GET"_method)([&ctx](const crow::request& req) {
    const auto connection = ctx.db.ConnectForThread();
    if (!connection.ok()) return HtmlPage(503, "<h1>Database unavailable</h1>");
    auto s = RequireAuth(ctx, req);
    if (!s.has_value()) { crow::json::wvalue v; v["ok"]=false; v["error"]="unauthenticated"; return Json(401, v); }
    if (!IsAdminUid(ctx, s->uid)) { crow::json::wvalue v; v["ok"]=false; v["error"]="forbidden"; return Json(403, v); }

    const std::string tenant = req.url_params.get("tenant_id") ? req.url_params.get("tenant_id") : "";
    const std::string uid    = req.url_params.get("invited_uid") ? req.url_params.get("invited_uid") : "";

    auto rows = ctx.invites.ListLatest(50, tenant, uid);
    if (!rows.ok()) { crow::json::wvalue v; v["ok"]=false; v["error"]=rows.status().ToString(); return Json(500, v); }

    crow::json::wvalue v;
    v["ok"] = true;
    v["items"] = crow::json::wvalue::list();
    unsigned int idx = 0;
    for (const auto& r : rows.value()) {
      crow::json::wvalue it;
      it["invite_id"]    = r.invite_id;
      it["tenant_id"]    = r.tenant_id;
      it["invited_uid"]  = r.invited_uid;
      it["invited_email"]= r.invited_email;
      it["status"]       = static_cast<int>(r.status);
      it["status_name"]  = InviteStatusName(r.status);
      it["created_at"]   = r.created_at;
      it["expires_at"]   = r.expires_at;
      it["revoked_at"]   = r.revoked_at;
      it["consumed_at"]  = r.consumed_at;
      it["created_by"]   = r.created_by;
      v["items"][idx++] = std::move(it);
    }
    return Json(200, v);
  });

  // ---- API: Revoke invite ----
  app.route_dynamic(base_uri + "/api/admin/invites/revoke").methods("POST"_method)([&ctx](const crow::request& req) {
    const auto connection = ctx.db.ConnectForThread();
    if (!connection.ok()) return HtmlPage(503, "<h1>Database unavailable</h1>");
    auto s = RequireAuth(ctx, req);
    if (!s.has_value()) { crow::json::wvalue v; v["ok"]=false; v["error"]="unauthenticated"; return Json(401, v); }
    if (!CsrfOkHeader(req, *s)) { crow::json::wvalue v; v["ok"]=false; v["error"]="invalid csrf token"; return Json(403, v); }
    if (!IsAdminUid(ctx, s->uid)) { crow::json::wvalue v; v["ok"]=false; v["error"]="forbidden"; return Json(403, v); }

    auto body = crow::json::load(req.body);
    if (!body || !body.has("invite_id")) { crow::json::wvalue v; v["ok"]=false; v["error"]="invalid json (need invite_id)"; return Json(400, v); }
    const std::string invite_id = std::string(body["invite_id"].s());
    if (invite_id.empty()) { crow::json::wvalue v; v["ok"]=false; v["error"]="invite_id empty"; return Json(400, v); }

    std::string inv_tenant_id, inv_uid;
    {
      auto inv = ctx.invites.GetById(invite_id);
      if (inv.ok() && inv.value().has_value()) {
        inv_tenant_id = inv.value()->tenant_id;
        inv_uid       = inv.value()->invited_uid;
      }
    }

    auto rc = ctx.invites.Revoke(invite_id, core::UnixNow());
    if (!rc.ok()) { crow::json::wvalue v; v["ok"]=false; v["error"]=rc.status().ToString(); return Json(500, v); }

    if (ctx.ldap_dir.has_value() && !inv_tenant_id.empty() && !inv_uid.empty()) {
      auto del_rc = ctx.ldap_dir->DeleteKrbAttributes(inv_tenant_id, inv_uid);
      if (!del_rc.ok()) {
        std::fprintf(stderr, "[gatehouse][ldap] revoke: DeleteKrbAttributes failed for %s/%s: %s\n",
                     inv_tenant_id.c_str(), inv_uid.c_str(),
                     del_rc.status().ToString().c_str());
        crow::json::wvalue error;
        error["ok"] = false;
        error["error"] = "Invitation revoked, but directory cleanup failed; retry revocation";
        return Json(502, error);
      }
    }

    crow::json::wvalue v; v["ok"]=true; return Json(200, v);
  });

  // ---- API: Create invite ----
  app.route_dynamic(base_uri + "/api/admin/invites").methods("POST"_method)([&ctx](const crow::request& req) {
    const auto connection = ctx.db.ConnectForThread();
    if (!connection.ok()) return HtmlPage(503, "<h1>Database unavailable</h1>");
    try {
      auto s = RequireAuth(ctx, req);
      if (!s.has_value()) { crow::json::wvalue v; v["ok"]=false; v["error"]="unauthenticated"; return Json(401, v); }
      if (!CsrfOkHeader(req, *s)) { crow::json::wvalue v; v["ok"]=false; v["error"]="invalid csrf token"; return Json(403, v); }
      if (!IsAdminUid(ctx, s->uid)) { crow::json::wvalue v; v["ok"]=false; v["error"]="forbidden"; return Json(403, v); }

      auto body = crow::json::load(req.body);
      if (!body || !body.has("tenant_ou") || !body.has("uid")) {
        crow::json::wvalue v; v["ok"]=false; v["error"]="invalid json (need tenant_ou, uid)"; return Json(400, v);
      }
      const std::string tenant_ou = std::string(body["tenant_ou"].s());
      const std::string uid       = std::string(body["uid"].s());
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
      if (ctx.ldap_dir.has_value()) {
        auto rc = ctx.ldap_dir->LookupMail(tenant_ou, uid);
        if (!rc.ok()) {
          std::fprintf(stderr, "[gatehouse][ldap] LookupMail failed for %s/%s: %s\n",
                       tenant_ou.c_str(), uid.c_str(), rc.status().ToString().c_str());
          crow::json::wvalue v; v["ok"]=false; v["error"]="directory lookup failed"; return Json(502, v);
        }
        mail = rc.value();
      } else if (!ctx.cfg.ldif_path.empty()) {
        mail = ctx.ldif_dir.LookupMail(tenant_ou, uid);
      } else {
        crow::json::wvalue v; v["ok"]=false; v["error"]="no directory configured"; return Json(409, v);
      }

      if (!mail.has_value() || mail->empty()) {
        crow::json::wvalue v; v["ok"]=false; v["error"]="user not found or missing mail"; return Json(404, v);
      }

      // Revoke any existing pending invites before creating a new one.
      auto revoked = ctx.invites.RevokePending(tenant_ou, uid, core::UnixNow());
      if (!revoked.ok()) { crow::json::wvalue error; error["error"] = "Invitation is busy"; return Json(409, error); }

      auto token_bytes    = core::RandomBytes(32);
      auto invite_id_bytes = core::RandomBytes(16);
      if (!token_bytes.ok() || !invite_id_bytes.ok()) {
        crow::json::wvalue v; v["ok"]=false; v["error"]="internal error"; return Json(500, v);
      }
      const std::string token_hex = core::HexEncode(token_bytes.value());

      auto token_hash = core::Sha256(token_bytes.value());
      if (!token_hash.ok()) { crow::json::wvalue v; v["ok"]=false; v["error"]="internal error"; return Json(500, v); }

      infra::InviteRow row;
      row.invite_id    = core::HexEncode(invite_id_bytes.value());
      row.tenant_id    = tenant_ou;
      row.invited_email = *mail;
      row.invited_uid  = uid;
      row.token_hash   = std::move(token_hash.value());
      row.status       = infra::InviteStatus::kInvited;
      row.created_at   = core::UnixNow();
      row.expires_at   = row.created_at + ctx.cfg.invite_ttl_seconds;
      row.created_by   = s->uid;

      auto ins = ctx.invites.Insert(row);
      if (!ins.ok()) { crow::json::wvalue v; v["ok"]=false; v["error"]=ins.status().ToString(); return Json(500, v); }

      const std::string invite_url = ctx.cfg.public_base_url + "/invite/accept?token=" + token_hex;
      const std::string subject    = "[" + ctx.cfg.instance_title + "] You have been invited to " + tenant_ou;
      const std::string body_txt   =
          "Hello,\n\n"
          "you have been invited to " + ctx.cfg.instance_title + ".\n\n"
          "Tenant: " + tenant_ou + "\n"
          "User: " + uid + "\n\n"
          "Accept invitation:\n" + invite_url + "\n\n";

      auto mail_rc = ctx.email.SendText(*mail, subject, body_txt);
      if (!mail_rc.ok()) { crow::json::wvalue v; v["ok"]=false; v["error"]="mail send failed: " + mail_rc.status().ToString(); return Json(502, v); }

      crow::json::wvalue v;
      v["ok"]           = true;
      v["tenant_ou"]    = tenant_ou;
      v["uid"]          = uid;
      v["invited_email"]= *mail;
      v["invite_url"]   = invite_url;
      v["expires_at"]   = row.expires_at;
      return Json(200, v);
    } catch (const std::exception& e) {
      crow::json::wvalue v; v["ok"]=false; v["error"]=std::string("exception: ") + e.what(); return Json(500, v);
    } catch (...) {
      crow::json::wvalue v; v["ok"]=false; v["error"]="unknown exception"; return Json(500, v);
    }
  });

  // ---- API: Kerberos attribute status for a user ----
  app.route_dynamic(base_uri + "/api/admin/user/krb-status").methods("GET"_method)([&ctx](const crow::request& req) {
    const auto connection = ctx.db.ConnectForThread();
    if (!connection.ok()) return HtmlPage(503, "<h1>Database unavailable</h1>");
    auto s = RequireAuth(ctx, req);
    if (!s.has_value()) { crow::json::wvalue v; v["ok"]=false; v["error"]="unauthenticated"; return Json(401, v); }
    if (!IsAdminUid(ctx, s->uid)) { crow::json::wvalue v; v["ok"]=false; v["error"]="forbidden"; return Json(403, v); }
    if (!ctx.ldap_dir.has_value()) { crow::json::wvalue v; v["ok"]=false; v["has_krb_attrs"]=false; return Json(200, v); }

    const std::string tenant_id = req.url_params.get("tenant_id") ? req.url_params.get("tenant_id") : "";
    const std::string uid       = req.url_params.get("uid") ? req.url_params.get("uid") : "";
    if (tenant_id.empty() || uid.empty()) {
      crow::json::wvalue v; v["ok"]=false; v["error"]="tenant_id and uid required"; return Json(400, v);
    }

    auto has = ctx.ldap_dir->HasKrbAttributes(tenant_id, uid);
    if (!has.ok()) {
      crow::json::wvalue v; v["ok"]=false; v["error"]=has.status().ToString(); return Json(502, v);
    }

    crow::json::wvalue v;
    v["ok"] = true;
    v["has_krb_attrs"] = has.value();
    return Json(200, v);
  });

  // ---- API: Reset Kerberos attributes for a user ----
  app.route_dynamic(base_uri + "/api/admin/user/reset-krb").methods("POST"_method)([&ctx](const crow::request& req) {
    const auto connection = ctx.db.ConnectForThread();
    if (!connection.ok()) return HtmlPage(503, "<h1>Database unavailable</h1>");
    auto s = RequireAuth(ctx, req);
    if (!s.has_value()) { crow::json::wvalue v; v["ok"]=false; v["error"]="unauthenticated"; return Json(401, v); }
    if (!CsrfOkHeader(req, *s)) { crow::json::wvalue v; v["ok"]=false; v["error"]="invalid csrf token"; return Json(403, v); }
    if (!IsAdminUid(ctx, s->uid)) { crow::json::wvalue v; v["ok"]=false; v["error"]="forbidden"; return Json(403, v); }
    if (!ctx.ldap_dir.has_value()) { crow::json::wvalue v; v["ok"]=false; v["error"]="LDAP not configured"; return Json(500, v); }

    auto body = crow::json::load(req.body);
    if (!body || !body.has("tenant_id") || !body.has("uid")) {
      crow::json::wvalue v; v["ok"]=false; v["error"]="invalid json (need tenant_id, uid)"; return Json(400, v);
    }
    const std::string tenant_id = std::string(body["tenant_id"].s());
    const std::string uid       = std::string(body["uid"].s());
    if (tenant_id.empty() || uid.empty()) {
      crow::json::wvalue v; v["ok"]=false; v["error"]="tenant_id/uid empty"; return Json(400, v);
    }

    auto revoked = ctx.invites.RevokeAll(tenant_id, uid, core::UnixNow());
    if (!revoked.ok()) { crow::json::wvalue error; error["error"] = "Invitation is busy"; return Json(409, error); }
    auto rc = ctx.ldap_dir->DeleteKrbAttributes(tenant_id, uid);
    if (!rc.ok()) {
      std::fprintf(stderr, "[gatehouse][ldap] reset-krb failed for %s/%s: %s\n",
                   tenant_id.c_str(), uid.c_str(), rc.status().ToString().c_str());
      crow::json::wvalue v; v["ok"]=false; v["error"]=rc.status().ToString(); return Json(502, v);
    }

    crow::json::wvalue v; v["ok"]=true; return Json(200, v);
  });

  // ---- API: Reset invitation (revoke all + delete krb attrs + new invite) ----
  app.route_dynamic(base_uri + "/api/admin/user/reset-invite").methods("POST"_method)([&ctx](const crow::request& req) {
    const auto connection = ctx.db.ConnectForThread();
    if (!connection.ok()) return HtmlPage(503, "<h1>Database unavailable</h1>");
    auto s = RequireAuth(ctx, req);
    if (!s.has_value()) { crow::json::wvalue v; v["ok"]=false; v["error"]="unauthenticated"; return Json(401, v); }
    if (!CsrfOkHeader(req, *s)) { crow::json::wvalue v; v["ok"]=false; v["error"]="invalid csrf token"; return Json(403, v); }
    if (!IsAdminUid(ctx, s->uid)) { crow::json::wvalue v; v["ok"]=false; v["error"]="forbidden"; return Json(403, v); }

    auto body = crow::json::load(req.body);
    if (!body || !body.has("tenant_id") || !body.has("uid")) {
      crow::json::wvalue v; v["ok"]=false; v["error"]="invalid json (need tenant_id, uid)"; return Json(400, v);
    }
    const std::string tenant_id = std::string(body["tenant_id"].s());
    const std::string uid       = std::string(body["uid"].s());
    if (tenant_id.empty() || uid.empty()) {
      crow::json::wvalue v; v["ok"]=false; v["error"]="tenant_id/uid empty"; return Json(400, v);
    }
    auto safe_name = [](const std::string& n) -> bool {
      if (n.empty() || n.size() > 64) return false;
      for (char c : n) if (!((c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='-'||c=='_'||c=='.')) return false;
      return true;
    };
    if (!safe_name(uid) || !safe_name(tenant_id)) {
      crow::json::wvalue v; v["ok"]=false; v["error"]="invalid characters in tenant_id or uid"; return Json(400, v);
    }

    const std::int64_t now = core::UnixNow();

    // 1. Revoke all invites (including completed).
    auto revoked = ctx.invites.RevokeAll(tenant_id, uid, now);
    if (!revoked.ok()) { crow::json::wvalue error; error["error"] = "Invitation is busy"; return Json(409, error); }

    // 2. Delete Kerberos attributes so the principal can be recreated.
    if (ctx.ldap_dir.has_value()) {
      auto krc = ctx.ldap_dir->DeleteKrbAttributes(tenant_id, uid);
      if (!krc.ok()) {
        std::fprintf(stderr, "[gatehouse][reset-invite] DeleteKrbAttributes failed for %s/%s: %s\n",
                     tenant_id.c_str(), uid.c_str(), krc.status().ToString().c_str());
      }
    }

    // 3. Look up current email from LDAP.
    std::optional<std::string> mail;
    if (ctx.ldap_dir.has_value()) {
      auto rc = ctx.ldap_dir->LookupMail(tenant_id, uid);
      if (!rc.ok()) {
        crow::json::wvalue v; v["ok"]=false; v["error"]="directory lookup failed"; return Json(502, v);
      }
      mail = rc.value();
    } else if (!ctx.cfg.ldif_path.empty()) {
      mail = ctx.ldif_dir.LookupMail(tenant_id, uid);
    } else {
      crow::json::wvalue v; v["ok"]=false; v["error"]="no directory configured"; return Json(409, v);
    }
    if (!mail.has_value() || mail->empty()) {
      crow::json::wvalue v; v["ok"]=false; v["error"]="user not found or missing mail"; return Json(404, v);
    }

    // 4. Create new invite and send email.
    auto token_bytes     = core::RandomBytes(32);
    auto invite_id_bytes = core::RandomBytes(16);
    if (!token_bytes.ok() || !invite_id_bytes.ok()) {
      crow::json::wvalue v; v["ok"]=false; v["error"]="internal error"; return Json(500, v);
    }
    const std::string token_hex = core::HexEncode(token_bytes.value());
    auto token_hash = core::Sha256(token_bytes.value());
    if (!token_hash.ok()) { crow::json::wvalue v; v["ok"]=false; v["error"]="internal error"; return Json(500, v); }

    infra::InviteRow row;
    row.invite_id     = core::HexEncode(invite_id_bytes.value());
    row.tenant_id     = tenant_id;
    row.invited_email = *mail;
    row.invited_uid   = uid;
    row.token_hash    = std::move(token_hash.value());
    row.status        = infra::InviteStatus::kInvited;
    row.created_at    = now;
    row.expires_at    = now + ctx.cfg.invite_ttl_seconds;
    row.created_by    = s->uid;

    auto ins = ctx.invites.Insert(row);
    if (!ins.ok()) { crow::json::wvalue v; v["ok"]=false; v["error"]=ins.status().ToString(); return Json(500, v); }

    const std::string invite_url = ctx.cfg.public_base_url + "/invite/accept?token=" + token_hex;
    const std::string subject    = "[" + ctx.cfg.instance_title + "] You have been invited to " + tenant_id;
    const std::string body_txt   =
        "Hello,\n\nyou have been invited to " + ctx.cfg.instance_title + ".\n\n"
        "Tenant: " + tenant_id + "\nUser: " + uid + "\n\n"
        "Accept invitation:\n" + invite_url + "\n\n";

    auto mail_rc = ctx.email.SendText(*mail, subject, body_txt);
    if (!mail_rc.ok()) { crow::json::wvalue v; v["ok"]=false; v["error"]="mail send failed: " + mail_rc.status().ToString(); return Json(502, v); }

    crow::json::wvalue v;
    v["ok"]            = true;
    v["tenant_id"]     = tenant_id;
    v["uid"]           = uid;
    v["invited_email"] = *mail;
    v["expires_at"]    = row.expires_at;
    return Json(200, v);
  });

  // ---- API: List tenants ----
  app.route_dynamic(base_uri + "/api/admin/tenants").methods("GET"_method)([&ctx](const crow::request& req) {
    const auto connection = ctx.db.ConnectForThread();
    if (!connection.ok()) return HtmlPage(503, "<h1>Database unavailable</h1>");
    auto s = RequireAuth(ctx, req);
    if (!s.has_value()) { crow::json::wvalue v; v["ok"]=false; v["error"]="unauthenticated"; return Json(401, v); }
    if (!IsAdminUid(ctx, s->uid)) { crow::json::wvalue v; v["ok"]=false; v["error"]="forbidden"; return Json(403, v); }
    if (!ctx.ldap_dir.has_value()) { crow::json::wvalue v; v["ok"]=false; v["error"]="LDAP not configured"; return Json(500, v); }

    auto res = ctx.ldap_dir->ListTenants();
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

  // ---- API: List users with hosts for a tenant ----
  app.route_dynamic(base_uri + "/api/admin/tenant-users").methods("GET"_method)([&ctx](const crow::request& req) {
    const auto connection = ctx.db.ConnectForThread();
    if (!connection.ok()) return HtmlPage(503, "<h1>Database unavailable</h1>");
    auto s = RequireAuth(ctx, req);
    if (!s.has_value()) { crow::json::wvalue v; v["ok"]=false; v["error"]="unauthenticated"; return Json(401, v); }
    if (!CsrfOkHeader(req, *s)) { crow::json::wvalue v; v["ok"]=false; v["error"]="invalid csrf token"; return Json(403, v); }
    if (!IsAdminUid(ctx, s->uid)) { crow::json::wvalue v; v["ok"]=false; v["error"]="forbidden"; return Json(403, v); }
    if (!ctx.ldap_dir.has_value()) { crow::json::wvalue v; v["ok"]=false; v["error"]="LDAP not configured"; return Json(500, v); }

    const std::string tenant = req.url_params.get("tenant_id") ? req.url_params.get("tenant_id") : "";
    if (tenant.empty()) { crow::json::wvalue v; v["ok"]=false; v["error"]="tenant_id required"; return Json(400, v); }

    auto res = ctx.ldap_dir->ListUsersWithHosts(tenant);
    if (!res.ok()) {
      std::fprintf(stderr, "[gatehouse][ldap] ListUsersWithHosts failed for %s: %s\n",
                   tenant.c_str(), res.status().ToString().c_str());
      crow::json::wvalue v; v["ok"]=false; v["error"]="directory lookup failed"; return Json(502, v);
    }

    // Build uid -> latest invite map.
    auto inv_res = ctx.invites.GetLatestPerUid(tenant);
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
}

}  // namespace gatehouse::app
