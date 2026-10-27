#include "app/routes.h"

#include <cstdio>
#include <string>

#include "app/http_utils.h"
#include "core/url.h"
#include "crow.h"
#include "crow/json.h"
#include "infra/krb5_client.h"

namespace gatehouse::app {

void RegisterPortalRoutes(crow::SimpleApp& app, ServerContext& ctx) {
  const std::string& base_uri = ctx.cfg.base_uri;

  // ---- Root redirect ----
  app.route_dynamic(base_uri + "/").methods("GET"_method)([&ctx](const crow::request& req) {
    const auto connection = ctx.db.ConnectForThread();
    if (!connection.ok()) return HtmlPage(503, "<h1>Database unavailable</h1>");
    const std::string& B = ctx.cfg.base_uri;
    auto s = RequireAuth(ctx, req);
    if (!s.has_value()) return RedirectTo(B + "/login");
    return RedirectTo(B + "/portal");
  });

  // ---- Portal dashboard ----
  app.route_dynamic(base_uri + "/portal").methods("GET"_method)([&ctx](const crow::request& req) {
    const auto connection = ctx.db.ConnectForThread();
    if (!connection.ok()) return HtmlPage(503, "<h1>Database unavailable</h1>");
    const std::string& B = ctx.cfg.base_uri;
    auto s = RequireAuth(ctx, req);
    if (!s.has_value()) return RedirectTo(B + "/login");

    const bool is_admin = IsAdminUid(ctx, s->uid);
    std::string admin_block;
    if (is_admin) {
      admin_block = "<p><b>Admin</b>: ";
      admin_block += "<a href=\"" + B + "/admin/invites\">Invitations</a>";
      admin_block += " &nbsp;|&nbsp; ";
      admin_block += "<a href=\"" + B + "/admin/tenants\">Tenant &amp; User Overview</a>";
      admin_block += "</p>";
    }

    std::string html = "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">";
    html += "<title>" + HtmlEscape(ctx.cfg.instance_title) + " Portal</title>";
    html += "<style>body{font-family:system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:40px;max-width:760px;background:#f9f9f9;color:#222}";
    html += ".card{background:#fff;padding:24px;border-radius:12px;box-shadow:0 2px 8px rgba(0,0,0,0.05);margin-bottom:24px}";
    html += "h1{margin-top:0} .host-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:16px;margin-top:16px}";
    html += ".host-card{padding:16px;border:1px solid #e0e0e0;border-radius:8px;background:#fafafa}";
    html += ".host-card b{display:block;font-size:1.1em;color:#0b57d0} .host-card code{font-size:0.9em;color:#555;background:#eee;padding:2px 6px;border-radius:4px}";
    html += "button{padding:10px 16px;border:none;border-radius:6px;background:#0b57d0;color:#fff;cursor:pointer;font-weight:600}";
    html += "button:hover{background:#0842a0} a{color:#0b57d0;text-decoration:none;font-weight:600} a:hover{text-decoration:underline}";
    html += "</style></head><body>";
    html += "<h1>" + HtmlEscape(ctx.cfg.instance_title) + " Portal</h1>";

    // Card: User Info
    html += "<div class=\"card\"><h3>Identity</h3>";
    html += "<p>Signed in as <b>" + HtmlEscape(s->uid) + "</b><br>";
    html += "Tenant: <code>" + HtmlEscape(s->tenant_id) + "</code></p>";
    if (!admin_block.empty()) html += admin_block;
    html += "</div>";

    // Card: Hosts (populated via JS)
    html += "<div class=\"card\"><h3>My Infrastructure</h3>";
    html += "<div id=\"hostContainer\"><p style=\"color:#666\">Loading hosts...</p></div>";
    html += "</div>";

    // Card: Security
    html += "<div class=\"card\"><h3>Security</h3>";
    html += "<p style=\"color:#555\">Manage your Kerberos account credentials.</p>";
    html += "<a href=\"" + B + "/portal/changepw\" style=\"display:inline-block;padding:10px 16px;background:#0b57d0;color:#fff;text-decoration:none;border-radius:6px;font-weight:600\">Change Password</a>";
    html += "</div>";

    // Card: Logout (CSRF token embedded)
    html += "<form method=\"post\" action=\"" + B + "/auth/logout\">";
    html += "<input type=\"hidden\" name=\"_csrf\" value=\"" + s->csrf_secret_hex + "\">";
    html += "<button type=\"submit\">Logout</button></form>";

    // JavaScript to fetch and render hosts
    // MED-08: Use DOM APIs with textContent to avoid innerHTML XSS from LDAP data.
    // Build _GUAC_PROTOS: list of protocols for which Connect buttons are shown.
    // Empty guac_enabled_protocols in config means "all" → ['rdp','ssh'].
    const bool guac_on = !ctx.cfg.guacamole_url.empty() && !ctx.cfg.guacamole_secret.empty();
    std::string guac_protos_js;
    if (!guac_on) {
      guac_protos_js = "[]";
    } else if (ctx.cfg.guac_enabled_protocols.empty()) {
      guac_protos_js = "['rdp','ssh']";
    } else {
      guac_protos_js = "[";
      for (const auto& p : ctx.cfg.guac_enabled_protocols)
        guac_protos_js += "'" + p + "',";
      guac_protos_js.back() = ']';
    }

    html += "<script>";
    html += "const _B='" + B + "';";
    html += "const _GUAC_PROTOS=" + guac_protos_js + ";";
    html += "</script><script src=\"" + HtmlEscape(B) + "/assets/portal.js\"></script>";


    html += "</body></html>";
    return HtmlPage(200, html);
  });

  // ---- Change password (GET + POST) ----
  app.route_dynamic(base_uri + "/portal/changepw").methods("GET"_method, "POST"_method)(
      [&ctx](const crow::request& req) {
    const auto connection = ctx.db.ConnectForThread();
    if (!connection.ok()) return HtmlPage(503, "<h1>Database unavailable</h1>");
    const std::string& B = ctx.cfg.base_uri;
    auto s = RequireAuth(ctx, req);
    if (!s.has_value()) return RedirectTo(B + "/login");

    if (req.method == "GET"_method) {
      const std::string err = req.url_params.get("err") ? req.url_params.get("err") : "";
      std::string html = "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">";
      html += "<title>Change Password \xe2\x80\x93 " + HtmlEscape(ctx.cfg.instance_title) + "</title>";
      html += "<style>body{font-family:system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:40px;max-width:540px;background:#f9f9f9;color:#222}";
      html += ".card{background:#fff;padding:24px;border-radius:12px;box-shadow:0 2px 8px rgba(0,0,0,0.05)}";
      html += "label{display:block;margin-top:16px;font-weight:500;font-size:0.95em} input{width:100%;padding:10px;margin-top:6px;border:1px solid #ccc;border-radius:6px;box-sizing:border-box}";
      html += "button{margin-top:24px;padding:12px 16px;border:none;border-radius:6px;background:#0b57d0;color:#fff;cursor:pointer;font-weight:600;width:100%;font-size:1em}";
      html += "button:hover{background:#0842a0} a{color:#0b57d0;text-decoration:none;font-weight:500} a:hover{text-decoration:underline}";
      html += "</style></head><body>";
      html += "<p><a href=\"" + B + "/portal\">&larr; Back to Dashboard</a></p>";
      html += "<h1>Change Password</h1>";
      html += "<div class=\"card\">";
      if (!err.empty()) html += "<div style=\"color:#b00020;background:#fce8e6;padding:12px;border-radius:8px;margin-bottom:16px\"><b>Error:</b> " + HtmlEscape(err) + "</div>";
      html += "<form method=\"post\" action=\"" + B + "/portal/changepw\">";
      html += "<input type=\"hidden\" name=\"_csrf\" value=\"" + s->csrf_secret_hex + "\">";
      html += "<label>Old Password <input type=\"password\" name=\"old_password\" required autofocus></label>";
      html += "<label>New Password <input type=\"password\" name=\"new_password\" required minlength=\"8\"></label>";
      html += "<label>Confirm New Password <input type=\"password\" name=\"new_password_confirm\" required minlength=\"8\"></label>";
      html += "<button type=\"submit\">Update Password</button>";
      html += "</form></div></body></html>";
      return HtmlPage(200, html);
    }

    // POST: change password
    if (!CsrfOkForm(req, *s)) return HtmlPage(403, "<h1>Invalid CSRF token</h1>");

    const std::string old_pw  = core::FormGet(req.body, "old_password").value_or("");
    const std::string new_pw  = core::FormGet(req.body, "new_password").value_or("");
    const std::string conf_pw = core::FormGet(req.body, "new_password_confirm").value_or("");

    if (old_pw.empty() || new_pw.empty()) return RedirectTo(B + "/portal/changepw?err=Missing+password+fields");
    if (new_pw.size() < 8) return RedirectTo(B + "/portal/changepw?err=New+password+must+be+at+least+8+characters");
    if (new_pw != conf_pw) return RedirectTo(B + "/portal/changepw?err=New+passwords+do+not+match");

    infra::Krb5Client krb(infra::Krb5Config{.realm = ctx.cfg.auth_cfg.krb5_realm});
    auto rc = krb.ChangePassword(s->uid, old_pw, new_pw);

    if (!rc.ok()) {
      std::fprintf(stderr, "[gatehouse][changepw] KDC error for %s: %s\n",
                   s->uid.c_str(), rc.status().ToString().c_str());
      const char* err_param;
      if (rc.status().code() == core::StatusCode::kUnavailable) {
        err_param = "Password+service+temporarily+unavailable+%E2%80%94+contact+admin";
      } else if (rc.status().code() == core::StatusCode::kUnauthenticated) {
        err_param = "Old+password+incorrect";
      } else {
        err_param = "Password+change+failed.+Ensure+new+password+meets+policy.";
      }
      return RedirectTo(B + "/portal/changepw?err=" + err_param);
    }

    return RedirectTo(B + "/portal?ok=Password+successfully+changed");
  });

  // ---- API: current user info ----
  app.route_dynamic(base_uri + "/api/me").methods("GET"_method)([&ctx](const crow::request& req) {
    const auto connection = ctx.db.ConnectForThread();
    if (!connection.ok()) return HtmlPage(503, "<h1>Database unavailable</h1>");
    auto s = RequireAuth(ctx, req);
    if (!s.has_value()) {
      crow::json::wvalue v; v["ok"]=false; v["error"]="unauthenticated"; return Json(401, v);
    }
    crow::json::wvalue v;
    v["ok"] = true;
    v["uid"] = s->uid;
    v["tenant_id"] = s->tenant_id;
    v["expires_at"] = s->expires_at;
    return Json(200, v);
  });

  // ---- API: user's managed hosts ----
  app.route_dynamic(base_uri + "/api/me/hosts").methods("GET"_method)([&ctx](const crow::request& req) {
    const auto connection = ctx.db.ConnectForThread();
    if (!connection.ok()) return HtmlPage(503, "<h1>Database unavailable</h1>");
    auto s = RequireAuth(ctx, req);
    if (!s.has_value()) {
      crow::json::wvalue v; v["ok"]=false; v["error"]="unauthenticated"; return Json(401, v);
    }
    if (!ctx.ldap_dir.has_value()) {
      crow::json::wvalue v; v["ok"]=false; v["error"]="LDAP not configured"; return Json(500, v);
    }

    auto hr = ctx.ldap_dir->GetUserHosts(s->tenant_id, s->uid);
    if (!hr.ok()) {
      crow::json::wvalue v; v["ok"]=false; v["error"]=hr.status().ToString(); return Json(502, v);
    }

    crow::json::wvalue v;
    v["ok"] = true;
    v["items"] = crow::json::wvalue::list();
    unsigned int idx = 0;
    for (const auto& h : hr.value()) {
      crow::json::wvalue it;
      it["hostname"] = h.hostname;
      it["ip"] = h.ip;
      it["dn"] = h.dn;
      it["protocol"] = h.protocol;
      v["items"][idx++] = std::move(it);
    }
    return Json(200, v);
  });
}

}  // namespace gatehouse::app
