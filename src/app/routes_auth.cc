#include "app/routes.h"

#include <string>

#include "app/http_utils.h"
#include "core/hex.h"
#include "core/random.h"
#include "core/time.h"
#include "core/url.h"
#include "crow.h"
#include "crow/json.h"
#include "infra/session_repo.h"

namespace gatehouse::app {

namespace {

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

}  // namespace

void RegisterAuthRoutes(crow::SimpleApp& app, ServerContext& ctx) {
  // ---- HTML login page ----
  CROW_ROUTE(app, "/login").methods("GET"_method)([&ctx](const crow::request& req) {
    const std::string err = req.url_params.get("err") ? req.url_params.get("err") : "";
    std::string page = ApplyTitle(kLoginPageTemplate, ctx.cfg.instance_title);
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

  // ---- Logout ----
  CROW_ROUTE(app, "/auth/logout").methods("POST"_method)([&ctx](const crow::request& req) {
    auto s = RequireAuth(ctx, req);
    if (s.has_value() && !CsrfOkForm(req, *s)) {
      return HtmlPage(403, "<h1>Invalid CSRF token</h1>");
    }
    const std::string sid = CookieValueFromHeader(req, ctx.cfg.session_cookie_name);
    if (!sid.empty()) (void)ctx.sessions.DeleteBySid(sid);
    auto r = RedirectTo("/login");
    r.add_header("Set-Cookie",
                 ctx.cfg.session_cookie_name + "=deleted; Path=/; Max-Age=0; HttpOnly; SameSite=Lax");
    r.add_header("Set-Cookie", "gh_csrf=deleted; Path=/; Max-Age=0; SameSite=Strict");
    return r;
  });

  // ---- HTML form login ----
  CROW_ROUTE(app, "/auth/login").methods("POST"_method)([&ctx](const crow::request& req) {
    if (!ctx.rate_limiter.Check(req.remote_ip_address)) {
      return RedirectTo("/login?err=Too+many+login+attempts.+Please+try+again+in+5+minutes.");
    }

    const std::optional<std::string> u = core::FormGet(req.body, "username");
    const std::optional<std::string> p = core::FormGet(req.body, "password");

    LoginRequest lr;
    lr.username = u.value_or("");
    lr.password = p.value_or("");

    auto vr = ctx.auth.Verify(lr);
    if (!vr.ok() || !vr.value().has_value()) return RedirectTo("/login?err=Invalid+credentials");

    LoginPrincipal principal = *vr.value();
    if (ctx.ldap_dir.has_value()) {
      auto t_res = ctx.ldap_dir->ResolveTenantByUid(principal.uid);
      if (t_res.ok() && t_res.value().has_value()) {
        principal.tenant_id = t_res.value().value();
      }
    }
    auto ticket_id = StoreTicketIfPresent(ctx, principal);
    if (!ticket_id.ok()) return RedirectTo("/login?err=Internal+error");

    auto sid_bytes = core::RandomBytes(32);
    auto csrf_bytes = core::RandomBytes(32);
    if (!sid_bytes.ok() || !csrf_bytes.ok()) return RedirectTo("/login?err=Internal+error");

    infra::SessionRow row;
    row.sid = core::HexEncode(sid_bytes.value());
    row.uid = principal.uid;
    row.tenant_id = principal.tenant_id;
    row.created_at = core::UnixNow();
    row.expires_at = row.created_at + ctx.cfg.session_ttl_seconds;
    row.mfa_state = 0;
    row.ticket_id = ticket_id.value();

    const std::vector<std::uint8_t> ip_hash = HashRemoteIp(req.remote_ip_address);
    auto ins = ctx.sessions.Insert(row, csrf_bytes.value(), ip_hash);
    if (!ins.ok()) return RedirectTo("/login?err=Internal+error");

    auto r = RedirectTo("/portal");
    r.add_header("Set-Cookie",
                 ctx.cfg.session_cookie_name + "=" + row.sid +
                     "; Path=/; Max-Age=" + std::to_string(ctx.cfg.session_ttl_seconds) +
                     "; HttpOnly; SameSite=Lax" +
                     (ctx.cfg.secure_cookies ? "; Secure" : ""));
    SetCsrfCookie(r, core::HexEncode(csrf_bytes.value()), ctx.cfg.session_ttl_seconds);
    return r;
  });

  // ---- JSON login API ----
  CROW_ROUTE(app, "/api/auth/login").methods("POST"_method)([&ctx](const crow::request& req) {
    if (!ctx.rate_limiter.Check(req.remote_ip_address)) {
      crow::json::wvalue v; v["ok"]=false; v["error"]="too many login attempts"; return Json(429, v);
    }

    auto body = crow::json::load(req.body);
    if (!body) {
      crow::json::wvalue v; v["ok"]=false; v["error"]="invalid json"; return Json(400, v);
    }

    LoginRequest lr;
    if (body.has("username")) lr.username = std::string(body["username"].s());
    if (body.has("password")) lr.password = std::string(body["password"].s());

    auto vr = ctx.auth.Verify(lr);
    if (!vr.ok() || !vr.value().has_value()) {
      crow::json::wvalue v; v["ok"]=false; v["error"]="invalid credentials"; return Json(401, v);
    }

    LoginPrincipal principal = *vr.value();
    if (ctx.ldap_dir.has_value()) {
      auto t_res = ctx.ldap_dir->ResolveTenantByUid(principal.uid);
      if (t_res.ok() && t_res.value().has_value()) {
        principal.tenant_id = t_res.value().value();
      }
    }
    auto ticket_id = StoreTicketIfPresent(ctx, principal);
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
    row.expires_at = row.created_at + ctx.cfg.session_ttl_seconds;
    row.mfa_state = 0;
    row.ticket_id = ticket_id.value();

    const std::vector<std::uint8_t> ip_hash = HashRemoteIp(req.remote_ip_address);
    auto ins = ctx.sessions.Insert(row, csrf_bytes.value(), ip_hash);
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
                    ctx.cfg.session_cookie_name + "=" + row.sid +
                        "; Path=/; Max-Age=" + std::to_string(ctx.cfg.session_ttl_seconds) +
                        "; HttpOnly; SameSite=Lax" +
                        (ctx.cfg.secure_cookies ? "; Secure" : ""));
    SetCsrfCookie(resp, core::HexEncode(csrf_bytes.value()), ctx.cfg.session_ttl_seconds);
    return resp;
  });
}

}  // namespace gatehouse::app
