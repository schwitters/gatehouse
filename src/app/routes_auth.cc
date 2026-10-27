#include "app/routes.h"
#include "web_assets.h"

#include <cstdio>
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

const char* kLoginPageTemplate = assets::k_login;

}  // namespace

void RegisterAuthRoutes(crow::SimpleApp& app, ServerContext& ctx) {
  const std::string& base_uri = ctx.cfg.base_uri;

  // ---- HTML login page ----
  app.route_dynamic(base_uri + "/login").methods("GET"_method)([&ctx](const crow::request& req) {
    const auto connection = ctx.db.ConnectForThread();
    if (!connection.ok()) return HtmlPage(503, "<h1>Database unavailable</h1>");
    const std::string& B = ctx.cfg.base_uri;
    const std::string err = req.url_params.get("err") ? req.url_params.get("err") : "";
    std::string page = ApplyTitle(kLoginPageTemplate, ctx.cfg.instance_title);
    // Substitute %B% with the configured base URI
    const std::size_t bp = page.find("%B%");
    if (bp != std::string::npos) page.replace(bp, 3, B);
    if (!err.empty()) {
      const std::string block = std::string("<div class=\"err\">") + HtmlEscape(err) + "</div>";
      const std::size_t pos = page.find("%ERROR%");
      if (pos != std::string::npos) page.replace(pos, 7, block);
    } else {
      const std::size_t pos = page.find("%ERROR%");
      if (pos != std::string::npos) page.replace(pos, 7, "");
    }
    return HtmlPage(200, page);
  });

  // ---- Logout ----
  app.route_dynamic(base_uri + "/auth/logout").methods("POST"_method)([&ctx](const crow::request& req) {
    const auto connection = ctx.db.ConnectForThread();
    if (!connection.ok()) return HtmlPage(503, "<h1>Database unavailable</h1>");
    const std::string& B = ctx.cfg.base_uri;
    const std::string cookie_path = B.empty() ? "/" : B + "/";
    auto s = RequireAuth(ctx, req);
    if (s.has_value() && !CsrfOkForm(req, *s)) {
      return HtmlPage(403, "<h1>Invalid CSRF token</h1>");
    }
    const std::string sid = CookieValueFromHeader(req, ctx.cfg.session_cookie_name);
    if (!sid.empty()) {
      const auto deleted = ctx.sessions.DeleteBySid(sid);
      if (!deleted.ok()) return HtmlPage(503, "<h1>Logout could not finish</h1>");
    }
    auto r = RedirectTo(B + "/login");
    r.add_header("Set-Cookie",
                 ctx.cfg.session_cookie_name + "=deleted; Path=" + cookie_path + "; Max-Age=0; HttpOnly; SameSite=Lax");
    r.add_header("Set-Cookie", "gh_csrf=deleted; Path=" + cookie_path + "; Max-Age=0; SameSite=Strict");
    return r;
  });

  // ---- HTML form login ----
  app.route_dynamic(base_uri + "/auth/login").methods("POST"_method)([&ctx](const crow::request& req) {
    const auto connection = ctx.db.ConnectForThread();
    if (!connection.ok()) return HtmlPage(503, "<h1>Database unavailable</h1>");
    const std::string& B = ctx.cfg.base_uri;
    const std::string cookie_path = B.empty() ? "/" : B + "/";

    const std::optional<std::string> u = core::FormGet(req.body, "username");
    const std::optional<std::string> p = core::FormGet(req.body, "password");

    LoginRequest lr;
    lr.username = u.value_or("");
    lr.password = p.value_or("");

    std::string account_key = lr.username;
    const std::string realm_suffix = "@" + ctx.cfg.auth_cfg.krb5_realm;
    if (account_key.ends_with(realm_suffix)) {
      account_key.resize(account_key.size() - realm_suffix.size());
    }
    if (!ctx.rate_limiter.Check(account_key)) {
      return HtmlPage(429, "<h1>Too many login attempts</h1>");
    }

    auto vr = ctx.auth.Verify(lr);
    if (!vr.ok() || !vr.value().has_value()) {
      std::fprintf(stderr, "[gatehouse][login] failed user='%s' ip=%s\n",
                   SanitizeForLog(lr.username).c_str(),
                   SanitizeForLog(req.remote_ip_address).c_str());
      return RedirectTo(B + "/login?err=Invalid+credentials");
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
      std::fprintf(stderr, "[gatehouse][login] ticket storage failed uid='%s': %s\n",
                   SanitizeForLog(principal.uid).c_str(),
                   ticket_id.status().ToString().c_str());
      return RedirectTo(B + "/login?err=Internal+error");
    }

    auto sid_bytes = core::RandomBytes(32);
    auto csrf_bytes = core::RandomBytes(32);
    if (!sid_bytes.ok() || !csrf_bytes.ok()) {
      std::fprintf(stderr, "[gatehouse][login] random bytes failed uid='%s': %s\n",
                   SanitizeForLog(principal.uid).c_str(),
                   (!sid_bytes.ok() ? sid_bytes.status().ToString()
                                    : csrf_bytes.status().ToString()).c_str());
      return RedirectTo(B + "/login?err=Internal+error");
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
      std::fprintf(stderr, "[gatehouse][login] session insert failed uid='%s': %s\n",
                   SanitizeForLog(row.uid).c_str(),
                   ins.status().ToString().c_str());
      return RedirectTo(B + "/login?err=Internal+error");
    }

    std::fprintf(stderr, "[gatehouse][login] ok uid='%s' tenant='%s' ip=%s\n",
                 row.uid.c_str(), row.tenant_id.c_str(),
                 SanitizeForLog(req.remote_ip_address).c_str());
    auto r = RedirectTo(B + "/portal");
    r.add_header("Set-Cookie",
                 ctx.cfg.session_cookie_name + "=" + row.sid +
                     "; Path=" + cookie_path + "; Max-Age=" + std::to_string(ctx.cfg.session_ttl_seconds) +
                     "; HttpOnly; SameSite=Lax" +
                     (ctx.cfg.secure_cookies ? "; Secure" : ""));
    SetCsrfCookie(r, core::HexEncode(csrf_bytes.value()), ctx.cfg.session_ttl_seconds, B, ctx.cfg.secure_cookies);
    return r;
  });

  // ---- JSON login API ----
  app.route_dynamic(base_uri + "/api/auth/login").methods("POST"_method)([&ctx](const crow::request& req) {
    const auto connection = ctx.db.ConnectForThread();
    if (!connection.ok()) return HtmlPage(503, "<h1>Database unavailable</h1>");
    const std::string& B = ctx.cfg.base_uri;
    const std::string cookie_path = B.empty() ? "/" : B + "/";

    auto body = crow::json::load(req.body);
    if (!body) {
      crow::json::wvalue v; v["ok"]=false; v["error"]="invalid json"; return Json(400, v);
    }

    LoginRequest lr;
    if (body.has("username")) lr.username = std::string(body["username"].s());
    if (body.has("password")) lr.password = std::string(body["password"].s());

    std::string account_key = lr.username;
    const std::string realm_suffix = "@" + ctx.cfg.auth_cfg.krb5_realm;
    if (account_key.ends_with(realm_suffix)) {
      account_key.resize(account_key.size() - realm_suffix.size());
    }
    if (!ctx.rate_limiter.Check(account_key)) {
      crow::json::wvalue error;
      error["ok"] = false;
      error["error"] = "too many login attempts";
      return Json(429, error);
    }

    auto vr = ctx.auth.Verify(lr);
    if (!vr.ok() || !vr.value().has_value()) {
      std::fprintf(stderr, "[gatehouse][api/login] failed user='%s' ip=%s\n",
                   SanitizeForLog(lr.username).c_str(),
                   SanitizeForLog(req.remote_ip_address).c_str());
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
      std::fprintf(stderr, "[gatehouse][api/login] ticket storage failed uid='%s': %s\n",
                   SanitizeForLog(principal.uid).c_str(),
                   ticket_id.status().ToString().c_str());
      crow::json::wvalue v; v["ok"]=false; v["error"]="internal error"; return Json(500, v);
    }

    auto sid_bytes = core::RandomBytes(32);
    auto csrf_bytes = core::RandomBytes(32);
    if (!sid_bytes.ok() || !csrf_bytes.ok()) {
      std::fprintf(stderr, "[gatehouse][api/login] random bytes failed uid='%s': %s\n",
                   SanitizeForLog(principal.uid).c_str(),
                   (!sid_bytes.ok() ? sid_bytes.status().ToString()
                                    : csrf_bytes.status().ToString()).c_str());
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
      std::fprintf(stderr, "[gatehouse][api/login] session insert failed uid='%s': %s\n",
                   SanitizeForLog(row.uid).c_str(),
                   ins.status().ToString().c_str());
      crow::json::wvalue v; v["ok"]=false; v["error"]="internal error"; return Json(500, v);
    }

    std::fprintf(stderr, "[gatehouse][api/login] ok uid='%s' tenant='%s' ip=%s\n",
                 row.uid.c_str(), row.tenant_id.c_str(),
                 SanitizeForLog(req.remote_ip_address).c_str());
    crow::json::wvalue v;
    v["ok"] = true;
    v["uid"] = row.uid;
    v["tenant_id"] = row.tenant_id;
    v["expires_at"] = row.expires_at;

    auto resp = Json(200, v);
    resp.add_header("Set-Cookie",
                    ctx.cfg.session_cookie_name + "=" + row.sid +
                        "; Path=" + cookie_path + "; Max-Age=" + std::to_string(ctx.cfg.session_ttl_seconds) +
                        "; HttpOnly; SameSite=Lax" +
                        (ctx.cfg.secure_cookies ? "; Secure" : ""));
    SetCsrfCookie(resp, core::HexEncode(csrf_bytes.value()), ctx.cfg.session_ttl_seconds, B, ctx.cfg.secure_cookies);
    return resp;
  });
}

}  // namespace gatehouse::app
