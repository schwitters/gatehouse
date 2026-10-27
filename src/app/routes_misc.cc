#include "app/routes.h"
#include "web_assets.h"

#include "app/http_utils.h"
#include "crow.h"
#include "crow/json.h"

namespace gatehouse::app {

void RegisterMiscRoutes(crow::SimpleApp& app, ServerContext& ctx) {
  const std::string& base_uri = ctx.cfg.base_uri;

  app.route_dynamic(base_uri + "/assets/portal.js").methods("GET"_method)([] {
    crow::response response(200);
    response.set_header("Content-Type", "text/javascript; charset=utf-8");
    response.set_header("X-Content-Type-Options", "nosniff");
    response.body = assets::k_portal_js;
    return response;
  });

  app.route_dynamic(base_uri + "/assets/admin-tenants.js").methods("GET"_method)([] {
    crow::response response(200);
    response.set_header("Content-Type", "text/javascript; charset=utf-8");
    response.set_header("X-Content-Type-Options", "nosniff");
    response.body = assets::k_admin_tenants_js;
    return response;
  });

  // LOW-07: Instruct crawlers to stay out of admin and API paths.
  app.route_dynamic(base_uri + "/robots.txt").methods("GET"_method)([&ctx] {
    const std::string& B = ctx.cfg.base_uri;
    crow::response r;
    r.code = 200;
    r.set_header("Content-Type", "text/plain");
    r.body = "User-agent: *\n"
             "Disallow: " + B + "/admin\n"
             "Disallow: " + B + "/api\n"
             "Disallow: " + B + "/portal\n"
             "Disallow: " + B + "/invite\n";
    return r;
  });

  app.route_dynamic(base_uri + "/api/healthz").methods("GET"_method)([&ctx] {
    crow::json::wvalue v;
    v["status"] = "ok";
    v["db"] = ctx.db.is_open();
    return Json(200, v);
  });
}

}  // namespace gatehouse::app
