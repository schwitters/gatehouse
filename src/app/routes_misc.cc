#include "app/routes.h"

#include "app/http_utils.h"
#include "crow.h"
#include "crow/json.h"

namespace gatehouse::app {

void RegisterMiscRoutes(crow::SimpleApp& app, ServerContext& ctx) {
  const std::string& B = ctx.cfg.base_uri;

  // LOW-07: Instruct crawlers to stay out of admin and API paths.
  app.route_dynamic(B + "/robots.txt").methods("GET"_method)([&ctx] {
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

  app.route_dynamic(B + "/api/healthz").methods("GET"_method)([&ctx] {
    crow::json::wvalue v;
    v["status"] = "ok";
    v["db"] = ctx.db.is_open();
    return Json(200, v);
  });
}

}  // namespace gatehouse::app
