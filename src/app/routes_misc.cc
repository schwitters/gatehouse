#include "app/routes.h"

#include "app/http_utils.h"
#include "crow.h"
#include "crow/json.h"

namespace gatehouse::app {

void RegisterMiscRoutes(crow::SimpleApp& app, ServerContext& ctx) {
  // LOW-07: Instruct crawlers to stay out of admin and API paths.
  CROW_ROUTE(app, "/robots.txt").methods("GET"_method)([] {
    crow::response r;
    r.code = 200;
    r.set_header("Content-Type", "text/plain");
    r.body = "User-agent: *\nDisallow: /admin\nDisallow: /api\nDisallow: /portal\nDisallow: /invite\n";
    return r;
  });

  CROW_ROUTE(app, "/api/healthz").methods("GET"_method)([&ctx] {
    crow::json::wvalue v;
    v["status"] = "ok";
    v["db"] = ctx.db.is_open();
    return Json(200, v);
  });
}

}  // namespace gatehouse::app
