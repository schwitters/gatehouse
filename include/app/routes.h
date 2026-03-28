#pragma once

#include "app/server_context.h"
#include "crow.h"

namespace gatehouse::app {

// Miscellaneous routes: /robots.txt, /api/healthz.
void RegisterMiscRoutes(crow::SimpleApp& app, ServerContext& ctx);

// Authentication routes: /login, /auth/logout, /auth/login, /api/auth/login.
void RegisterAuthRoutes(crow::SimpleApp& app, ServerContext& ctx);

// Portal routes: /, /portal, /portal/changepw, /api/me, /api/me/hosts.
void RegisterPortalRoutes(crow::SimpleApp& app, ServerContext& ctx);

// Invite-flow routes: /invite/accept, /invite/complete, /invite/otp/*.
void RegisterInviteRoutes(crow::SimpleApp& app, ServerContext& ctx);

// Admin routes: /admin/*, /api/admin/*.
void RegisterAdminRoutes(crow::SimpleApp& app, ServerContext& ctx);

// Guacamole routes: /api/me/guacamole-session, /api/cred-fetch/ticket.
void RegisterGuacamoleRoutes(crow::SimpleApp& app, ServerContext& ctx);

}  // namespace gatehouse::app
