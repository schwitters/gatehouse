#pragma once

#include <cstdint>
#include <string>

#include "crow.h"
#include "crow/json.h"
#include "infra/invite_repo.h"

namespace gatehouse::app {

// Replace all occurrences of %TITLE% in `tmpl` with `title`.
std::string ApplyTitle(const char* tmpl, const std::string& title);

// Strip non-printable / control chars to prevent log-injection (LOW-05).
std::string SanitizeForLog(const std::string& s);

// Extract a named cookie value from the Cookie request header.
std::string CookieValueFromHeader(const crow::request& req,
                                  const std::string& cookie_name);

// Build an HTML response with standard security headers.
crow::response HtmlPage(int code, const std::string& html);

// Build a 302 redirect response.
crow::response RedirectTo(const std::string& where);

// Build a JSON response with standard headers.
crow::response Json(int code, const crow::json::wvalue& v);

// Human-readable name for an InviteStatus enum value.
std::string InviteStatusName(infra::InviteStatus s);

}  // namespace gatehouse::app
