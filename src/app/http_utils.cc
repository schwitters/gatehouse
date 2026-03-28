#include "app/http_utils.h"

#include <string>

namespace gatehouse::app {

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

std::string CookieValueFromHeader(const crow::request& req,
                                  const std::string& cookie_name) {
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

std::string InviteStatusName(infra::InviteStatus s) {
  switch (s) {
    case infra::InviteStatus::kInvited:        return "Invited";
    case infra::InviteStatus::kLinkVerified:   return "LinkVerified";
    case infra::InviteStatus::kStepupSent:     return "StepupSent";
    case infra::InviteStatus::kStepupVerified: return "StepupVerified";
    case infra::InviteStatus::kCompleted:      return "Completed";
    case infra::InviteStatus::kExpired:        return "Expired";
    case infra::InviteStatus::kRevoked:        return "Revoked";
  }
  return "Unknown";
}

}  // namespace gatehouse::app
