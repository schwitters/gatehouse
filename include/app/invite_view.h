#pragma once
#include <string>
namespace gatehouse::app {
struct InviteView {
  std::string title, base_uri, csrf, tenant, uid, email, display, error;
  bool verified{false};
  bool sent{false};
};
[[nodiscard]] std::string RenderInvitation(const InviteView& view);
}  // namespace gatehouse::app
