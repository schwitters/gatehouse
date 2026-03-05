#pragma once

#include <optional>
#include <string>
#include <unordered_map>

#include "core/result.h"

namespace gatehouse::infra {

// Key: tenant_ou + '\n' + uid
class LdifDirectory final {
 public:
  LdifDirectory() = default;

  [[nodiscard]] core::Result<void> LoadFile(const std::string& path);

  [[nodiscard]] std::optional<std::string> LookupMail(const std::string& tenant_ou,
                                                      const std::string& uid) const;

 private:
  static std::string MakeKey(const std::string& tenant_ou, const std::string& uid);

  std::unordered_map<std::string, std::string> mail_by_tenant_uid_;
};

}  // namespace gatehouse::infra
