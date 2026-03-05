#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace gatehouse::core {

// Decodes %XX and '+' (plus->space). Returns nullopt on invalid encoding.
[[nodiscard]] std::optional<std::string> UrlDecode(std::string_view in);

// Extracts a key from application/x-www-form-urlencoded body.
[[nodiscard]] std::optional<std::string> FormGet(std::string_view body, std::string_view key);

}  // namespace gatehouse::core
