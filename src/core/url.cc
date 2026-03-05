#include "core/url.h"

#include <cctype>
#include <optional>
#include <string>
#include <string_view>

namespace gatehouse::core {
namespace {

int HexVal(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
  return -1;
}

}  // namespace

std::optional<std::string> UrlDecode(std::string_view in) {
  std::string out;
  out.reserve(in.size());

  for (std::size_t i = 0; i < in.size(); ++i) {
    const char c = in[i];
    if (c == '+') {
      out.push_back(' ');
      continue;
    }
    if (c != '%') {
      out.push_back(c);
      continue;
    }
    if (i + 2 >= in.size()) return std::nullopt;
    const int hi = HexVal(in[i + 1]);
    const int lo = HexVal(in[i + 2]);
    if (hi < 0 || lo < 0) return std::nullopt;
    const char b = static_cast<char>((hi << 4) | lo);
    out.push_back(b);
    i += 2;
  }
  return out;
}

std::optional<std::string> FormGet(std::string_view body, std::string_view key) {
  // Naive but safe: scan pairs split by '&', then split by '='.
  std::size_t pos = 0;
  while (pos <= body.size()) {
    std::size_t amp = body.find('&', pos);
    if (amp == std::string_view::npos) amp = body.size();
    const std::string_view pair = body.substr(pos, amp - pos);

    const std::size_t eq = pair.find('=');
    const std::string_view k = (eq == std::string_view::npos) ? pair : pair.substr(0, eq);
    const std::string_view v = (eq == std::string_view::npos) ? std::string_view{} : pair.substr(eq + 1);

    if (k == key) {
      return UrlDecode(v);
    }

    if (amp == body.size()) break;
    pos = amp + 1;
  }
  return std::nullopt;
}

}  // namespace gatehouse::core
