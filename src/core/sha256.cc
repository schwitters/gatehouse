#include "core/sha256.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <openssl/evp.h>

namespace gatehouse::core {

Result<std::vector<std::uint8_t>> Sha256(const std::vector<std::uint8_t>& data) {
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (ctx == nullptr) {
    return Result<std::vector<std::uint8_t>>::Err(
        Status::Error(StatusCode::kInternal, "EVP_MD_CTX_new failed"));
  }

  const EVP_MD* md = EVP_sha256();
  if (EVP_DigestInit_ex(ctx, md, nullptr) != 1) {
    EVP_MD_CTX_free(ctx);
    return Result<std::vector<std::uint8_t>>::Err(
        Status::Error(StatusCode::kInternal, "EVP_DigestInit_ex failed"));
  }

  if (!data.empty()) {
    if (EVP_DigestUpdate(ctx, data.data(), data.size()) != 1) {
      EVP_MD_CTX_free(ctx);
      return Result<std::vector<std::uint8_t>>::Err(
          Status::Error(StatusCode::kInternal, "EVP_DigestUpdate failed"));
    }
  }

  unsigned char out[32];
  unsigned int out_len = 0;
  if (EVP_DigestFinal_ex(ctx, out, &out_len) != 1 || out_len != 32) {
    EVP_MD_CTX_free(ctx);
    return Result<std::vector<std::uint8_t>>::Err(
        Status::Error(StatusCode::kInternal, "EVP_DigestFinal_ex failed"));
  }

  EVP_MD_CTX_free(ctx);
  return Result<std::vector<std::uint8_t>>::Ok(std::vector<std::uint8_t>(out, out + 32));
}

std::string Base64UrlNoPad(const std::vector<std::uint8_t>& data) {
  // Very small base64url encoder (no padding). Suitable for tokens.
  static constexpr char kB64[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

  std::string out;
  out.reserve(((data.size() + 2) / 3) * 4);

  std::size_t i = 0;
  while (i + 3 <= data.size()) {
    const std::uint32_t v =
        (static_cast<std::uint32_t>(data[i]) << 16) |
        (static_cast<std::uint32_t>(data[i + 1]) << 8) |
        (static_cast<std::uint32_t>(data[i + 2]) << 0);
    out.push_back(kB64[(v >> 18) & 0x3F]);
    out.push_back(kB64[(v >> 12) & 0x3F]);
    out.push_back(kB64[(v >> 6) & 0x3F]);
    out.push_back(kB64[(v >> 0) & 0x3F]);
    i += 3;
  }

  const std::size_t rem = data.size() - i;
  if (rem == 1) {
    const std::uint32_t v = static_cast<std::uint32_t>(data[i]) << 16;
    out.push_back(kB64[(v >> 18) & 0x3F]);
    out.push_back(kB64[(v >> 12) & 0x3F]);
    // no padding
  } else if (rem == 2) {
    const std::uint32_t v =
        (static_cast<std::uint32_t>(data[i]) << 16) |
        (static_cast<std::uint32_t>(data[i + 1]) << 8);
    out.push_back(kB64[(v >> 18) & 0x3F]);
    out.push_back(kB64[(v >> 12) & 0x3F]);
    out.push_back(kB64[(v >> 6) & 0x3F]);
    // no padding
  }

  return out;
}

}  // namespace gatehouse::core
