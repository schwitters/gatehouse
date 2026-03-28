#include "core/aes_cbc.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <cstdint>
#include <vector>

namespace gatehouse::core {

Result<std::vector<std::uint8_t>> Aes128CbcEncrypt(
    const std::vector<std::uint8_t>& key16,
    const std::vector<std::uint8_t>& plaintext) {
  if (key16.size() != 16) {
    return Result<std::vector<std::uint8_t>>::Err(
        Status::Error(StatusCode::kInvalidArgument, "key16 must be exactly 16 bytes"));
  }

  std::vector<std::uint8_t> iv(16);
  if (RAND_bytes(iv.data(), 16) != 1) {
    return Result<std::vector<std::uint8_t>>::Err(
        Status::Error(StatusCode::kInternal, "RAND_bytes failed"));
  }

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (ctx == nullptr) {
    return Result<std::vector<std::uint8_t>>::Err(
        Status::Error(StatusCode::kInternal, "EVP_CIPHER_CTX_new failed"));
  }

  if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr,
                         key16.data(), iv.data()) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return Result<std::vector<std::uint8_t>>::Err(
        Status::Error(StatusCode::kInternal, "EVP_EncryptInit_ex failed"));
  }

  // ciphertext can be at most plaintext.size() + one block (16 bytes for padding)
  std::vector<std::uint8_t> ciphertext(plaintext.size() + 16);
  int len = 0;
  if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                        plaintext.data(),
                        static_cast<int>(plaintext.size())) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return Result<std::vector<std::uint8_t>>::Err(
        Status::Error(StatusCode::kInternal, "EVP_EncryptUpdate failed"));
  }
  int total = len;

  int final_len = 0;
  if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + total, &final_len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return Result<std::vector<std::uint8_t>>::Err(
        Status::Error(StatusCode::kInternal, "EVP_EncryptFinal_ex failed"));
  }
  EVP_CIPHER_CTX_free(ctx);
  total += final_len;
  ciphertext.resize(static_cast<std::size_t>(total));

  // Result = IV (16 bytes) || ciphertext
  std::vector<std::uint8_t> result;
  result.reserve(16 + ciphertext.size());
  result.insert(result.end(), iv.begin(), iv.end());
  result.insert(result.end(), ciphertext.begin(), ciphertext.end());
  return Result<std::vector<std::uint8_t>>::Ok(std::move(result));
}

namespace {
constexpr const char kB64Chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
}

std::string Base64Encode(const std::vector<std::uint8_t>& data) {
  std::string out;
  out.reserve(((data.size() + 2) / 3) * 4);
  for (std::size_t i = 0; i < data.size(); i += 3) {
    const std::uint32_t b0 = data[i];
    const std::uint32_t b1 = (i + 1 < data.size()) ? data[i + 1] : 0u;
    const std::uint32_t b2 = (i + 2 < data.size()) ? data[i + 2] : 0u;
    const std::uint32_t triple = (b0 << 16) | (b1 << 8) | b2;
    out.push_back(kB64Chars[(triple >> 18) & 0x3Fu]);
    out.push_back(kB64Chars[(triple >> 12) & 0x3Fu]);
    out.push_back((i + 1 < data.size()) ? kB64Chars[(triple >> 6) & 0x3Fu] : '=');
    out.push_back((i + 2 < data.size()) ? kB64Chars[triple & 0x3Fu] : '=');
  }
  return out;
}

std::string Base64UrlEncode(const std::vector<std::uint8_t>& data) {
  std::string s = Base64Encode(data);
  for (char& c : s) {
    if (c == '+') c = '-';
    else if (c == '/') c = '_';
  }
  while (!s.empty() && s.back() == '=') s.pop_back();
  return s;
}

}  // namespace gatehouse::core
