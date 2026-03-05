#include "core/crypto_aead.h"

#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include <openssl/evp.h>

namespace gatehouse::core {
namespace {

int HexVal(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
  if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
  return -1;
}

}  // namespace

Result<std::vector<std::uint8_t>> HexDecode(std::string_view hex) {
  if ((hex.size() % 2) != 0) {
    return Result<std::vector<std::uint8_t>>::Err(
        Status::Error(StatusCode::kInvalidArgument, "hex length must be even"));
  }
  std::vector<std::uint8_t> out;
  out.reserve(hex.size() / 2);
  for (std::size_t i = 0; i < hex.size(); i += 2) {
    const int hi = HexVal(hex[i]);
    const int lo = HexVal(hex[i + 1]);
    if (hi < 0 || lo < 0) {
      return Result<std::vector<std::uint8_t>>::Err(
          Status::Error(StatusCode::kInvalidArgument, "hex contains invalid character"));
    }
    out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
  }
  return Result<std::vector<std::uint8_t>>::Ok(std::move(out));
}

Result<std::vector<std::uint8_t>> Aes256GcmEncrypt(
    const std::vector<std::uint8_t>& key32,
    const std::vector<std::uint8_t>& nonce12,
    std::string_view aad,
    const std::vector<std::uint8_t>& plaintext) {
  if (key32.size() != 32) {
    return Result<std::vector<std::uint8_t>>::Err(
        Status::Error(StatusCode::kInvalidArgument, "AES-256-GCM key must be 32 bytes"));
  }
  if (nonce12.size() != 12) {
    return Result<std::vector<std::uint8_t>>::Err(
        Status::Error(StatusCode::kInvalidArgument, "AES-256-GCM nonce must be 12 bytes"));
  }

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (ctx == nullptr) {
    return Result<std::vector<std::uint8_t>>::Err(
        Status::Error(StatusCode::kInternal, "EVP_CIPHER_CTX_new failed"));
  }

  std::vector<std::uint8_t> out;
  out.resize(plaintext.size() + 16);

  int ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
  if (ok != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return Result<std::vector<std::uint8_t>>::Err(
        Status::Error(StatusCode::kInternal, "EVP_EncryptInit_ex failed"));
  }

  ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                           static_cast<int>(nonce12.size()), nullptr);
  if (ok != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return Result<std::vector<std::uint8_t>>::Err(
        Status::Error(StatusCode::kInternal, "EVP_CTRL_GCM_SET_IVLEN failed"));
  }

  ok = EVP_EncryptInit_ex(ctx, nullptr, nullptr, key32.data(), nonce12.data());
  if (ok != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return Result<std::vector<std::uint8_t>>::Err(
        Status::Error(StatusCode::kInternal, "EVP_EncryptInit_ex(key/iv) failed"));
  }

  int len = 0;
  if (!aad.empty()) {
    ok = EVP_EncryptUpdate(ctx, nullptr, &len,
                          reinterpret_cast<const unsigned char*>(aad.data()),
                          static_cast<int>(aad.size()));
    if (ok != 1) {
      EVP_CIPHER_CTX_free(ctx);
      return Result<std::vector<std::uint8_t>>::Err(
          Status::Error(StatusCode::kInternal, "EVP_EncryptUpdate(aad) failed"));
    }
  }

  int out_len = 0;
  if (!plaintext.empty()) {
    ok = EVP_EncryptUpdate(ctx, out.data(), &len, plaintext.data(),
                          static_cast<int>(plaintext.size()));
    if (ok != 1) {
      EVP_CIPHER_CTX_free(ctx);
      return Result<std::vector<std::uint8_t>>::Err(
          Status::Error(StatusCode::kInternal, "EVP_EncryptUpdate(pt) failed"));
    }
    out_len += len;
  }

  ok = EVP_EncryptFinal_ex(ctx, out.data() + out_len, &len);
  if (ok != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return Result<std::vector<std::uint8_t>>::Err(
        Status::Error(StatusCode::kInternal, "EVP_EncryptFinal_ex failed"));
  }
  out_len += len;

  unsigned char tag[16];
  ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
  EVP_CIPHER_CTX_free(ctx);
  if (ok != 1) {
    return Result<std::vector<std::uint8_t>>::Err(
        Status::Error(StatusCode::kInternal, "EVP_CTRL_GCM_GET_TAG failed"));
  }

  if (out_len != static_cast<int>(plaintext.size())) {
    return Result<std::vector<std::uint8_t>>::Err(
        Status::Error(StatusCode::kInternal, "unexpected ciphertext length"));
  }
  std::memcpy(out.data() + plaintext.size(), tag, 16);
  return Result<std::vector<std::uint8_t>>::Ok(std::move(out));
}

Result<std::vector<std::uint8_t>> Aes256GcmDecrypt(
    const std::vector<std::uint8_t>& key32,
    const std::vector<std::uint8_t>& nonce12,
    std::string_view aad,
    const std::vector<std::uint8_t>& ciphertext_and_tag) {
  if (key32.size() != 32) {
    return Result<std::vector<std::uint8_t>>::Err(
        Status::Error(StatusCode::kInvalidArgument, "AES-256-GCM key must be 32 bytes"));
  }
  if (nonce12.size() != 12) {
    return Result<std::vector<std::uint8_t>>::Err(
        Status::Error(StatusCode::kInvalidArgument, "AES-256-GCM nonce must be 12 bytes"));
  }
  if (ciphertext_and_tag.size() < 16) {
    return Result<std::vector<std::uint8_t>>::Err(
        Status::Error(StatusCode::kInvalidArgument, "ciphertext too short"));
  }

  const std::size_t ct_len = ciphertext_and_tag.size() - 16;
  const unsigned char* tag = ciphertext_and_tag.data() + ct_len;

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (ctx == nullptr) {
    return Result<std::vector<std::uint8_t>>::Err(
        Status::Error(StatusCode::kInternal, "EVP_CIPHER_CTX_new failed"));
  }

  std::vector<std::uint8_t> pt;
  pt.resize(ct_len);

  int ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
  if (ok != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return Result<std::vector<std::uint8_t>>::Err(
        Status::Error(StatusCode::kInternal, "EVP_DecryptInit_ex failed"));
  }

  ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                           static_cast<int>(nonce12.size()), nullptr);
  if (ok != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return Result<std::vector<std::uint8_t>>::Err(
        Status::Error(StatusCode::kInternal, "EVP_CTRL_GCM_SET_IVLEN failed"));
  }

  ok = EVP_DecryptInit_ex(ctx, nullptr, nullptr, key32.data(), nonce12.data());
  if (ok != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return Result<std::vector<std::uint8_t>>::Err(
        Status::Error(StatusCode::kInternal, "EVP_DecryptInit_ex(key/iv) failed"));
  }

  int len = 0;
  if (!aad.empty()) {
    ok = EVP_DecryptUpdate(ctx, nullptr, &len,
                          reinterpret_cast<const unsigned char*>(aad.data()),
                          static_cast<int>(aad.size()));
    if (ok != 1) {
      EVP_CIPHER_CTX_free(ctx);
      return Result<std::vector<std::uint8_t>>::Err(
          Status::Error(StatusCode::kInternal, "EVP_DecryptUpdate(aad) failed"));
    }
  }

  int out_len = 0;
  if (ct_len > 0) {
    ok = EVP_DecryptUpdate(ctx, pt.data(), &len, ciphertext_and_tag.data(),
                          static_cast<int>(ct_len));
    if (ok != 1) {
      EVP_CIPHER_CTX_free(ctx);
      return Result<std::vector<std::uint8_t>>::Err(
          Status::Error(StatusCode::kInternal, "EVP_DecryptUpdate(ct) failed"));
    }
    out_len += len;
  }

  ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<unsigned char*>(tag));
  if (ok != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return Result<std::vector<std::uint8_t>>::Err(
        Status::Error(StatusCode::kInternal, "EVP_CTRL_GCM_SET_TAG failed"));
  }

  ok = EVP_DecryptFinal_ex(ctx, pt.data() + out_len, &len);
  EVP_CIPHER_CTX_free(ctx);

  if (ok != 1) {
    return Result<std::vector<std::uint8_t>>::Err(
        Status::Error(StatusCode::kUnauthenticated, "GCM tag verify failed"));
  }
  out_len += len;

  if (out_len != static_cast<int>(ct_len)) {
    return Result<std::vector<std::uint8_t>>::Err(
        Status::Error(StatusCode::kInternal, "unexpected plaintext length"));
  }
  return Result<std::vector<std::uint8_t>>::Ok(std::move(pt));
}

}  // namespace gatehouse::core
