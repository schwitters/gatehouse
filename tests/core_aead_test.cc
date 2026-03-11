#include <gtest/gtest.h>

#include "core/crypto_aead.h"
#include "core/hex.h"
#include "core/status.h"

using namespace gatehouse::core;

namespace {

// 32-byte all-zero key
std::vector<uint8_t> ZeroKey32() { return std::vector<uint8_t>(32, 0x00); }

// 12-byte all-zero nonce
std::vector<uint8_t> ZeroNonce12() { return std::vector<uint8_t>(12, 0x00); }

}  // namespace

// ---------------------------------------------------------------------------
// HexDecode (re-exported from crypto_aead.h)
// ---------------------------------------------------------------------------
TEST(CryptoHexDecodeTest, BasicDecode) {
  auto r = HexDecode("ff00");
  ASSERT_TRUE(r.ok());
  EXPECT_EQ(r.value(), (std::vector<uint8_t>{0xFF, 0x00}));
}

// ---------------------------------------------------------------------------
// Aes256GcmEncrypt — error cases
// ---------------------------------------------------------------------------
TEST(Aes256GcmEncryptTest, KeyTooShort) {
  std::vector<uint8_t> short_key(16, 0x00);
  auto r = Aes256GcmEncrypt(short_key, ZeroNonce12(), "", {0x01});
  EXPECT_FALSE(r.ok());
  EXPECT_EQ(r.status().code(), StatusCode::kInvalidArgument);
}

TEST(Aes256GcmEncryptTest, KeyTooLong) {
  std::vector<uint8_t> long_key(64, 0x00);
  auto r = Aes256GcmEncrypt(long_key, ZeroNonce12(), "", {0x01});
  EXPECT_FALSE(r.ok());
  EXPECT_EQ(r.status().code(), StatusCode::kInvalidArgument);
}

TEST(Aes256GcmEncryptTest, NonceTooShort) {
  std::vector<uint8_t> short_nonce(8, 0x00);
  auto r = Aes256GcmEncrypt(ZeroKey32(), short_nonce, "", {0x01});
  EXPECT_FALSE(r.ok());
  EXPECT_EQ(r.status().code(), StatusCode::kInvalidArgument);
}

TEST(Aes256GcmEncryptTest, NonceTooLong) {
  std::vector<uint8_t> long_nonce(16, 0x00);
  auto r = Aes256GcmEncrypt(ZeroKey32(), long_nonce, "", {0x01});
  EXPECT_FALSE(r.ok());
  EXPECT_EQ(r.status().code(), StatusCode::kInvalidArgument);
}

// ---------------------------------------------------------------------------
// Aes256GcmEncrypt — output format
// ---------------------------------------------------------------------------
TEST(Aes256GcmEncryptTest, OutputLengthEqualsCiphertextPlusTag) {
  std::vector<uint8_t> pt = {0x01, 0x02, 0x03, 0x04};
  auto r = Aes256GcmEncrypt(ZeroKey32(), ZeroNonce12(), "", pt);
  ASSERT_TRUE(r.ok());
  // ciphertext length == plaintext length, plus 16-byte GCM tag
  EXPECT_EQ(r.value().size(), pt.size() + 16);
}

TEST(Aes256GcmEncryptTest, EmptyPlaintextProducesOnlyTag) {
  auto r = Aes256GcmEncrypt(ZeroKey32(), ZeroNonce12(), "", {});
  ASSERT_TRUE(r.ok());
  EXPECT_EQ(r.value().size(), 16u);  // tag only
}

TEST(Aes256GcmEncryptTest, Deterministic) {
  std::vector<uint8_t> pt = {0xAA, 0xBB, 0xCC};
  auto r1 = Aes256GcmEncrypt(ZeroKey32(), ZeroNonce12(), "", pt);
  auto r2 = Aes256GcmEncrypt(ZeroKey32(), ZeroNonce12(), "", pt);
  ASSERT_TRUE(r1.ok());
  ASSERT_TRUE(r2.ok());
  EXPECT_EQ(r1.value(), r2.value());
}

TEST(Aes256GcmEncryptTest, DifferentNoncesProduceDifferentCiphertext) {
  std::vector<uint8_t> pt = {0x01, 0x02, 0x03};
  std::vector<uint8_t> nonce1(12, 0x00);
  std::vector<uint8_t> nonce2(12, 0x01);
  auto r1 = Aes256GcmEncrypt(ZeroKey32(), nonce1, "", pt);
  auto r2 = Aes256GcmEncrypt(ZeroKey32(), nonce2, "", pt);
  ASSERT_TRUE(r1.ok());
  ASSERT_TRUE(r2.ok());
  EXPECT_NE(r1.value(), r2.value());
}

TEST(Aes256GcmEncryptTest, DifferentKeysProduceDifferentCiphertext) {
  std::vector<uint8_t> pt = {0x01, 0x02, 0x03};
  std::vector<uint8_t> key2(32, 0x01);
  auto r1 = Aes256GcmEncrypt(ZeroKey32(), ZeroNonce12(), "", pt);
  auto r2 = Aes256GcmEncrypt(key2, ZeroNonce12(), "", pt);
  ASSERT_TRUE(r1.ok());
  ASSERT_TRUE(r2.ok());
  EXPECT_NE(r1.value(), r2.value());
}

// ---------------------------------------------------------------------------
// Aes256GcmDecrypt — error cases
// ---------------------------------------------------------------------------
TEST(Aes256GcmDecryptTest, TooShortCiphertextAndTag) {
  std::vector<uint8_t> too_short(15, 0x00);  // needs at least 16 bytes for tag
  auto r = Aes256GcmDecrypt(ZeroKey32(), ZeroNonce12(), "", too_short);
  EXPECT_FALSE(r.ok());
}

TEST(Aes256GcmDecryptTest, KeyTooShort) {
  std::vector<uint8_t> ct(16, 0x00);
  std::vector<uint8_t> short_key(16, 0x00);
  auto r = Aes256GcmDecrypt(short_key, ZeroNonce12(), "", ct);
  EXPECT_FALSE(r.ok());
  EXPECT_EQ(r.status().code(), StatusCode::kInvalidArgument);
}

TEST(Aes256GcmDecryptTest, NonceTooShort) {
  std::vector<uint8_t> ct(16, 0x00);
  std::vector<uint8_t> short_nonce(4, 0x00);
  auto r = Aes256GcmDecrypt(ZeroKey32(), short_nonce, "", ct);
  EXPECT_FALSE(r.ok());
  EXPECT_EQ(r.status().code(), StatusCode::kInvalidArgument);
}

// ---------------------------------------------------------------------------
// Encrypt → Decrypt round-trips
// ---------------------------------------------------------------------------
TEST(AeadRoundTripTest, BasicRoundTrip) {
  std::vector<uint8_t> pt = {0x48, 0x65, 0x6C, 0x6C, 0x6F};  // "Hello"
  auto enc = Aes256GcmEncrypt(ZeroKey32(), ZeroNonce12(), "", pt);
  ASSERT_TRUE(enc.ok());

  auto dec = Aes256GcmDecrypt(ZeroKey32(), ZeroNonce12(), "", enc.value());
  ASSERT_TRUE(dec.ok());
  EXPECT_EQ(dec.value(), pt);
}

TEST(AeadRoundTripTest, EmptyPlaintextRoundTrip) {
  auto enc = Aes256GcmEncrypt(ZeroKey32(), ZeroNonce12(), "", {});
  ASSERT_TRUE(enc.ok());
  EXPECT_EQ(enc.value().size(), 16u);

  auto dec = Aes256GcmDecrypt(ZeroKey32(), ZeroNonce12(), "", enc.value());
  ASSERT_TRUE(dec.ok());
  EXPECT_TRUE(dec.value().empty());
}

TEST(AeadRoundTripTest, WithAADRoundTrip) {
  std::vector<uint8_t> pt = {0x01, 0x02, 0x03, 0x04};
  const std::string aad = "session-id-1234";

  auto enc = Aes256GcmEncrypt(ZeroKey32(), ZeroNonce12(), aad, pt);
  ASSERT_TRUE(enc.ok());

  auto dec = Aes256GcmDecrypt(ZeroKey32(), ZeroNonce12(), aad, enc.value());
  ASSERT_TRUE(dec.ok());
  EXPECT_EQ(dec.value(), pt);
}

TEST(AeadRoundTripTest, LargerPayload) {
  std::vector<uint8_t> pt(1024, 0xAB);
  std::vector<uint8_t> key(32, 0x42);
  std::vector<uint8_t> nonce(12, 0x13);

  auto enc = Aes256GcmEncrypt(key, nonce, "aad", pt);
  ASSERT_TRUE(enc.ok());
  EXPECT_EQ(enc.value().size(), pt.size() + 16);

  auto dec = Aes256GcmDecrypt(key, nonce, "aad", enc.value());
  ASSERT_TRUE(dec.ok());
  EXPECT_EQ(dec.value(), pt);
}

// ---------------------------------------------------------------------------
// Authentication failure (tampering detection)
// ---------------------------------------------------------------------------
TEST(AeadTamperingTest, FlipCiphertextByte) {
  std::vector<uint8_t> pt = {0x01, 0x02, 0x03, 0x04, 0x05};
  auto enc = Aes256GcmEncrypt(ZeroKey32(), ZeroNonce12(), "", pt);
  ASSERT_TRUE(enc.ok());

  auto tampered = enc.value();
  tampered[0] ^= 0x01;  // Flip one bit in the ciphertext

  auto dec = Aes256GcmDecrypt(ZeroKey32(), ZeroNonce12(), "", tampered);
  EXPECT_FALSE(dec.ok());
  EXPECT_EQ(dec.status().code(), StatusCode::kUnauthenticated);
}

TEST(AeadTamperingTest, FlipTagByte) {
  std::vector<uint8_t> pt = {0xDE, 0xAD, 0xBE, 0xEF};
  auto enc = Aes256GcmEncrypt(ZeroKey32(), ZeroNonce12(), "", pt);
  ASSERT_TRUE(enc.ok());

  auto tampered = enc.value();
  tampered.back() ^= 0xFF;  // Flip all bits in last tag byte

  auto dec = Aes256GcmDecrypt(ZeroKey32(), ZeroNonce12(), "", tampered);
  EXPECT_FALSE(dec.ok());
  EXPECT_EQ(dec.status().code(), StatusCode::kUnauthenticated);
}

TEST(AeadTamperingTest, WrongKey) {
  std::vector<uint8_t> pt = {0x01, 0x02, 0x03};
  auto enc = Aes256GcmEncrypt(ZeroKey32(), ZeroNonce12(), "", pt);
  ASSERT_TRUE(enc.ok());

  std::vector<uint8_t> wrong_key(32, 0xFF);
  auto dec = Aes256GcmDecrypt(wrong_key, ZeroNonce12(), "", enc.value());
  EXPECT_FALSE(dec.ok());
  EXPECT_EQ(dec.status().code(), StatusCode::kUnauthenticated);
}

TEST(AeadTamperingTest, WrongNonce) {
  std::vector<uint8_t> pt = {0x01, 0x02, 0x03};
  auto enc = Aes256GcmEncrypt(ZeroKey32(), ZeroNonce12(), "", pt);
  ASSERT_TRUE(enc.ok());

  std::vector<uint8_t> wrong_nonce(12, 0xFF);
  auto dec = Aes256GcmDecrypt(ZeroKey32(), wrong_nonce, "", enc.value());
  EXPECT_FALSE(dec.ok());
  EXPECT_EQ(dec.status().code(), StatusCode::kUnauthenticated);
}

TEST(AeadTamperingTest, WrongAAD) {
  std::vector<uint8_t> pt = {0x01, 0x02, 0x03};
  auto enc = Aes256GcmEncrypt(ZeroKey32(), ZeroNonce12(), "correct-aad", pt);
  ASSERT_TRUE(enc.ok());

  auto dec = Aes256GcmDecrypt(ZeroKey32(), ZeroNonce12(), "wrong-aad", enc.value());
  EXPECT_FALSE(dec.ok());
  EXPECT_EQ(dec.status().code(), StatusCode::kUnauthenticated);
}
