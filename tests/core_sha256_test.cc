#include <gtest/gtest.h>

#include "core/sha256.h"
#include "core/hex.h"
#include "core/status.h"

using namespace gatehouse::core;

// ---------------------------------------------------------------------------
// Sha256 — known NIST test vectors
// ---------------------------------------------------------------------------
TEST(Sha256Test, EmptyInput) {
  // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  auto r = Sha256({});
  ASSERT_TRUE(r.ok());
  EXPECT_EQ(HexEncode(r.value()),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(Sha256Test, AbcInput) {
  // SHA-256("abc") per OpenSSL / NIST FIPS 180-4
  const std::string msg = "abc";
  std::vector<uint8_t> data(msg.begin(), msg.end());
  auto r = Sha256(data);
  ASSERT_TRUE(r.ok());
  EXPECT_EQ(HexEncode(r.value()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST(Sha256Test, OutputIs32Bytes) {
  auto r = Sha256({0x01, 0x02, 0x03});
  ASSERT_TRUE(r.ok());
  EXPECT_EQ(r.value().size(), 32u);
}

TEST(Sha256Test, DifferentInputsDifferentOutputs) {
  auto r1 = Sha256({0x00});
  auto r2 = Sha256({0x01});
  ASSERT_TRUE(r1.ok());
  ASSERT_TRUE(r2.ok());
  EXPECT_NE(r1.value(), r2.value());
}

TEST(Sha256Test, Deterministic) {
  std::vector<uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF};
  auto r1 = Sha256(data);
  auto r2 = Sha256(data);
  ASSERT_TRUE(r1.ok());
  ASSERT_TRUE(r2.ok());
  EXPECT_EQ(r1.value(), r2.value());
}

// ---------------------------------------------------------------------------
// Base64UrlNoPad — known vectors
// ---------------------------------------------------------------------------
TEST(Base64UrlNoPadTest, EmptyInput) {
  EXPECT_EQ(Base64UrlNoPad({}), "");
}

TEST(Base64UrlNoPadTest, SingleZeroByte) {
  // [0x00] -> "AA"
  EXPECT_EQ(Base64UrlNoPad({0x00}), "AA");
}

TEST(Base64UrlNoPadTest, ThreeBytesManVector) {
  // "Man" = {0x4D, 0x61, 0x6E} -> "TWFu"
  EXPECT_EQ(Base64UrlNoPad({0x4D, 0x61, 0x6E}), "TWFu");
}

TEST(Base64UrlNoPadTest, TwoBytesUrlSafe) {
  // {0xFB, 0xFF}: groups are 62, 63, 60 -> '-', '_', '8'
  EXPECT_EQ(Base64UrlNoPad({0xFB, 0xFF}), "-_8");
}

TEST(Base64UrlNoPadTest, NoTrailingEquals) {
  // For non-multiples-of-3 inputs, result must not end with '='
  for (size_t len = 1; len <= 5; ++len) {
    std::vector<uint8_t> data(len, 0xAA);
    auto encoded = Base64UrlNoPad(data);
    EXPECT_FALSE(encoded.ends_with('='))
        << "Trailing padding found for input length " << len;
  }
}

TEST(Base64UrlNoPadTest, OnlyUrlSafeChars) {
  std::vector<uint8_t> data = {0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA};
  auto encoded = Base64UrlNoPad(data);
  for (char c : encoded) {
    bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_';
    EXPECT_TRUE(ok) << "Non-URL-safe char '" << c << "' found";
  }
}

TEST(Base64UrlNoPadTest, NoStandardBase64Chars) {
  // Standard base64 uses '+' and '/' — URL-safe variant must not
  std::vector<uint8_t> data(256);
  for (int i = 0; i < 256; ++i) data[static_cast<size_t>(i)] = static_cast<uint8_t>(i);
  auto encoded = Base64UrlNoPad(data);
  EXPECT_EQ(encoded.find('+'), std::string::npos);
  EXPECT_EQ(encoded.find('/'), std::string::npos);
}

TEST(Base64UrlNoPadTest, LengthFormula) {
  // ceil(n * 4 / 3) without padding: (n + 2) / 3 * 4 - padding_removed
  // Simpler: n=0->0, n=1->2, n=2->3, n=3->4, n=4->6, n=6->8
  EXPECT_EQ(Base64UrlNoPad({}).size(), 0u);
  EXPECT_EQ(Base64UrlNoPad({0x00}).size(), 2u);
  EXPECT_EQ(Base64UrlNoPad({0x00, 0x00}).size(), 3u);
  EXPECT_EQ(Base64UrlNoPad({0x00, 0x00, 0x00}).size(), 4u);
  EXPECT_EQ(Base64UrlNoPad({0x00, 0x00, 0x00, 0x00}).size(), 6u);
}
