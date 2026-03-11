#include <gtest/gtest.h>

#include "core/crypto_aead.h"
#include "core/hex.h"
#include "core/status.h"

using namespace gatehouse::core;

// ---------------------------------------------------------------------------
// HexEncode
// ---------------------------------------------------------------------------
TEST(HexEncodeTest, EmptyInput) {
  EXPECT_EQ(HexEncode({}), "");
}

TEST(HexEncodeTest, SingleByte) {
  EXPECT_EQ(HexEncode({0x00}), "00");
  EXPECT_EQ(HexEncode({0xFF}), "ff");
  EXPECT_EQ(HexEncode({0x0F}), "0f");
  EXPECT_EQ(HexEncode({0xAB}), "ab");
}

TEST(HexEncodeTest, MultipleBytes) {
  EXPECT_EQ(HexEncode({0xDE, 0xAD, 0xBE, 0xEF}), "deadbeef");
  EXPECT_EQ(HexEncode({0x01, 0x23, 0x45, 0x67, 0x89}), "0123456789");
}

TEST(HexEncodeTest, AllLowercase) {
  auto encoded = HexEncode({0xCA, 0xFE});
  EXPECT_EQ(encoded, "cafe");
  for (char c : encoded) {
    EXPECT_FALSE(c >= 'A' && c <= 'F') << "Uppercase char found: " << c;
  }
}

TEST(HexEncodeTest, LengthIsDoubled) {
  std::vector<uint8_t> data(16, 0x42);
  EXPECT_EQ(HexEncode(data).size(), 32u);
}

// ---------------------------------------------------------------------------
// HexDecode
// ---------------------------------------------------------------------------
TEST(HexDecodeTest, EmptyInput) {
  auto r = HexDecode("");
  ASSERT_TRUE(r.ok());
  EXPECT_TRUE(r.value().empty());
}

TEST(HexDecodeTest, LowercaseHex) {
  auto r = HexDecode("deadbeef");
  ASSERT_TRUE(r.ok());
  EXPECT_EQ(r.value(), (std::vector<uint8_t>{0xDE, 0xAD, 0xBE, 0xEF}));
}

TEST(HexDecodeTest, UppercaseHex) {
  auto r = HexDecode("DEADBEEF");
  ASSERT_TRUE(r.ok());
  EXPECT_EQ(r.value(), (std::vector<uint8_t>{0xDE, 0xAD, 0xBE, 0xEF}));
}

TEST(HexDecodeTest, MixedCase) {
  auto r = HexDecode("DeAdBeEf");
  ASSERT_TRUE(r.ok());
  EXPECT_EQ(r.value(), (std::vector<uint8_t>{0xDE, 0xAD, 0xBE, 0xEF}));
}

TEST(HexDecodeTest, OddLengthReturnsError) {
  auto r = HexDecode("abc");
  EXPECT_FALSE(r.ok());
  EXPECT_EQ(r.status().code(), StatusCode::kInvalidArgument);
}

TEST(HexDecodeTest, InvalidCharReturnsError) {
  auto r = HexDecode("zz");
  EXPECT_FALSE(r.ok());
  EXPECT_EQ(r.status().code(), StatusCode::kInvalidArgument);
}

TEST(HexDecodeTest, InvalidCharMidStringReturnsError) {
  auto r = HexDecode("abGH");
  EXPECT_FALSE(r.ok());
}

TEST(HexDecodeTest, AllZeros) {
  auto r = HexDecode("0000");
  ASSERT_TRUE(r.ok());
  EXPECT_EQ(r.value(), (std::vector<uint8_t>{0x00, 0x00}));
}

TEST(HexDecodeTest, AllFs) {
  auto r = HexDecode("ffff");
  ASSERT_TRUE(r.ok());
  EXPECT_EQ(r.value(), (std::vector<uint8_t>{0xFF, 0xFF}));
}

// ---------------------------------------------------------------------------
// Round-trip: HexEncode(HexDecode(x)) == x
// ---------------------------------------------------------------------------
TEST(HexRoundTripTest, EncodeThenDecode) {
  std::vector<uint8_t> original = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                                   0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
                                   0xEE, 0xFF};
  auto encoded = HexEncode(original);
  auto r = HexDecode(encoded);
  ASSERT_TRUE(r.ok());
  EXPECT_EQ(r.value(), original);
}

TEST(HexRoundTripTest, DecodeThenEncode) {
  const std::string hex = "0102030405060708090a0b0c0d0e0f10";
  auto r = HexDecode(hex);
  ASSERT_TRUE(r.ok());
  EXPECT_EQ(HexEncode(r.value()), hex);
}
