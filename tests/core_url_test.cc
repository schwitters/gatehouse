#include <gtest/gtest.h>

#include "core/url.h"

using namespace gatehouse::core;

// ---------------------------------------------------------------------------
// UrlDecode
// ---------------------------------------------------------------------------
TEST(UrlDecodeTest, EmptyInput) {
  auto r = UrlDecode("");
  ASSERT_TRUE(r.has_value());
  EXPECT_EQ(*r, "");
}

TEST(UrlDecodeTest, PlainAscii) {
  auto r = UrlDecode("hello");
  ASSERT_TRUE(r.has_value());
  EXPECT_EQ(*r, "hello");
}

TEST(UrlDecodeTest, PlusDecodedAsSpace) {
  auto r = UrlDecode("hello+world");
  ASSERT_TRUE(r.has_value());
  EXPECT_EQ(*r, "hello world");
}

TEST(UrlDecodeTest, PercentEncodedSpace) {
  auto r = UrlDecode("hello%20world");
  ASSERT_TRUE(r.has_value());
  EXPECT_EQ(*r, "hello world");
}

TEST(UrlDecodeTest, PercentEncodedLetter) {
  auto r = UrlDecode("%41");  // 'A'
  ASSERT_TRUE(r.has_value());
  EXPECT_EQ(*r, "A");
}

TEST(UrlDecodeTest, PercentEncodedUppercase) {
  auto r = UrlDecode("%2B");  // '+'
  ASSERT_TRUE(r.has_value());
  EXPECT_EQ(*r, "+");
}

TEST(UrlDecodeTest, PercentEncodedLowercase) {
  auto r = UrlDecode("%2b");  // '+'
  ASSERT_TRUE(r.has_value());
  EXPECT_EQ(*r, "+");
}

TEST(UrlDecodeTest, MultiplePlusAndPercent) {
  auto r = UrlDecode("a+b%3Dc");  // "a b=c"
  ASSERT_TRUE(r.has_value());
  EXPECT_EQ(*r, "a b=c");
}

TEST(UrlDecodeTest, TrailingPercent) {
  auto r = UrlDecode("abc%");
  EXPECT_FALSE(r.has_value());
}

TEST(UrlDecodeTest, IncompletePercentSequence) {
  auto r = UrlDecode("abc%4");
  EXPECT_FALSE(r.has_value());
}

TEST(UrlDecodeTest, InvalidHexInPercent) {
  auto r = UrlDecode("%ZZ");
  EXPECT_FALSE(r.has_value());
}

TEST(UrlDecodeTest, InvalidFirstHexNibble) {
  auto r = UrlDecode("%GF");
  EXPECT_FALSE(r.has_value());
}

TEST(UrlDecodeTest, InvalidSecondHexNibble) {
  auto r = UrlDecode("%FG");
  EXPECT_FALSE(r.has_value());
}

TEST(UrlDecodeTest, NullByte) {
  auto r = UrlDecode("%00");
  ASSERT_TRUE(r.has_value());
  EXPECT_EQ(r->size(), 1u);
  EXPECT_EQ((*r)[0], '\0');
}

TEST(UrlDecodeTest, AllPlusChars) {
  auto r = UrlDecode("+++");
  ASSERT_TRUE(r.has_value());
  EXPECT_EQ(*r, "   ");
}

// ---------------------------------------------------------------------------
// FormGet
// ---------------------------------------------------------------------------
TEST(FormGetTest, SingleParam) {
  auto r = FormGet("foo=bar", "foo");
  ASSERT_TRUE(r.has_value());
  EXPECT_EQ(*r, "bar");
}

TEST(FormGetTest, MultipleParams) {
  auto r = FormGet("foo=bar&baz=qux", "baz");
  ASSERT_TRUE(r.has_value());
  EXPECT_EQ(*r, "qux");
}

TEST(FormGetTest, FirstParam) {
  auto r = FormGet("foo=bar&baz=qux", "foo");
  ASSERT_TRUE(r.has_value());
  EXPECT_EQ(*r, "bar");
}

TEST(FormGetTest, MissingKey) {
  auto r = FormGet("foo=bar&baz=qux", "missing");
  EXPECT_FALSE(r.has_value());
}

TEST(FormGetTest, EmptyBody) {
  auto r = FormGet("", "foo");
  EXPECT_FALSE(r.has_value());
}

TEST(FormGetTest, ValueWithEncodedChars) {
  auto r = FormGet("msg=hello+world", "msg");
  ASSERT_TRUE(r.has_value());
  EXPECT_EQ(*r, "hello world");
}

TEST(FormGetTest, ValueWithPercentEncoding) {
  auto r = FormGet("name=John%20Doe", "name");
  ASSERT_TRUE(r.has_value());
  EXPECT_EQ(*r, "John Doe");
}

TEST(FormGetTest, EmptyValue) {
  auto r = FormGet("foo=", "foo");
  ASSERT_TRUE(r.has_value());
  EXPECT_EQ(*r, "");
}

TEST(FormGetTest, ThreeParams) {
  auto r = FormGet("a=1&b=2&c=3", "c");
  ASSERT_TRUE(r.has_value());
  EXPECT_EQ(*r, "3");
}

TEST(FormGetTest, KeyComparedVerbatim) {
  // FormGet compares keys without decoding — raw key "a%2Bb" != "a+b"
  auto r = FormGet("a%2Bb=value", "a%2Bb");
  ASSERT_TRUE(r.has_value());
  EXPECT_EQ(*r, "value");

  auto r2 = FormGet("a%2Bb=value", "a+b");
  EXPECT_FALSE(r2.has_value());
}
