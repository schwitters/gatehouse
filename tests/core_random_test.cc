#include <gtest/gtest.h>

#include <unordered_set>

#include "core/random.h"
#include "core/status.h"

using namespace gatehouse::core;

TEST(RandomBytesTest, ZeroLengthReturnsEmptyOk) {
  auto r = RandomBytes(0);
  ASSERT_TRUE(r.ok());
  EXPECT_TRUE(r.value().empty());
}

TEST(RandomBytesTest, RequestedLength) {
  for (size_t n : {1u, 16u, 32u, 64u, 256u}) {
    auto r = RandomBytes(n);
    ASSERT_TRUE(r.ok()) << "Failed for n=" << n;
    EXPECT_EQ(r.value().size(), n);
  }
}

TEST(RandomBytesTest, RandomnessCheck) {
  // Repeated calls should almost never produce the same 16 bytes
  auto r1 = RandomBytes(16);
  auto r2 = RandomBytes(16);
  ASSERT_TRUE(r1.ok());
  ASSERT_TRUE(r2.ok());
  // Probability of collision: 1/2^128 — effectively impossible
  EXPECT_NE(r1.value(), r2.value());
}

TEST(RandomBytesTest, NotAllZeros) {
  // 32 random bytes — the probability of all-zeros is 1/2^256
  auto r = RandomBytes(32);
  ASSERT_TRUE(r.ok());
  bool all_zero = true;
  for (auto b : r.value()) {
    if (b != 0) { all_zero = false; break; }
  }
  EXPECT_FALSE(all_zero);
}

TEST(RandomBytesTest, OutputHasVariety) {
  // For 256 random bytes, expect at least 10 distinct byte values
  auto r = RandomBytes(256);
  ASSERT_TRUE(r.ok());
  std::unordered_set<uint8_t> distinct(r.value().begin(), r.value().end());
  EXPECT_GE(distinct.size(), 10u);
}
