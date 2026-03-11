#include <gtest/gtest.h>

#include "core/result.h"
#include "core/status.h"

using namespace gatehouse::core;

TEST(StatusTest, OkIsOk) {
  auto s = Status::Ok();
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.code(), StatusCode::kOk);
  EXPECT_TRUE(s.message().empty());
}

TEST(StatusTest, ErrorIsNotOk) {
  auto s = Status::Error(StatusCode::kNotFound, "not found");
  EXPECT_FALSE(s.ok());
  EXPECT_EQ(s.code(), StatusCode::kNotFound);
  EXPECT_EQ(s.message(), "not found");
}

TEST(StatusTest, DefaultConstructedIsOk) {
  Status s;
  EXPECT_TRUE(s.ok());
}

TEST(ResultTest, OkResult) {
  auto r = Result<int>::Ok(42);
  EXPECT_TRUE(r.ok());
  EXPECT_EQ(r.value(), 42);
}

TEST(ResultTest, ErrResult) {
  auto r = Result<int>::Err(Status::Error(StatusCode::kInternal, "oops"));
  EXPECT_FALSE(r.ok());
  EXPECT_EQ(r.status().code(), StatusCode::kInternal);
  EXPECT_EQ(r.status().message(), "oops");
}

TEST(ResultTest, OkStringResult) {
  auto r = Result<std::string>::Ok("hello");
  EXPECT_TRUE(r.ok());
  EXPECT_EQ(r.value(), "hello");
}

TEST(ResultTest, MoveValue) {
  auto r = Result<std::string>::Ok("world");
  std::string s = std::move(r).value();
  EXPECT_EQ(s, "world");
}

TEST(ResultVoidTest, OkVoid) {
  auto r = Result<void>::Ok();
  EXPECT_TRUE(r.ok());
}

TEST(ResultVoidTest, ErrVoid) {
  auto r = Result<void>::Err(Status::Error(StatusCode::kUnauthenticated, "denied"));
  EXPECT_FALSE(r.ok());
  EXPECT_EQ(r.status().code(), StatusCode::kUnauthenticated);
}

TEST(ResultTest, MoveConstruct) {
  auto r1 = Result<int>::Ok(99);
  Result<int> r2 = std::move(r1);
  EXPECT_TRUE(r2.ok());
  EXPECT_EQ(r2.value(), 99);
}
