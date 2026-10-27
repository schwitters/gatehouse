#include "app/auth.h"
#include "app/http_utils.h"

#include <gtest/gtest.h>

namespace gatehouse::app {
namespace {

TEST(HtmlEscapeTest, EscapesMarkupAndBothAttributeDelimiters) {
  EXPECT_EQ(HtmlEscape("<script>&\"'"), "&lt;script&gt;&amp;&quot;&#39;");
}

TEST(HtmlEscapeTest, PreservesOrdinaryText) {
  EXPECT_EQ(HtmlEscape("Gatehouse user 42"), "Gatehouse user 42");
}

TEST(HtmlEscapeTest, TitleCannotIntroduceMarkup) {
  EXPECT_EQ(ApplyTitle("<title>%TITLE%</title>", "</title><script>"),
            "<title>&lt;/title&gt;&lt;script&gt;</title>");
}

TEST(AuthSecurityTest, RejectsForeignRealmBeforeContactingKdc) {
  AuthConfig config;
  config.krb5_realm = "LOCAL.INVALID";
  AuthService auth(config);
  const auto result = auth.Verify({"admin@FOREIGN.INVALID", "password"});
  ASSERT_TRUE(result.ok());
  EXPECT_FALSE(result.value().has_value());
}

TEST(AuthSecurityTest, RejectsMissingRealmConfiguration) {
  AuthService auth(AuthConfig{});
  const auto result = auth.Verify({"admin", "password"});
  ASSERT_TRUE(result.ok());
  EXPECT_FALSE(result.value().has_value());
}

}  // namespace
}  // namespace gatehouse::app
