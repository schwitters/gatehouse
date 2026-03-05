#pragma once

#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "core/result.h"

namespace gatehouse::app {

struct EmailAddressList {
  std::vector<std::string> to;
  std::vector<std::string> cc;
  std::vector<std::string> bcc;  // no header, but recipients
};

struct Attachment {
  std::string path;         // required
  std::string filename;     // optional
  std::string content_type; // optional
};

struct MailSpec {
  std::string from_email;
  std::string from_name;   // optional ASCII-safe here
  EmailAddressList addrs;

  std::string subject;
  std::string text_body_utf8;

  std::vector<Attachment> attachments;
};

class IEmailSender {
 public:
  virtual ~IEmailSender() = default;

  // Convenience wrapper used by Gatehouse now.
  virtual core::Result<void> SendText(const std::string& to_email,
                                      const std::string& subject,
                                      const std::string& body) = 0;

  // Full-featured API (to/cc/bcc + attachments)
  virtual core::Result<void> Send(const MailSpec& spec) = 0;
};

class ConsoleEmailSender final : public IEmailSender {
 public:
  core::Result<void> SendText(const std::string& to_email,
                              const std::string& subject,
                              const std::string& body) override;

  core::Result<void> Send(const MailSpec& spec) override;
};

// Libcurl SMTPS sender.
// Uses env vars by default:
//   GMAIL_USER, GMAIL_APP_PASS
// Optional:
//   SMTP_URL (default: smtps://smtp.gmail.com:465)
class CurlSmtpsEmailSender final : public IEmailSender {
 public:
  CurlSmtpsEmailSender();

  core::Result<void> SendText(const std::string& to_email,
                              const std::string& subject,
                              const std::string& body) override;

  core::Result<void> Send(const MailSpec& spec) override;

 private:
  std::string smtp_url_;
  std::string username_;
  std::string app_password_;
};

}  // namespace gatehouse::app
