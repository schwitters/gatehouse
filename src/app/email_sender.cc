#include "app/email_sender.h"

#include <curl/curl.h>

#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace gatehouse::app {
namespace {

struct CurlGlobal {
  CurlGlobal() { curl_global_init(CURL_GLOBAL_DEFAULT); }
  ~CurlGlobal() { curl_global_cleanup(); }
  CurlGlobal(const CurlGlobal&) = delete;
  CurlGlobal& operator=(const CurlGlobal&) = delete;
};

struct CurlEasy {
  CurlEasy() : h(curl_easy_init()) {}
  ~CurlEasy() { if (h) curl_easy_cleanup(h); }
  CURL* get() const { return h; }
  CURL* h = nullptr;
};

static std::string JoinAddressesHeader(std::string_view header_name,
                                       const std::vector<std::string>& addrs) {
  if (addrs.empty()) return {};
  std::string out;
  out.reserve(header_name.size() + 2 + 8 * addrs.size());
  out.append(header_name);
  out.append(": ");
  for (size_t i = 0; i < addrs.size(); ++i) {
    if (i) out.append(", ");
    out.append(addrs[i]);
  }
  out.append("\r\n");
  return out;
}

static void AppendRcpt(struct curl_slist** list, const std::string& email) {
  const std::string rcpt = "<" + email + ">";
  *list = curl_slist_append(*list, rcpt.c_str());
}

static void AppendAllRecipients(struct curl_slist** rcpt, const EmailAddressList& addrs) {
  for (const auto& a : addrs.to) AppendRcpt(rcpt, a);
  for (const auto& a : addrs.cc) AppendRcpt(rcpt, a);
  for (const auto& a : addrs.bcc) AppendRcpt(rcpt, a);
}

static std::string FormatFromHeader(const std::string& from_email,
                                    const std::string& from_name) {
  std::string out = "From: ";
  if (!from_name.empty()) {
    out += from_name;
    out += " <";
    out += from_email;
    out += ">\r\n";
  } else {
    out += from_email;
    out += "\r\n";
  }
  return out;
}

static bool AddTextPart(curl_mime* mime, const std::string& text_utf8) {
  curl_mimepart* part = curl_mime_addpart(mime);
  if (!part) return false;
  curl_mime_data(part, text_utf8.c_str(), CURL_ZERO_TERMINATED);
  curl_mime_type(part, "text/plain; charset=UTF-8");
  return true;
}

static bool AddAttachmentPart(curl_mime* mime, const Attachment& a) {
  if (a.path.empty()) return false;

  curl_mimepart* part = curl_mime_addpart(mime);
  if (!part) return false;

  if (curl_mime_filedata(part, a.path.c_str()) != CURLE_OK) return false;

  if (!a.filename.empty()) {
    if (curl_mime_filename(part, a.filename.c_str()) != CURLE_OK) return false;
  }
  if (!a.content_type.empty()) {
    if (curl_mime_type(part, a.content_type.c_str()) != CURLE_OK) return false;
  }
  return true;
}

static core::Result<void> SendMailSmtps(const std::string& smtp_url,
                                       const std::string& username,
                                       const std::string& app_password,
                                       const MailSpec& spec) {
  static CurlGlobal curl_global;

  CurlEasy curl;
  if (!curl.get()) {
    return core::Result<void>::Err(core::Status::Error(core::StatusCode::kInternal,
                                                      "curl_easy_init failed"));
  }

  curl_easy_setopt(curl.get(), CURLOPT_URL, smtp_url.c_str());
  curl_easy_setopt(curl.get(), CURLOPT_USERNAME, username.c_str());
  curl_easy_setopt(curl.get(), CURLOPT_PASSWORD, app_password.c_str());

  curl_easy_setopt(curl.get(), CURLOPT_USE_SSL, static_cast<long>(CURLUSESSL_ALL));
  curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYHOST, 2L);

  const std::string mail_from = "<" + spec.from_email + ">";
  curl_easy_setopt(curl.get(), CURLOPT_MAIL_FROM, mail_from.c_str());

  struct curl_slist* rcpt = nullptr;
  AppendAllRecipients(&rcpt, spec.addrs);
  if (!rcpt) {
    return core::Result<void>::Err(core::Status::Error(core::StatusCode::kInvalidArgument,
                                                      "no recipients"));
  }
  curl_easy_setopt(curl.get(), CURLOPT_MAIL_RCPT, rcpt);

  struct curl_slist* headers = nullptr;
  const std::string from_hdr = FormatFromHeader(spec.from_email, spec.from_name);
  const std::string to_hdr = JoinAddressesHeader("To", spec.addrs.to);
  const std::string cc_hdr = JoinAddressesHeader("Cc", spec.addrs.cc);
  const std::string subject_hdr = "Subject: " + spec.subject + "\r\n";

  headers = curl_slist_append(headers, from_hdr.c_str());
  if (!to_hdr.empty()) headers = curl_slist_append(headers, to_hdr.c_str());
  if (!cc_hdr.empty()) headers = curl_slist_append(headers, cc_hdr.c_str());
  headers = curl_slist_append(headers, subject_hdr.c_str());
  headers = curl_slist_append(headers, "MIME-Version: 1.0\r\n");

  curl_mime* mime = curl_mime_init(curl.get());
  if (!mime) {
    curl_slist_free_all(headers);
    curl_slist_free_all(rcpt);
    return core::Result<void>::Err(core::Status::Error(core::StatusCode::kInternal,
                                                      "curl_mime_init failed"));
  }

  if (!AddTextPart(mime, spec.text_body_utf8)) {
    curl_mime_free(mime);
    curl_slist_free_all(headers);
    curl_slist_free_all(rcpt);
    return core::Result<void>::Err(core::Status::Error(core::StatusCode::kInternal,
                                                      "failed to add text part"));
  }

  for (const auto& a : spec.attachments) {
    if (!AddAttachmentPart(mime, a)) {
      curl_mime_free(mime);
      curl_slist_free_all(headers);
      curl_slist_free_all(rcpt);
      return core::Result<void>::Err(core::Status::Error(core::StatusCode::kInternal,
                                                        "failed to add attachment: " + a.path));
    }
  }

  curl_easy_setopt(curl.get(), CURLOPT_MIMEPOST, mime);
  curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, headers);

  const CURLcode res = curl_easy_perform(curl.get());

  curl_mime_free(mime);
  curl_slist_free_all(headers);
  curl_slist_free_all(rcpt);

  if (res != CURLE_OK) {
    return core::Result<void>::Err(core::Status::Error(core::StatusCode::kUnavailable,
                                                      curl_easy_strerror(res)));
  }
  return core::Result<void>::Ok();
}

}  // namespace

core::Result<void> ConsoleEmailSender::SendText(const std::string& to_email,
                                               const std::string& subject,
                                               const std::string& body) {
  std::cerr << "\n=== GATEHOUSE EMAIL (console) ===\n";
  std::cerr << "To: " << to_email << "\n";
  std::cerr << "Subject: " << subject << "\n\n";
  std::cerr << body << "\n";
  std::cerr << "=== /GATEHOUSE EMAIL ===\n\n";
  return core::Result<void>::Ok();
}

core::Result<void> ConsoleEmailSender::Send(const MailSpec& spec) {
  // Render a minimal representation.
  std::string to;
  for (size_t i = 0; i < spec.addrs.to.size(); ++i) {
    if (i) to += ", ";
    to += spec.addrs.to[i];
  }
  return SendText(to, spec.subject, spec.text_body_utf8);
}

CurlSmtpsEmailSender::CurlSmtpsEmailSender() {
  const char* env_user = std::getenv("GMAIL_USER");
  const char* env_pass = std::getenv("GMAIL_APP_PASS");
  const char* env_url = std::getenv("SMTP_URL");

  username_ = env_user ? env_user : "";
  app_password_ = env_pass ? env_pass : "";
  smtp_url_ = env_url ? env_url : "smtps://smtp.gmail.com:465";
}

core::Result<void> CurlSmtpsEmailSender::SendText(const std::string& to_email,
                                                  const std::string& subject,
                                                  const std::string& body) {
  MailSpec spec;
  spec.from_email = username_;
  spec.from_name = "Gatehouse";
  spec.addrs.to = {to_email};
  spec.subject = subject;
  spec.text_body_utf8 = body;
  return Send(spec);
}

core::Result<void> CurlSmtpsEmailSender::Send(const MailSpec& spec) {
  if (username_.empty() || app_password_.empty()) {
    return core::Result<void>::Err(core::Status::Error(
        core::StatusCode::kFailedPrecondition,
        "missing env: GMAIL_USER / GMAIL_APP_PASS (and optional SMTP_URL)"));
  }
  if (spec.from_email.empty()) {
    return core::Result<void>::Err(core::Status::Error(
        core::StatusCode::kInvalidArgument, "MailSpec.from_email is empty"));
  }
  return SendMailSmtps(smtp_url_, username_, app_password_, spec);
}

}  // namespace gatehouse::app
