#include "app/invite_view.h"

#include "app/http_utils.h"
namespace gatehouse::app {
std::string RenderInvitation(const InviteView& view) {
  const std::string& B = view.base_uri;
  // Wizard steps: 1=send code  2=enter code  3=set password
  const int wizard_step = view.verified ? 3 : (view.sent ? 2 : 1);

  // Use the invite session SID as CSRF token: HttpOnly, embedded in HTML by
  // server.
  const std::string inv_csrf = HtmlEscape(view.csrf);

  auto wstep_class = [&](int n) -> std::string {
    if (n < wizard_step) return "wstep done";
    if (n == wizard_step) return "wstep active";
    return "wstep";
  };

  std::string html;
  html +=
      "<!doctype html><html><head><meta charset='utf-8'><meta "
      "name='viewport' content='width=device-width,initial-scale=1'>";
  html += "<title>Complete Invitation \xe2\x80\x93 " + HtmlEscape(view.title) +
          "</title><style>";
  html +=
      "body{font-family:system-ui,Segoe "
      "UI,Roboto,Helvetica,Arial,sans-serif;margin:0;background:#f0f4f9;"
      "color:#222}";
  html += ".wrap{max-width:520px;margin:48px auto;padding:0 16px}";
  html += "h1{font-size:1.5rem;margin:0 0 4px}";
  html += ".subtitle{color:#555;font-size:.9em;margin:0 0 28px}";
  html +=
      ".wizard{display:flex;margin-bottom:32px;border-radius:10px;overflow:"
      "hidden;background:#fff;box-shadow:0 1px 4px rgba(0,0,0,.08)}";
  html +=
      ".wstep{flex:1;text-align:center;padding:12px "
      "6px;font-size:12px;font-weight:500;color:#aaa;border-bottom:3px "
      "solid transparent;transition:all .2s}";
  html += ".wstep.done{color:#137333;border-bottom-color:#137333}";
  html +=
      ".wstep.active{color:#0b57d0;border-bottom-color:#0b57d0;font-weight:"
      "700}";
  html +=
      ".card{background:#fff;padding:28px 28px "
      "24px;border-radius:12px;box-shadow:0 2px 8px "
      "rgba(0,0,0,.07);margin-bottom:20px}";
  html += "h2{margin:0 0 8px;font-size:1.15rem}";
  html +=
      ".info-row{display:flex;gap:6px;align-items:center;font-size:.88em;"
      "color:#555;margin-bottom:4px}";
  html += ".info-row b{color:#222}";
  html +=
      "label{display:block;margin-top:18px;font-size:.9em;font-weight:600;"
      "color:#333}";
  html +=
      "input{width:100%;padding:11px 12px;margin-top:6px;border:1px solid "
      "#ccc;border-radius:7px;font-size:1em;box-sizing:border-box;"
      "transition:border-color .15s}";
  html +=
      "input:focus{outline:none;border-color:#0b57d0;box-shadow:0 0 0 3px "
      "rgba(11,87,208,.12)}";
  html += ".code-input{letter-spacing:6px;font-size:1.6em;text-align:center}";
  html +=
      ".btn{display:inline-block;margin-top:20px;padding:12px "
      "20px;border:none;border-radius:7px;font-size:1em;font-weight:600;"
      "cursor:pointer;width:100%;text-align:center}";
  html +=
      ".btn-primary{background:#0b57d0;color:#fff} "
      ".btn-primary:hover{background:#0842a0}";
  html +=
      ".btn-ghost{background:#f0f0f0;color:#333;margin-top:12px} "
      ".btn-ghost:hover{background:#e0e0e0}";
  html +=
      ".alert-err{background:#fce8e6;color:#c5221f;border-radius:7px;"
      "padding:10px 14px;margin-top:14px;font-size:.9em}";
  html +=
      ".alert-info{background:#e8f0fe;color:#1a73e8;border-radius:7px;"
      "padding:10px 14px;margin-top:14px;font-size:.9em}";
  html += "a{color:#0b57d0;font-weight:600}";
  html += "</style></head><body><div class='wrap'>";

  html += "<h1>Complete Invitation</h1>";
  html += "<p class='subtitle'>Tenant: <b>" + HtmlEscape(view.tenant) +
          "</b> &nbsp;&middot;&nbsp; User: <b>" + HtmlEscape(view.uid) +
          "</b></p>";

  html += "<div class='wizard'>";
  html += "<div class='" + wstep_class(1) + "'>1. Verify Email</div>";
  html += "<div class='" + wstep_class(2) + "'>2. Enter Code</div>";
  html += "<div class='" + wstep_class(3) + "'>3. Set Password</div>";
  html += "</div>";

  if (wizard_step == 1) {
    html += "<div class='card'>";
    html += "<h2>Verify your email address</h2>";
    html +=
        "<p style='color:#555;font-size:.93em;margin:8px 0 0'>We'll send a "
        "6-digit code to:</p>";
    html += "<div class='info-row' style='margin-top:8px'><b>" +
            HtmlEscape(view.email) + "</b></div>";
    if (!view.error.empty())
      html +=
          "<div class='alert-err'>Error: " + HtmlEscape(view.error) + "</div>";
    html += "<form method='post' action='" + B + "/invite/otp/send'>";
    html += "<input type='hidden' name='_csrf' value='" + inv_csrf + "'>";
    html +=
        "<button type='submit' class='btn btn-primary'>Send Verification "
        "Code</button>";
    html += "</form></div>";
  } else if (wizard_step == 2) {
    html += "<div class='card'>";
    html += "<h2>Enter verification code</h2>";
    html +=
        "<p style='color:#555;font-size:.93em;margin:8px 0 0'>We sent a "
        "6-digit code to <b>" +
        HtmlEscape(view.email) + "</b>.<br>It expires in 10&nbsp;minutes.</p>";
    if (!view.error.empty())
      html +=
          "<div class='alert-err'>Error: " + HtmlEscape(view.error) + "</div>";
    html += "<form method='post' action='" + B + "/invite/otp/verify'>";
    html += "<input type='hidden' name='_csrf' value='" + inv_csrf + "'>";
    html += "<label>Verification code";
    html +=
        "<input name='code' class='code-input' placeholder='123456' "
        "autocomplete='one-time-code' inputmode='numeric' maxlength='6' "
        "required></label>";
    html +=
        "<button type='submit' class='btn btn-primary'>Verify Code</button>";
    html += "</form>";
    html += "<form method='post' action='" + B + "/invite/otp/send'>";
    html += "<input type='hidden' name='_csrf' value='" + inv_csrf + "'>";
    html += "<button type='submit' class='btn btn-ghost'>Resend Code</button>";
    html += "</form></div>";
  } else {
    html += "<div class='card'>";
    html += "<h2>Set up your account</h2>";
    html +=
        "<p style='color:#555;font-size:.93em;margin:8px 0 0'>Email "
        "verified. Choose a password to complete your registration.</p>";
    if (!view.error.empty())
      html +=
          "<div class='alert-err'>Error: " + HtmlEscape(view.error) + "</div>";
    html += "<form method='post' action='" + B + "/invite/complete'>";
    html += "<input type='hidden' name='_csrf' value='" + inv_csrf + "'>";
    html +=
        "<label>Display name <span "
        "style='color:#aaa;font-weight:400'>(optional)</span>";
    html += "<input name='display_name' placeholder='Your full name' value='" +
            HtmlEscape(view.display) + "'></label>";
    html += "<label>New password <span style='color:#b00020'>*</span>";
    html +=
        "<input type='password' name='password' required minlength='8' "
        "autocomplete='new-password'></label>";
    html += "<label>Confirm password <span style='color:#b00020'>*</span>";
    html +=
        "<input type='password' name='password_confirm' required "
        "minlength='8' autocomplete='new-password'></label>";
    html +=
        "<button type='submit' class='btn btn-primary'>Complete Setup</button>";
    html += "</form></div>";
  }

  html += "</div></body></html>";
  return html;
}
}  // namespace gatehouse::app
