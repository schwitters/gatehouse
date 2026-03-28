#include "app/routes.h"

#include <cstdio>
#include <string>

#include "app/http_utils.h"
#include "core/crypto_aead.h"
#include "core/hex.h"
#include "core/random.h"
#include "core/sha256.h"
#include "core/time.h"
#include "core/url.h"
#include "crow.h"
#include "crow/json.h"
#include "infra/invite_session_repo.h"
#include "infra/kadm5_client.h"

namespace gatehouse::app {

void RegisterInviteRoutes(crow::SimpleApp& app, ServerContext& ctx) {
  // ---- Accept invite token -> invite_session cookie ----
  CROW_ROUTE(app, "/invite/accept").methods("GET"_method)([&ctx](const crow::request& req) {
    const char* t = req.url_params.get("token");
    if (t == nullptr) return HtmlPage(400, "<h1>Invalid invitation</h1>");
    const std::string token_hex = t;

    auto token_bytes = core::HexDecode(token_hex);
    if (!token_bytes.ok()) return HtmlPage(400, "<h1>Invalid invitation token</h1>");

    auto hash = core::Sha256(token_bytes.value());
    if (!hash.ok()) return HtmlPage(500, "<h1>Internal error</h1>");

    // BEGIN IMMEDIATE transaction to prevent race condition: two concurrent
    // requests with the same token must not both create valid invite sessions.
    auto tx = ctx.db.Exec("BEGIN IMMEDIATE;");
    if (!tx.ok()) return HtmlPage(500, "<h1>Internal error</h1>");

    auto row = ctx.invites.GetByTokenHash(hash.value());
    if (!row.ok() || !row.value().has_value()) {
      (void)ctx.db.Exec("ROLLBACK;");
      return HtmlPage(404, "<h1>Invitation not found</h1>");
    }

    const auto now = core::UnixNow();
    const auto& inv = *row.value();

    if (inv.revoked_at != 0 || inv.status == infra::InviteStatus::kRevoked) {
      (void)ctx.db.Exec("ROLLBACK;");
      return HtmlPage(410, "<h1>Invitation revoked</h1>");
    }
    if (inv.status == infra::InviteStatus::kCompleted) {
      (void)ctx.db.Exec("ROLLBACK;");
      return HtmlPage(410, "<h1>Invitation already completed</h1>");
    }
    if (inv.expires_at <= now) {
      (void)ctx.invites.UpdateStatus(inv.invite_id, infra::InviteStatus::kExpired, now);
      (void)ctx.db.Exec("COMMIT;");
      return HtmlPage(410, "<h1>Invitation expired</h1>");
    }

    (void)ctx.invites.UpdateStatus(inv.invite_id, infra::InviteStatus::kLinkVerified, now);

    auto sid_bytes = core::RandomBytes(32);
    if (!sid_bytes.ok()) {
      (void)ctx.db.Exec("ROLLBACK;");
      return HtmlPage(500, "<h1>Internal error</h1>");
    }

    infra::InviteSessionRow s;
    s.sid = core::HexEncode(sid_bytes.value());
    s.invite_id = inv.invite_id;
    s.created_at = now;
    s.expires_at = now + 1800;

    auto ins = ctx.invite_sessions.Insert(s);
    if (!ins.ok()) {
      (void)ctx.db.Exec("ROLLBACK;");
      return HtmlPage(500, "<h1>Internal error</h1>");
    }

    auto cm = ctx.db.Exec("COMMIT;");
    if (!cm.ok()) return HtmlPage(500, "<h1>Internal error</h1>");

    auto r = RedirectTo("/invite/complete");
    r.add_header("Set-Cookie", std::string(kInviteCookie) + "=" + s.sid +
                               "; Path=/; Max-Age=1800; HttpOnly; SameSite=Lax");
    return r;
  });

  // ---- Complete invite wizard (GET) ----
  CROW_ROUTE(app, "/invite/complete").methods("GET"_method)([&ctx](const crow::request& req) {
    auto is = RequireInviteSession(ctx, req);
    if (!is.has_value())
      return HtmlPage(401, "<h1>Invitation session expired</h1><p>Please open your invite link again.</p>");

    auto inv = ctx.invites.GetById(is->invite_id);
    if (!inv.ok() || !inv.value().has_value()) return HtmlPage(404, "<h1>Invitation not found</h1>");
    const auto& row = *inv.value();
    if (row.status == infra::InviteStatus::kRevoked) return HtmlPage(410, "<h1>Invitation revoked</h1>");

    auto prof = ctx.invite_profiles.GetByInviteId(row.invite_id);
    std::string display;
    if (prof.ok() && prof.value().has_value()) display = prof.value()->display_name;

    auto verified_res = ctx.invite_otps.IsVerified(is->sid);
    const bool verified = verified_res.ok() && verified_res.value();

    const std::string sent = req.url_params.get("sent") ? req.url_params.get("sent") : "";
    const std::string err  = req.url_params.get("err")  ? req.url_params.get("err")  : "";

    // Wizard steps: 1=send code  2=enter code  3=set password
    const int wizard_step = verified ? 3 : (!sent.empty() ? 2 : 1);

    // Use the invite session SID as CSRF token: HttpOnly, embedded in HTML by server.
    const std::string inv_csrf = crow::json::escape(is->sid);

    auto wstep_class = [&](int n) -> std::string {
      if (n < wizard_step) return "wstep done";
      if (n == wizard_step) return "wstep active";
      return "wstep";
    };

    std::string html;
    html += "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>";
    html += "<title>Complete Invitation \xe2\x80\x93 " + ctx.cfg.instance_title + "</title><style>";
    html += "body{font-family:system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:0;background:#f0f4f9;color:#222}";
    html += ".wrap{max-width:520px;margin:48px auto;padding:0 16px}";
    html += "h1{font-size:1.5rem;margin:0 0 4px}";
    html += ".subtitle{color:#555;font-size:.9em;margin:0 0 28px}";
    html += ".wizard{display:flex;margin-bottom:32px;border-radius:10px;overflow:hidden;background:#fff;box-shadow:0 1px 4px rgba(0,0,0,.08)}";
    html += ".wstep{flex:1;text-align:center;padding:12px 6px;font-size:12px;font-weight:500;color:#aaa;border-bottom:3px solid transparent;transition:all .2s}";
    html += ".wstep.done{color:#137333;border-bottom-color:#137333}";
    html += ".wstep.active{color:#0b57d0;border-bottom-color:#0b57d0;font-weight:700}";
    html += ".card{background:#fff;padding:28px 28px 24px;border-radius:12px;box-shadow:0 2px 8px rgba(0,0,0,.07);margin-bottom:20px}";
    html += "h2{margin:0 0 8px;font-size:1.15rem}";
    html += ".info-row{display:flex;gap:6px;align-items:center;font-size:.88em;color:#555;margin-bottom:4px}";
    html += ".info-row b{color:#222}";
    html += "label{display:block;margin-top:18px;font-size:.9em;font-weight:600;color:#333}";
    html += "input{width:100%;padding:11px 12px;margin-top:6px;border:1px solid #ccc;border-radius:7px;font-size:1em;box-sizing:border-box;transition:border-color .15s}";
    html += "input:focus{outline:none;border-color:#0b57d0;box-shadow:0 0 0 3px rgba(11,87,208,.12)}";
    html += ".code-input{letter-spacing:6px;font-size:1.6em;text-align:center}";
    html += ".btn{display:inline-block;margin-top:20px;padding:12px 20px;border:none;border-radius:7px;font-size:1em;font-weight:600;cursor:pointer;width:100%;text-align:center}";
    html += ".btn-primary{background:#0b57d0;color:#fff} .btn-primary:hover{background:#0842a0}";
    html += ".btn-ghost{background:#f0f0f0;color:#333;margin-top:12px} .btn-ghost:hover{background:#e0e0e0}";
    html += ".alert-err{background:#fce8e6;color:#c5221f;border-radius:7px;padding:10px 14px;margin-top:14px;font-size:.9em}";
    html += ".alert-info{background:#e8f0fe;color:#1a73e8;border-radius:7px;padding:10px 14px;margin-top:14px;font-size:.9em}";
    html += "a{color:#0b57d0;font-weight:600}";
    html += "</style></head><body><div class='wrap'>";

    html += "<h1>Complete Invitation</h1>";
    html += "<p class='subtitle'>Tenant: <b>" + crow::json::escape(row.tenant_id) + "</b> &nbsp;&middot;&nbsp; User: <b>" + crow::json::escape(row.invited_uid) + "</b></p>";

    html += "<div class='wizard'>";
    html += "<div class='" + wstep_class(1) + "'>1. Verify Email</div>";
    html += "<div class='" + wstep_class(2) + "'>2. Enter Code</div>";
    html += "<div class='" + wstep_class(3) + "'>3. Set Password</div>";
    html += "</div>";

    if (wizard_step == 1) {
      html += "<div class='card'>";
      html += "<h2>Verify your email address</h2>";
      html += "<p style='color:#555;font-size:.93em;margin:8px 0 0'>We'll send a 6-digit code to:</p>";
      html += "<div class='info-row' style='margin-top:8px'><b>" + crow::json::escape(row.invited_email) + "</b></div>";
      if (!err.empty()) html += "<div class='alert-err'>Error: " + crow::json::escape(err) + "</div>";
      html += "<form method='post' action='/invite/otp/send'>";
      html += "<input type='hidden' name='_csrf' value='" + inv_csrf + "'>";
      html += "<button type='submit' class='btn btn-primary'>Send Verification Code</button>";
      html += "</form></div>";
    } else if (wizard_step == 2) {
      html += "<div class='card'>";
      html += "<h2>Enter verification code</h2>";
      html += "<p style='color:#555;font-size:.93em;margin:8px 0 0'>We sent a 6-digit code to <b>" + crow::json::escape(row.invited_email) + "</b>.<br>It expires in 10&nbsp;minutes.</p>";
      if (!err.empty()) html += "<div class='alert-err'>Error: " + crow::json::escape(err) + "</div>";
      html += "<form method='post' action='/invite/otp/verify'>";
      html += "<input type='hidden' name='_csrf' value='" + inv_csrf + "'>";
      html += "<label>Verification code";
      html += "<input name='code' class='code-input' placeholder='123456' autocomplete='one-time-code' inputmode='numeric' maxlength='6' required></label>";
      html += "<button type='submit' class='btn btn-primary'>Verify Code</button>";
      html += "</form>";
      html += "<form method='post' action='/invite/otp/send'>";
      html += "<input type='hidden' name='_csrf' value='" + inv_csrf + "'>";
      html += "<button type='submit' class='btn btn-ghost'>Resend Code</button>";
      html += "</form></div>";
    } else {
      html += "<div class='card'>";
      html += "<h2>Set up your account</h2>";
      html += "<p style='color:#555;font-size:.93em;margin:8px 0 0'>Email verified. Choose a password to complete your registration.</p>";
      if (!err.empty()) html += "<div class='alert-err'>Error: " + crow::json::escape(err) + "</div>";
      html += "<form method='post' action='/invite/complete'>";
      html += "<input type='hidden' name='_csrf' value='" + inv_csrf + "'>";
      html += "<label>Display name <span style='color:#aaa;font-weight:400'>(optional)</span>";
      html += "<input name='display_name' placeholder='Your full name' value='" + crow::json::escape(display) + "'></label>";
      html += "<label>New password <span style='color:#b00020'>*</span>";
      html += "<input type='password' name='password' required minlength='8' autocomplete='new-password'></label>";
      html += "<label>Confirm password <span style='color:#b00020'>*</span>";
      html += "<input type='password' name='password_confirm' required minlength='8' autocomplete='new-password'></label>";
      html += "<button type='submit' class='btn btn-primary'>Complete Setup</button>";
      html += "</form></div>";
    }

    html += "</div></body></html>";
    return HtmlPage(200, html);
  });

  // ---- Complete invite wizard (POST) ----
  CROW_ROUTE(app, "/invite/complete").methods("POST"_method)([&ctx](const crow::request& req) {
    auto is = RequireInviteSession(ctx, req);
    if (!is.has_value()) return HtmlPage(401, "<h1>Invitation session expired</h1>");

    const auto csrf_val = core::FormGet(req.body, "_csrf");
    if (!csrf_val.has_value() || *csrf_val != is->sid) {
      return HtmlPage(403, "<h1>Invalid CSRF token</h1>");
    }

    // HIGH-06: Verify OTP step-up before proceeding. Without this check an
    // attacker could POST directly to /invite/complete and skip email verification.
    auto verified_res = ctx.invite_otps.IsVerified(is->sid);
    if (!verified_res.ok() || !verified_res.value()) {
      return RedirectTo("/invite/complete?err=Email+verification+required");
    }

    auto inv = ctx.invites.GetById(is->invite_id);
    if (!inv.ok() || !inv.value().has_value()) return HtmlPage(404, "<h1>Invitation not found</h1>");

    const auto now = core::UnixNow();
    const std::string display = core::FormGet(req.body, "display_name").value_or("");
    const std::string pwd1 = core::FormGet(req.body, "password").value_or("");
    const std::string pwd2 = core::FormGet(req.body, "password_confirm").value_or("");

    if (pwd1.empty() || pwd1 != pwd2) {
      return RedirectTo("/invite/complete?err=Passwords+do+not+match");
    }

    const char* env_kadmin_princ = std::getenv("GATEHOUSE_KADM5_ADMIN_PRINC");
    const char* env_kadmin_pass  = std::getenv("GATEHOUSE_KADM5_ADMIN_PASS");

    if (env_kadmin_princ && env_kadmin_pass && ctx.ldap_dir.has_value()) {
      infra::Kadm5Config kcfg;
      kcfg.realm = ctx.cfg.auth_cfg.krb5_realm;
      kcfg.admin_principal = env_kadmin_princ;
      kcfg.admin_password  = env_kadmin_pass;
      infra::Kadm5Client kadm(kcfg);

      auto dn_res = ctx.ldap_dir->GetUserDn(inv.value()->tenant_id, inv.value()->invited_uid);
      if (dn_res.ok() && dn_res.value().has_value()) {
        std::string new_princ = inv.value()->invited_uid + "@" + ctx.cfg.auth_cfg.krb5_realm;
        auto krc = kadm.CreatePrincipal(new_princ, pwd1, dn_res.value().value());
        if (!krc.ok()) {
          std::fprintf(stderr, "[gatehouse][kadm5] Failed to create principal: %s\n",
                       SanitizeForLog(krc.status().ToString()).c_str());
          return RedirectTo("/invite/complete?err=Failed+to+create+Kerberos+principal");
        }
      }
    }

    infra::InviteProfileRow pr;
    pr.invite_id   = is->invite_id;
    pr.display_name = display;
    pr.created_at  = now;
    pr.updated_at  = now;

    (void)ctx.invite_profiles.Upsert(pr);
    (void)ctx.invites.UpdateStatus(is->invite_id, infra::InviteStatus::kCompleted, now);
    (void)ctx.invite_sessions.Consume(is->sid, now);

    // Activate user in LDAP.
    if (ctx.ldap_dir.has_value() && !inv.value()->invited_uid.empty()) {
      auto act_rc = ctx.ldap_dir->ActivateUser(inv.value()->tenant_id, inv.value()->invited_uid);
      if (!act_rc.ok()) {
        std::fprintf(stderr, "[gatehouse][activate] Warning: LDAP activation failed for %s: %s\n",
                     SanitizeForLog(inv.value()->invited_uid).c_str(),
                     SanitizeForLog(act_rc.status().ToString()).c_str());
      }
    }

    std::string done_html;
    done_html += "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>";
    done_html += "<title>Setup Complete \xe2\x80\x93 " + ctx.cfg.instance_title + "</title><style>";
    done_html += "body{font-family:system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:0;background:#f0f4f9;color:#222}";
    done_html += ".wrap{max-width:520px;margin:48px auto;padding:0 16px}";
    done_html += "h1{font-size:1.5rem;margin:0 0 4px}";
    done_html += ".subtitle{color:#555;font-size:.9em;margin:0 0 28px}";
    done_html += ".wizard{display:flex;margin-bottom:32px;border-radius:10px;overflow:hidden;background:#fff;box-shadow:0 1px 4px rgba(0,0,0,.08)}";
    done_html += ".wstep{flex:1;text-align:center;padding:12px 6px;font-size:12px;font-weight:500;color:#137333;border-bottom:3px solid #137333}";
    done_html += ".card{background:#fff;padding:28px 28px 24px;border-radius:12px;box-shadow:0 2px 8px rgba(0,0,0,.07)}";
    done_html += ".check{font-size:3rem;text-align:center;margin-bottom:16px}";
    done_html += "h2{margin:0 0 12px;font-size:1.15rem;text-align:center}";
    done_html += ".btn{display:inline-block;margin-top:20px;padding:12px 20px;border:none;border-radius:7px;font-size:1em;font-weight:600;cursor:pointer;width:100%;text-align:center;text-decoration:none}";
    done_html += ".btn-primary{background:#0b57d0;color:#fff} .btn-primary:hover{background:#0842a0}";
    done_html += "</style></head><body><div class='wrap'>";
    done_html += "<h1>Complete Invitation</h1><p class='subtitle'>&nbsp;</p>";
    done_html += "<div class='wizard'>";
    done_html += "<div class='wstep'>1. Verify Email</div>";
    done_html += "<div class='wstep'>2. Enter Code</div>";
    done_html += "<div class='wstep'>3. Set Password</div>";
    done_html += "</div>";
    done_html += "<div class='card'>";
    done_html += "<div class='check'>\xe2\x9c\x93</div>";
    done_html += "<h2>You're all set!</h2>";
    done_html += "<p style='text-align:center;color:#555;font-size:.93em'>Your invitation has been completed. You can now sign in with your new credentials.</p>";
    done_html += "<a href='/login' class='btn btn-primary'>Sign In</a>";
    done_html += "</div></div></body></html>";

    auto r = HtmlPage(200, done_html);
    r.add_header("Set-Cookie", std::string(kInviteCookie) + "=deleted; Path=/; Max-Age=0; HttpOnly; SameSite=Lax");
    return r;
  });

  // ---- Send OTP email ----
  CROW_ROUTE(app, "/invite/otp/send").methods("POST"_method)([&ctx](const crow::request& req) {
    auto is = RequireInviteSession(ctx, req);
    if (!is.has_value()) return HtmlPage(401, "<h1>Invitation session expired</h1>");

    const auto csrf_val = core::FormGet(req.body, "_csrf");
    if (!csrf_val.has_value() || *csrf_val != is->sid) {
      return HtmlPage(403, "<h1>Invalid CSRF token</h1>");
    }

    const std::int64_t now = core::UnixNow();

    // Cooldown check (rate limiting).
    auto last_issued = ctx.invite_otps.GetLastIssuedAt(is->sid);
    if (!last_issued.ok()) return HtmlPage(500, "<h1>Internal error</h1>");
    if (last_issued.value().has_value()) {
      const std::int64_t diff = now - last_issued.value().value();
      if (diff < 60) {
        return RedirectTo("/invite/complete?err=Please+wait+60+seconds+before+requesting+a+new+code");
      }
    }

    auto inv = ctx.invites.GetById(is->invite_id);
    if (!inv.ok() || !inv.value().has_value()) return HtmlPage(404, "<h1>Invitation not found</h1>");
    const auto& row = *inv.value();

    // HIGH-03: Rejection-sampling to eliminate modular bias in the OTP.
    constexpr unsigned int kRange = 900000U;
    constexpr unsigned int kLimit = ((~0U) - (~0U) % kRange);
    unsigned int v = 0;
    for (int attempt = 0; attempt < 32; ++attempt) {
      auto rnd = core::RandomBytes(4);
      if (!rnd.ok()) return HtmlPage(500, "<h1>Internal error</h1>");
      v = (static_cast<unsigned int>(rnd.value()[0]) << 24) |
          (static_cast<unsigned int>(rnd.value()[1]) << 16) |
          (static_cast<unsigned int>(rnd.value()[2]) <<  8) |
          (static_cast<unsigned int>(rnd.value()[3]) <<  0);
      if (v < kLimit) break;
    }
    const std::string otp = std::to_string((v % kRange) + 100000U);

    std::vector<std::uint8_t> otp_bytes(otp.begin(), otp.end());
    auto h = core::Sha256(otp_bytes);
    if (!h.ok()) return HtmlPage(500, "<h1>Internal error</h1>");

    (void)ctx.invite_otps.DeleteBySid(is->sid);

    auto otp_id_bytes = core::RandomBytes(16);
    if (!otp_id_bytes.ok()) return HtmlPage(500, "<h1>Internal error</h1>");

    infra::InviteOtpRow o;
    o.otp_id       = core::HexEncode(otp_id_bytes.value());
    o.sid          = is->sid;
    o.otp_hash     = std::move(h.value());
    o.issued_at    = now;
    o.expires_at   = now + 600;  // 10 min
    o.attempts     = 0;
    o.max_attempts = 5;

    auto ins = ctx.invite_otps.Insert(o);
    if (!ins.ok()) return HtmlPage(500, "<h1>Internal error</h1>");

    const std::string subject  = "[" + ctx.cfg.instance_title + "] Your email verification code";
    const std::string body_txt =
        "Your " + ctx.cfg.instance_title + " verification code is:\n\n" + otp + "\n\n"
        "It expires in 10 minutes.\n";

    auto mail_rc = ctx.email.SendText(row.invited_email, subject, body_txt);
    if (!mail_rc.ok()) return HtmlPage(502, "<h1>Mail send failed</h1>");

    (void)ctx.invites.UpdateStatus(row.invite_id, infra::InviteStatus::kStepupSent, now);
    return RedirectTo("/invite/complete?sent=1");
  });

  // ---- Verify OTP ----
  CROW_ROUTE(app, "/invite/otp/verify").methods("POST"_method)([&ctx](const crow::request& req) {
    auto is = RequireInviteSession(ctx, req);
    if (!is.has_value()) return HtmlPage(401, "<h1>Invitation session expired</h1>");

    const auto csrf_val = core::FormGet(req.body, "_csrf");
    if (!csrf_val.has_value() || *csrf_val != is->sid) {
      return HtmlPage(403, "<h1>Invalid CSRF token</h1>");
    }

    const std::string code = core::FormGet(req.body, "code").value_or("");
    if (code.size() < 4 || code.size() > 10) return RedirectTo("/invite/complete?err=invalid+code");

    std::vector<std::uint8_t> otp_bytes(code.begin(), code.end());
    auto h = core::Sha256(otp_bytes);
    if (!h.ok()) return HtmlPage(500, "<h1>Internal error</h1>");

    const std::int64_t now = core::UnixNow();
    auto ok = ctx.invite_otps.VerifyAndConsume(is->sid, h.value(), now);
    if (!ok.ok()) return HtmlPage(500, "<h1>Internal error</h1>");
    if (!ok.value()) return RedirectTo("/invite/complete?err=wrong+code");

    auto inv_otp = ctx.invites.GetById(is->invite_id);
    if (inv_otp.ok() && inv_otp.value().has_value()) {
      (void)ctx.invites.UpdateStatus(is->invite_id, infra::InviteStatus::kStepupVerified, now);
    }
    return RedirectTo("/invite/complete?ok=1");
  });
}

}  // namespace gatehouse::app
