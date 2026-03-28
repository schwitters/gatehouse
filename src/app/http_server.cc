#include "app/http_server.h"

#include <cstdint>
#include <cstdlib>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "app/auth.h"
#include "app/email_sender.h"
#include "app/routes.h"
#include "app/server_context.h"
#include "core/crypto_aead.h"
#include "core/hex.h"
#include "core/result.h"
#include "crow.h"
#include "infra/invite_otp_repo.h"
#include "infra/invite_repo.h"
#include "infra/invite_session_repo.h"
#include "infra/ldap_directory.h"
#include "infra/ldif_directory.h"
#include "infra/session_repo.h"
#include "infra/sqlite_db.h"
#include "infra/cred_fetch_token_repo.h"
#include "infra/ticket_vault_read.h"
#include "infra/ticket_vault_repo.h"

namespace gatehouse::app {

namespace {

core::Result<std::vector<std::uint8_t>> LoadMasterKeyFromEnv() {
  const char* p = std::getenv("GATEHOUSE_MASTER_KEY_HEX");
  if (p == nullptr || std::string(p).empty()) {
    return core::Result<std::vector<std::uint8_t>>::Err(core::Status::Error(
        core::StatusCode::kFailedPrecondition,
        "GATEHOUSE_MASTER_KEY_HEX not set (need 64 hex chars for 32-byte key)"));
  }
  auto key = core::HexDecode(p);
  if (!key.ok()) return key;
  if (key.value().size() != 32) {
    return core::Result<std::vector<std::uint8_t>>::Err(core::Status::Error(
        core::StatusCode::kInvalidArgument,
        "GATEHOUSE_MASTER_KEY_HEX must decode to 32 bytes"));
  }
  return key;
}

}  // namespace

HttpServer::HttpServer(HttpServerConfig cfg, std::shared_ptr<infra::SqliteDb> db)
    : cfg_(std::move(cfg)), db_(std::move(db)) {}

core::Result<void> HttpServer::Run() {
  try {
    crow::SimpleApp app;
    app.loglevel(crow::LogLevel::Warning);

    if (db_ == nullptr || !db_->is_open()) {
      return core::Result<void>::Err(
          core::Status::Error(core::StatusCode::kFailedPrecondition, "DB not open"));
    }

    auto mk = LoadMasterKeyFromEnv();
    if (!mk.ok()) return core::Result<void>::Err(mk.status());
    const std::vector<std::uint8_t> master_key = std::move(mk.value());

    // Directory setup (LDAP preferred over LDIF).
    std::optional<infra::LdapDirectory> ldap_dir;
    infra::LdifDirectory ldif_dir;
    if (!cfg_.ldap_url.empty()) {
      infra::LdapConfig lc;
      lc.url      = cfg_.ldap_url;
      lc.bind_dn  = cfg_.ldap_bind_dn;
      lc.bind_pw  = cfg_.ldap_bind_pw;
      lc.base_dn  = cfg_.ldap_base_dn;
      lc.starttls = cfg_.ldap_starttls;
      ldap_dir.emplace(lc);
    } else if (!cfg_.ldif_path.empty()) {
      auto rc = ldif_dir.LoadFile(cfg_.ldif_path);
      if (!rc.ok()) return core::Result<void>::Err(rc.status());
    }

    std::unique_ptr<IEmailSender> email;
    if (cfg_.email_backend == "curl") {
      email = std::make_unique<CurlSmtpsEmailSender>();
    } else {
      email = std::make_unique<ConsoleEmailSender>();
    }

    AuthService auth(cfg_.auth_cfg);

    infra::SessionRepo         sessions(*db_);
    infra::TicketVaultRepo     vault(*db_);
    infra::InviteRepo          invites(*db_);
    infra::InviteSessionRepo   invite_sessions(*db_);
    infra::InviteProfileRepo   invite_profiles(*db_);
    infra::InviteOtpRepo       invite_otps(*db_);
    infra::CredFetchTokenRepo  cred_fetch_tokens(*db_);
    infra::TicketVaultReadRepo ticket_vault_read(*db_);

    LoginRateLimiter rate_limiter;

    ServerContext ctx{
        cfg_,
        *db_,
        ldap_dir,
        ldif_dir,
        sessions,
        vault,
        invites,
        invite_sessions,
        invite_profiles,
        invite_otps,
        cred_fetch_tokens,
        ticket_vault_read,
        auth,
        *email,
        master_key,
        rate_limiter,
    };

    RegisterMiscRoutes(app, ctx);
    RegisterAuthRoutes(app, ctx);
    RegisterPortalRoutes(app, ctx);
    RegisterInviteRoutes(app, ctx);
    RegisterAdminRoutes(app, ctx);
    RegisterGuacamoleRoutes(app, ctx);

    app.concurrency(cfg_.threads);

    if (!cfg_.unix_socket.empty()) {
      app.local_socket_path(cfg_.unix_socket).run();
    } else {
      app.bindaddr(cfg_.bind_addr)
          .port(static_cast<std::uint16_t>(cfg_.port))
          .run();
    }

    return core::Result<void>::Ok();
  } catch (...) {
    return core::Result<void>::Err(
        core::Status::Error(core::StatusCode::kInternal, "HTTP server crashed"));
  }
}

}  // namespace gatehouse::app
