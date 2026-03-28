# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

**Gatehouse** is a C++20 authentication and session gateway service. It handles user login (demo or Kerberos 5), session management, Kerberos ticket storage, and a multi-step invitation flow with email OTP step-up. It exposes both an HTML UI and a JSON API, served via the Crow HTTP framework.

## Build

### System dependencies (Debian/Ubuntu)

```bash
sudo apt-get install -y libsqlite3-dev libkrb5-dev libldap2-dev libssl-dev libcurl4-openssl-dev libboost-all-dev pkg-config
```

### Regular build

```bash
cmake -B build
cmake --build build -j$(nproc)
```

### AddressSanitizer build

```bash
cmake -B build-asan -DGATEHOUSE_ENABLE_ASAN=ON
cmake --build build-asan -j$(nproc)
```

The binary is output to `build/gatehouse` or `build-asan/gatehouse`.

## Running

The server **requires** the `GATEHOUSE_MASTER_KEY_HEX` environment variable (64 hex chars = 32-byte AES-256-GCM key for encrypting Kerberos ticket blobs):

```bash
export GATEHOUSE_MASTER_KEY_HEX=$(openssl rand -hex 32)
./build/gatehouse --db gatehouse.db --realm EXAMPLE.COM
```

The binary must be run from the project root so the DB migration SQL files are found at `db/schema_v1.sql` … `db/schema_v5.sql` relative to CWD.

Key CLI flags:
- `--db PATH` — SQLite database path (default: `gatehouse.db`)
- `--port PORT` — HTTP port (default: 18080)
- `--bind ADDR` — TCP bind address (default: `0.0.0.0`)
- `--unix-socket PATH` — listen on Unix Domain Socket instead of TCP
- `--threads N` — worker threads (default: 2)
- `--session-ttl SECONDS` — session lifetime (default: 3600)
- `--realm REALM` — Kerberos realm
- `--ldap-url URL` / `--ldif PATH` — LDAP live lookup or LDIF fallback for invitations
- `--ldap-bind-dn DN` / `--ldap-bind-pw PW` / `--ldap-base-dn DN` — LDAP credentials
- `--ldap-starttls` — upgrade LDAP connection with StartTLS
- `--ldap-admin-group DN` — LDAP group DN whose members get admin access
- `--admin-uids CSV` — comma-separated UIDs that can access admin invitation APIs
- `--public-base-url URL` — base URL used in invite email links
- `--invite-ttl SECONDS` — invite link lifetime (default: 604800)
- `--email-backend console|curl` — email delivery (`console` just prints to stdout)
- `--secure-cookies` — set Secure flag on session cookies (for HTTPS/reverse-proxy deployments)
- `--instance-title TITLE` — UI and email title (default: Gatehouse)
- `--guacamole-url URL` — Guacamole web app base URL; enables "Connect" buttons in the portal
- `--guacamole-secret SECRET` — shared secret for Guacamole Encrypted JSON authentication
- `--guac-token-ttl SECONDS` — credential-fetch token lifetime (default: 60)

Environment variables:
- `GATEHOUSE_MASTER_KEY_HEX` **(required)** — 64 hex chars = 32-byte AES-256-GCM key
- `GATEHOUSE_KADM5_ADMIN_PRINC` / `GATEHOUSE_KADM5_ADMIN_PASS` — Kerberos admin principal for invite completion
- `GATEHOUSE_SMTP_USER` / `GATEHOUSE_SMTP_PASS` / `GATEHOUSE_SMTP_URL` — SMTP credentials (`--email-backend curl`)

## Architecture

### Layer structure

```
src/core/      — Pure utilities with no external dependencies
src/app/       — Application logic (HTTP routing, auth service, email)
src/infra/     — I/O: SQLite repos, Kerberos client, LDAP/LDIF directory
```

Headers mirror the same three-layer structure under `include/`.

### Error handling pattern

All non-trivial functions return `core::Result<T>` (defined in `include/core/result.h`). There are no exceptions in business logic — exceptions are only caught at the HTTP handler boundary in `http_server.cc`. Check `.ok()` before calling `.value()`.

`Status::ToString()` is implemented in `src/core/result.cc`.

```cpp
auto result = SomeFunc();
if (!result.ok()) return core::Result<T>::Err(result.status());
```

`core::Status` carries a `StatusCode` enum and a message string.

### Key components

| File | Responsibility |
|---|---|
| `src/main.cc` | CLI parsing, DB open + migrate, `HttpServer::Run()` |
| `src/app/http_server.cc` | Server setup, instantiates `ServerContext`, calls all `RegisterXxxRoutes()` |
| `src/app/http_utils.cc` | Pure HTTP helpers: `HtmlPage`, `RedirectTo`, `Json`, `ApplyTitle`, `InviteStatusName`, etc. |
| `src/app/server_context.cc` | `ServerContext`, `LoginRateLimiter`, `RequireAuth`, `CsrfOkForm/Header`, `StoreTicketIfPresent`, etc. |
| `src/app/routes_misc.cc` | `/robots.txt`, `/api/healthz` |
| `src/app/routes_auth.cc` | `/login`, `/auth/logout`, `/auth/login`, `/api/auth/login` |
| `src/app/routes_portal.cc` | `/`, `/portal`, `/portal/changepw`, `/api/me`, `/api/me/hosts` |
| `src/app/routes_invite.cc` | `/invite/accept`, `/invite/complete`, `/invite/otp/send`, `/invite/otp/verify` |
| `src/app/routes_admin.cc` | `/admin/invites`, `/admin/tenants`, all `/api/admin/*` endpoints |
| `src/app/routes_guacamole.cc` | `/api/me/guacamole-session` (create session), `/api/cred-fetch/ticket` (PAM credential fetch) |
| `src/app/auth.cc` | `AuthService::Verify()` — demo or Kerberos login |
| `src/app/email_sender.cc` | Email delivery (console or curl/SMTP backend) |
| `src/infra/migrate.cc` | Applies `db/schema_v1.sql` … `db/schema_v5.sql` in order |
| `src/infra/session_repo.cc` | CRUD for `auth_session` table incl. CSRF secret |
| `src/infra/ticket_vault_repo.cc` | AES-256-GCM encrypted Kerberos ccache storage |
| `src/infra/ticket_vault_read.cc` | Read/decrypt path for ticket vault |
| `src/infra/invite_repo.cc` | Invite lifecycle (`kInvited` → `kCompleted`/`kRevoked`) |
| `src/infra/invite_session_repo.cc` | Sessions scoped to an invite acceptance flow |
| `src/infra/invite_otp_repo.cc` | 6-digit email OTP for invite step-up verification |
| `src/infra/xrdp_otp_repo.cc` | One-time passwords for the XRDP Remote Desktop gate |
| `src/infra/cred_fetch_token_repo.cc` | Short-lived tokens for XRDP host credential fetching |
| `src/infra/ldap_directory.cc` | Live LDAP lookup (email, group membership, tenant resolution) |
| `src/infra/ldif_directory.cc` | In-memory LDIF parser (dev/test fallback) |
| `src/infra/krb5_client.cc` | Kerberos 5 authentication and ccache handling |
| `src/infra/kadm5_client.cc` | Kerberos admin (kadmin) operations for invite completion |
| `src/core/crypto_aead.cc` | AES-256-GCM encrypt/decrypt via OpenSSL |
| `src/core/aes_cbc.cc` | AES-128-CBC encrypt + Base64/Base64URL encode (Guacamole Encrypted JSON) |

### Database schema

Five versioned SQL files applied at startup in order (migration state tracked via `PRAGMA user_version`):

| File | Changes |
|---|---|
| `db/schema_v1.sql` | Creates `auth_session`, `ticket_vault`, `xrdp_otp`, `cred_fetch_token`, `audit_log` |
| `db/schema_v2.sql` | Adds `ticket_id` column to `auth_session` |
| `db/schema_v3.sql` | Creates `invite` table |
| `db/schema_v4.sql` | Creates `invite_profile` and `invite_session` tables |
| `db/schema_v5.sql` | Creates `invite_otp` table |

### Invitation flow

1. Admin POSTs to `/api/admin/invites` → LDAP lookup for email → creates `invite` row → sends email with token
2. Invitee clicks link → `GET /invite/accept?token=<hex>` → validates token hash → creates `invite_session` cookie
3. Invitee at `/invite/complete` → requests email OTP (`POST /invite/otp/send`) → verifies OTP (`POST /invite/otp/verify`) → submits display name → invite marked `kCompleted`, Kerberos principal created via kadmin

### Guacamole integration flow

1. User clicks "Connect (SSH/RDP)" on a host card in `/portal`
2. Browser `POST /api/me/guacamole-session` `{hostname, protocol}` with CSRF header
3. Gatehouse verifies LDAP host access, generates a 32-byte one-time token (stored as SHA-256 hash), builds Guacamole Encrypted JSON, returns `{ok:true, url:...}`
4. Browser opens Guacamole URL in new tab; Guacamole connects using the token as password
5. PAM module in the target container calls `GET /api/cred-fetch/ticket?token=<hex>&uid=<uid>&host=<hostname>`
6. Gatehouse decodes token → SHA-256 → `VerifyAndConsume` → reads & decrypts Kerberos ccache → **deletes ticket** → returns `{ok:true, ccache_b64:...}`

Key parameters: `--guacamole-url`, `--guacamole-secret`, `--guac-token-ttl`

Guacamole encryption: AES-128-CBC (key = first 16 UTF-8 bytes of secret, zero-padded), random IV, output = `Base64URL(IV || ciphertext)`, passed as `?data=` query parameter.

### Security

- **CSRF:** `gh_csrf` cookie (JS-readable) + hidden `_csrf` field (HTML forms) / `X-CSRF-Token` header (JSON API)
- **Kerberos tickets:** stored encrypted in DB (AES-256-GCM); master key passed via `GATEHOUSE_MASTER_KEY_HEX`
- **Credential-fetch tokens:** SHA-256 hashed in DB; raw token passed as Guacamole password; single-use (`VerifyAndConsume`)
- **LDAP admin group:** members resolved via `IsUserInGroup` (supports `memberUid`, `member`, `uniqueMember`)
- **Session cookies:** `HttpOnly`; `Secure` flag opt-in via `--secure-cookies`
- **Audit log:** all auth events written to `audit_log` table (no secrets stored)

### HTTP routing structure

Routes are split by domain into separate files. All route files receive a `ServerContext&` (defined in `include/app/server_context.h`) that holds references to all shared services and repositories. Helper lambdas like `RequireAuth`, `CsrfOkForm/Header`, and `SetCsrfCookie` are free functions in `server_context.cc`.

`http_server.cc` sets up the context and calls:
```cpp
RegisterMiscRoutes(app, ctx);
RegisterAuthRoutes(app, ctx);
RegisterPortalRoutes(app, ctx);
RegisterInviteRoutes(app, ctx);
RegisterAdminRoutes(app, ctx);
RegisterGuacamoleRoutes(app, ctx);
```

### Crow HTTP framework

Crow is fetched at configure time via CMake `FetchContent` (v1.3.0, from GitHub). A patch is applied to remove a Boost alias conflict. Uses `CROW_USE_BOOST` / Boost.Asio.

## Tests

Unit tests cover the `core` layer (no Kerberos/LDAP dependencies):

```bash
cmake --build build -j$(nproc)
cd build && ctest --output-on-failure
```

Test files: `tests/core_result_test.cc`, `core_hex_test.cc`, `core_sha256_test.cc`, `core_url_test.cc`, `core_aead_test.cc`, `core_random_test.cc`.

Integration / end-to-end testing is done manually against a live Kerberos + LDAP environment.
