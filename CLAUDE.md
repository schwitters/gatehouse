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
./build/gatehouse --auth demo --db gatehouse.db
```

The binary must be run from the project root so the DB migration SQL files are found at `db/schema_v1.sql` and `db/schema_v2.sql` relative to CWD.

Key CLI flags:
- `--auth demo|krb5` — auth mode (demo uses hardcoded `demo`/`demo`)
- `--db PATH` — SQLite database path (default: `gatehouse.db`)
- `--port PORT` — HTTP port (default: 18080)
- `--ldap-url URL` / `--ldif PATH` — LDAP live lookup or LDIF fallback for invitations
- `--admin-uids CSV` — comma-separated UIDs that can access admin invitation APIs
- `--public-base-url URL` — base URL used in invite email links
- `--email-backend console|curl` — email delivery (`console` just prints to stdout)

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

```cpp
auto result = SomeFunc();
if (!result.ok()) return core::Result<T>::Err(result.status());
```

`core::Status` carries a `StatusCode` enum and a message string.

### Key components

| File | Responsibility |
|---|---|
| `src/main.cc` | CLI parsing, DB open + migrate, `HttpServer::Run()` |
| `src/app/http_server.cc` | All HTTP routes (Crow), inline HTML templates, JSON API |
| `src/app/auth.cc` | `AuthService::Verify()` — demo or Kerberos login |
| `src/infra/migrate.cc` | Applies `db/schema_v1.sql` then `db/schema_v2.sql` if needed |
| `src/infra/session_repo.cc` | CRUD for `auth_session` table |
| `src/infra/ticket_vault_repo.cc` | AES-256-GCM encrypted Kerberos ccache storage |
| `src/infra/invite_repo.cc` | Invite lifecycle (`kInvited` → `kCompleted`/`kRevoked`) |
| `src/infra/invite_otp_repo.cc` | 6-digit email OTP for invite step-up verification |
| `src/infra/ldap_directory.cc` | Live LDAP lookup for invited user's email |
| `src/infra/ldif_directory.cc` | In-memory LDIF parser (dev/test fallback) |
| `src/core/crypto_aead.cc` | AES-256-GCM encrypt/decrypt via OpenSSL |

### Database schema

Two versioned SQL files applied at startup in order:
- `db/schema_v1.sql` — creates `auth_session`, `ticket_vault`, `xrdp_otp`, `cred_fetch_token`, `audit_log`
- `db/schema_v2.sql` — adds `ticket_id` column to `auth_session`

Migration state is tracked via SQLite `PRAGMA user_version`.

### Invitation flow

1. Admin POSTs to `/api/admin/invites` → LDAP lookup for email → creates `invite` row → sends email with token
2. Invitee clicks link → `GET /invite/accept?token=<hex>` → validates token hash → creates `invite_session` cookie
3. Invitee at `/invite/complete` → requests email OTP → verifies OTP → submits display name → invite marked `kCompleted`

### Crow HTTP framework

Crow is fetched at configure time via CMake `FetchContent` (v1.3.0, from GitHub). A patch is applied to remove a Boost alias conflict. Uses `CROW_USE_BOOST` / Boost.Asio.

## No tests

There is currently no test suite. Manual testing uses the demo auth mode with `--auth demo`.
