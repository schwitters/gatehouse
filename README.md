# Gatehouse

Gatehouse is an authentication and session gateway service written in C++20. It handles user login (demo mode or Kerberos 5), session management, a multi-step invitation flow with email OTP verification, and optional Apache Guacamole integration for browser-based SSH/RDP access.

It serves both a browser UI and a JSON API over HTTP via the [Crow](https://crowcpp.org/) framework, backed by a SQLite database.

---

## Table of Contents

1. [Requirements](#requirements)
2. [Build](#build)
3. [First Run](#first-run)
4. [Configuration Reference](#configuration-reference)
5. [User Invitation Flow](#user-invitation-flow)
6. [Guacamole Integration](#guacamole-integration)
7. [Running Tests](#running-tests)
8. [Directory Layout](#directory-layout)

---

## Requirements

**Operating system:** Debian/Ubuntu (tested). Other Linux distributions should work with equivalent packages.

**Build tools:** `cmake` (3.14+), a C++20-capable compiler (GCC 10+ or Clang 12+), `make` or `ninja`.

**System libraries:**

```bash
sudo apt-get update
sudo apt-get install -y \
    cmake build-essential \
    libsqlite3-dev \
    libkrb5-dev \
    libldap2-dev \
    libssl-dev \
    libcurl4-openssl-dev \
    libboost-all-dev \
    pkg-config
```

The Crow HTTP framework is fetched automatically by CMake at configure time — no manual download needed.

---

## Build

```bash
# Configure
cmake -B build

# Compile (uses all available CPU cores)
cmake --build build -j$(nproc)
```

The binary is written to `build/gatehouse`.

**Optional: AddressSanitizer build** (for development/debugging memory issues):

```bash
cmake -B build-asan -DGATEHOUSE_ENABLE_ASAN=ON
cmake --build build-asan -j$(nproc)
```

---

## First Run

Gatehouse requires one environment variable before it will start — a 256-bit master key used to encrypt stored Kerberos tickets:

```bash
# Generate a random key (do this once and store it securely)
export GATEHOUSE_MASTER_KEY_HEX=$(openssl rand -hex 32)

# Run the server
./build/gatehouse --db gatehouse.db --realm EXAMPLE.COM
```

> **Important:** Run the binary from the project root directory. The database migration SQL files (`db/schema_v1.sql` … `db/schema_v5.sql`) must be reachable relative to the current working directory.

The server listens on `http://0.0.0.0:18080` by default. Open that address in a browser to see the login page.

### Demo mode (no Kerberos)

If you omit `--realm`, Gatehouse falls back to demo mode, which accepts any username/password. Useful for local development.

---

## Configuration Reference

### CLI flags

| Flag | Default | Description |
|---|---|---|
| `--db PATH` | `gatehouse.db` | SQLite database file path |
| `--port PORT` | `18080` | HTTP port |
| `--bind ADDR` | `0.0.0.0` | TCP bind address |
| `--unix-socket PATH` | — | Listen on a Unix domain socket instead of TCP |
| `--threads N` | `2` | Number of worker threads |
| `--session-ttl SECONDS` | `3600` | How long a login session stays valid (1 hour) |
| `--realm REALM` | — | Kerberos realm (e.g. `EXAMPLE.COM`). Omit for demo mode |
| `--ldap-url URL` | — | LDAP server URL (e.g. `ldap://dc.example.com`) |
| `--ldif PATH` | — | LDIF file for dev/test (used when `--ldap-url` is absent) |
| `--ldap-bind-dn DN` | — | Service account DN for LDAP bind |
| `--ldap-bind-pw PW` | — | Password for the LDAP service account |
| `--ldap-base-dn DN` | — | Base DN for LDAP searches |
| `--ldap-starttls` | off | Upgrade LDAP connection with StartTLS |
| `--ldap-admin-group DN` | — | Members of this LDAP group get admin access in Gatehouse |
| `--admin-uids CSV` | — | Comma-separated UIDs with admin access (alternative to LDAP group) |
| `--public-base-url URL` | — | Base URL used in invitation email links (must be reachable by invitees) |
| `--invite-ttl SECONDS` | `604800` | Invitation link lifetime (7 days) |
| `--email-backend` | `console` | `console` prints emails to stdout; `curl` sends via SMTP |
| `--secure-cookies` | off | Add the `Secure` flag to session cookies (use behind HTTPS) |
| `--instance-title TITLE` | `Gatehouse` | Title shown in the UI and emails |
| `--guacamole-url URL` | — | Guacamole base URL; enables "Connect" buttons on the portal |
| `--guacamole-secret SECRET` | — | Shared secret for Guacamole Encrypted JSON authentication |
| `--guac-token-ttl SECONDS` | `60` | Lifetime of single-use credential-fetch tokens |

### Environment variables

| Variable | Required | Description |
|---|---|---|
| `GATEHOUSE_MASTER_KEY_HEX` | **Yes** | 64 hex characters (32-byte AES-256-GCM key) for encrypting Kerberos tickets |
| `GATEHOUSE_KADM5_ADMIN_PRINC` | No | Kerberos admin principal for creating principals during invite completion |
| `GATEHOUSE_KADM5_ADMIN_PASS` | No | Password for the Kerberos admin principal |
| `GATEHOUSE_SMTP_USER` | No | SMTP username (required with `--email-backend curl`) |
| `GATEHOUSE_SMTP_PASS` | No | SMTP password |
| `GATEHOUSE_SMTP_URL` | No | SMTP server URL (e.g. `smtps://mail.example.com:465`) |

### Example: production-like startup

```bash
export GATEHOUSE_MASTER_KEY_HEX="<your-64-hex-char-key>"
export GATEHOUSE_KADM5_ADMIN_PRINC="admin/admin@EXAMPLE.COM"
export GATEHOUSE_KADM5_ADMIN_PASS="secret"
export GATEHOUSE_SMTP_USER="noreply@example.com"
export GATEHOUSE_SMTP_PASS="smtppassword"
export GATEHOUSE_SMTP_URL="smtps://mail.example.com:465"

./build/gatehouse \
    --db /var/lib/gatehouse/gatehouse.db \
    --realm EXAMPLE.COM \
    --port 18080 \
    --ldap-url ldap://dc.example.com \
    --ldap-bind-dn "uid=svc-gatehouse,cn=users,dc=example,dc=com" \
    --ldap-bind-pw "ldappassword" \
    --ldap-base-dn "dc=example,dc=com" \
    --ldap-admin-group "cn=gatehouse-admins,cn=groups,dc=example,dc=com" \
    --public-base-url "https://gatehouse.example.com" \
    --email-backend curl \
    --secure-cookies \
    --instance-title "My Company Portal"
```

---

## User Invitation Flow

Gatehouse supports inviting new users via email before they have a Kerberos account:

1. **Admin sends invite** — POST to `/api/admin/invites` with the user's UID. Gatehouse looks up their email via LDAP and sends an invitation link.
2. **Invitee clicks the link** — Opens `/invite/accept?token=<hex>`, which starts an invite session.
3. **Email OTP verification** — The invitee requests a one-time code to their email and verifies it.
4. **Account creation** — The invitee submits a display name; Gatehouse creates their Kerberos principal via kadmin and marks the invite as completed.

The admin panel is available at `/admin/invites` (requires admin access).

---

## Guacamole Integration

When `--guacamole-url` and `--guacamole-secret` are set, each host card in the user portal shows a **Connect** button. Clicking it:

1. Calls `POST /api/me/guacamole-session` with the hostname and protocol.
2. Gatehouse verifies LDAP access, generates a one-time token, builds an Encrypted JSON payload, and returns a Guacamole URL.
3. The browser opens Guacamole in a new tab; the target host authenticates via a PAM module that calls back to Gatehouse to exchange the token for a Kerberos ccache.

The token is consumed on first use and automatically expires after `--guac-token-ttl` seconds.

---

## Running Tests

Unit tests cover the core utility layer and do not require Kerberos or LDAP:

```bash
cmake --build build -j$(nproc)
cd build && ctest --output-on-failure
```

---

## Directory Layout

```
src/core/       Pure utilities (crypto, result type, hex, SHA-256, …)
src/app/        HTTP routing, auth service, email, server context
src/infra/      I/O: SQLite repositories, Kerberos client, LDAP/LDIF
include/        Headers mirroring the same three-layer structure
db/             SQL migration files (schema_v1.sql … schema_v5.sql)
tests/          Unit tests
```
