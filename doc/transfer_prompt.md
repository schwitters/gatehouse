# Transfer Prompt: Gatehouse (CrowCpp + SQLite + LDAP + Invite Portal + Kerberos groundwork)

You are taking over development of **Gatehouse**, a Linux webapp/portal implemented in **C++20** with **CrowCpp** and **SQLite**, following **Clean Architecture**, **Google C++ Style Guide**, safe programming, and **Result/Status**-based error handling (no exceptions as design goal; some try/catch may exist around web handlers for safety).

## Current goals of Gatehouse

* Handle **invitations** for users managed in LDAP.
* Serve as a **portal**: unauthenticated users are redirected to login; admin users can create/manage invitations.
* Email is used both to deliver invite links and (now) as **second factor** via **Email OTP step-up** during invitation completion.
* LDAP data model supports many tenant OUs like `ou=k8s-20260118,dc=catuno,dc=lab` with users under `ou=people`.

## Tech stack / Build

* **C++20**, **CMake** project.
* **CrowCpp** fetched via FetchContent (with custom patch to avoid Boost conflict).
* Uses **Boost ASIO** (`-DCROW_USE_BOOST`, etc.) and suppresses warnings from third-party headers (system includes + warning disables).
* Uses **SQLite** (custom wrapper `infra::SqliteDb`).
* Uses **OpenSSL** for SHA256 and AES-256-GCM (ticket vault encryption).
* Uses **OpenLDAP libldap** for live LDAP search (and optional LDIF fallback in earlier iterations).
* Uses **libcurl** for SMTP(S) email sending.

## Runtime configuration

### Required env vars

* `GATEHOUSE_MASTER_KEY_HEX` (32 bytes hex, i.e. 64 hex chars): master key used to encrypt Kerberos ccache in ticket vault.

### Email backend

* CLI flag: `--email-backend console|curl`.
* If `curl`: uses env vars:

  * `GMAIL_USER`
  * `GMAIL_APP_PASS`
  * optional `SMTP_URL` (default `smtps://smtp.gmail.com:465`)

### LDAP configuration

Passed via CLI flags:

* `--ldap-url ldaps://...` or `ldap://...` (+ `--ldap-starttls`)
* `--ldap-bind-dn "cn=admin,dc=catuno,dc=lab"`
* `--ldap-bind-pw "SECRET"`
* `--ldap-base-dn "dc=catuno,dc=lab"`

Lookup behavior:

* Base for users: `ou=people,ou=<tenant_ou>,<base_dn>`
* Filter: `(uid=<uid>)`
* Attribute: `mail`

### Admin allowlist

* Simple allowlist via CLI: `--admin-uids demo,otheradmin`.

## Functional status (CURRENT)

### 1) Admin portal UI

* `/portal` shows signed-in user and an admin link if `uid` in `admin_uids`.
* `/admin/invites` is a single-page UI to:

  * Create invite by `tenant_ou + uid`
  * List latest invites (filters: tenant, uid)
  * Revoke invite
  * Resend (implemented as create a **new invite**, since token cannot be recovered)

### 2) Invitation creation (API)

* `POST /api/admin/invites` (requires authenticated admin)

  * Body: `{ "tenant_ou": "k8s-20260118", "uid": "krm" }`
  * Looks up LDAP `mail`.
  * Generates random token (hex) and stores **SHA256(token)** in DB.
  * Sends email with invite URL: `/invite/accept?token=<hex>`
  * Returns JSON including `invite_url`.

### 3) Invitation list/revoke (API)

* `GET /api/admin/invites/list?tenant_id=...&invited_uid=...`
* `POST /api/admin/invites/revoke { invite_id }`

### 4) Invite accept -> session cookie -> completion

* `GET /invite/accept?token=<hex>`

  * Validates token by SHA256 lookup
  * Checks not expired/revoked
  * Updates invite status to `LinkVerified`
  * Creates `invite_session` row and sets cookie `gh_inv_sid` (HttpOnly) then redirects to `/invite/complete`

### 5) NEW: Email OTP step-up during invite completion

* `/invite/complete` GET now gates completion behind OTP verification.

  * If not verified:

    * Shows **Send code** form: `POST /invite/otp/send`
    * Shows **Verify** form: `POST /invite/otp/verify` with `code`
  * If verified:

    * Shows profile fields (currently: display_name) and Finish.
* `POST /invite/otp/send`

  * Generates 6-digit OTP, TTL 10 minutes, max attempts 5.
  * Stores SHA256(otp) in `invite_otp` bound to current invite session `sid`.
  * Sends OTP via email to `invited_email`.
* `POST /invite/otp/verify`

  * Hashes code and calls repo VerifyAndConsume.
  * If ok, step-up considered verified (repo checks `invite_otp.consumed_at IS NOT NULL`).
* `POST /invite/complete` (after OTP verified)

  * Upserts `invite_profile(display_name)`.
  * Marks invite status `Completed`.
  * Consumes invite_session.

### 6) Authentication

* There is an auth subsystem with modes `demo` and `krb5` (Kerberos web-login).
* Ticket vault exists to store encrypted Kerberos ccache; currently invitation flow does not depend on Kerberos.

## Database schema / migrations

SQLite uses `PRAGMA user_version` incremental migrations.

* v3: `invite` table
* v4: `invite_session`, `invite_profile`
* v5: `invite_otp`

Tables of interest:

* `invite(invite_id, tenant_id, invited_email, invited_uid, token_hash, status, created_at, expires_at, consumed_at, revoked_at, created_by, roles_json)`
* `invite_session(sid, invite_id, created_at, expires_at, consumed_at)`
* `invite_profile(invite_id, display_name, created_at, updated_at)`
* `invite_otp(otp_id, sid, otp_hash, issued_at, expires_at, attempts, max_attempts, consumed_at)`

## Key implementation notes

* A previous iteration corrupted `http_server.cc` due to raw-string delimiters; the file was **fully rewritten** to use safe delimiters like `R"LOGIN(... )LOGIN"` and `R"ADMIN(... )ADMIN"`.
* LDAP lookup had earlier crashes; solved by simplifying to direct `ldap_get_values_len("mail")` and adding logging.
* Email sender uses libcurl SMTP(S) with MIME; currently Gatehouse uses `SendText()` only.

## How to run (typical)

```bash
export GATEHOUSE_MASTER_KEY_HEX="$(openssl rand -hex 32)"

# email backend curl
export GMAIL_USER="you@gmail.com"
export GMAIL_APP_PASS="<app-password>"
export SMTP_URL="smtps://smtp.gmail.com:465"  # optional

./build/gatehouse \
  --db gatehouse.db --port 18080 \
  --auth demo \
  --email-backend curl \
  --public-base-url http://127.0.0.1:18080 \
  --admin-uids demo \
  --ldap-url "ldaps://YOUR-LDAP:636" \
  --ldap-bind-dn "cn=admin,dc=catuno,dc=lab" \
  --ldap-bind-pw "SECRET" \
  --ldap-base-dn "dc=catuno,dc=lab"
```

## Immediate next steps (recommended)

1. **Harden OTP verification**

   * Increment attempts even on wrong code (currently attempts increments only when matched; consider tracking wrong attempts by sid).
   * Rate limit `/invite/otp/send` and `/invite/otp/verify`.
2. **Invite completion should create/activate user**

   * Currently it only stores `invite_profile` and marks invite completed.
   * Next: integrate with Keycloak or with LDAP/Kerberos provisioning (decide later).
3. Admin permissions: replace allowlist with LDAP group check.
4. Better UI/UX: show status changes, revoke confirmations, display invite status and completion data.

## Constraints / style rules to keep

* Follow Google C++ Style.
* Prefer `Result<T>` / `Status` returns; avoid exceptions.
* Keep dependencies minimal and Debian-friendly.
* Crow routes should not crash server: defensive validation, fail-fast, meaningful HTTP status codes.

## Files that matter right now

* `src/app/http_server.cc` (currently working, rewritten with safe raw strings)
* `src/infra/ldap_directory.cc` (live LDAP lookup)
* `src/app/email_sender.cc` (libcurl SMTPS sender, env-driven)
* `src/infra/migrate.cc` + `include/infra/migrate.h` (v1..v5 migrations)
* `db/schema_v3.sql`, `db/schema_v4.sql`, `db/schema_v5.sql`
* `src/infra/invite_repo.cc`, `src/infra/invite_session_repo.cc`, `src/infra/invite_otp_repo.cc`

## Conversation context / product intent

Gatehouse is part of a larger environment where:

* Users are in LDAP and authenticate via Kerberos (MIT) on Debian 13.
* Gatehouse will later broker access to Guacamole/xRDP sessions (guacamole-auth-json), map users to xRDP hosts by LDAP attributes, and provide OTP-based login gating for xRDP plus Kerberos ticket handing. That broader functionality is planned but not the current focus.

End of transfer prompt.
