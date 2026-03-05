PRAGMA foreign_keys = ON;

-- Sessions
CREATE TABLE IF NOT EXISTS auth_session (
  sid              TEXT PRIMARY KEY,
  uid              TEXT NOT NULL,
  tenant_id         TEXT NOT NULL DEFAULT 'default',
  created_at        INTEGER NOT NULL,
  expires_at        INTEGER NOT NULL,
  mfa_state         INTEGER NOT NULL DEFAULT 0, -- 0=none,1=pending,2=verified
  ip_hash           BLOB,
  ua_hash           BLOB,
  csrf_secret       BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auth_session_uid ON auth_session(uid);
CREATE INDEX IF NOT EXISTS idx_auth_session_expires ON auth_session(expires_at);

-- Kerberos ticket vault (encrypted blob; crypto handled in app layer)
CREATE TABLE IF NOT EXISTS ticket_vault (
  ticket_id         TEXT PRIMARY KEY,
  uid               TEXT NOT NULL,
  tenant_id         TEXT NOT NULL DEFAULT 'default',
  created_at        INTEGER NOT NULL,
  expires_at        INTEGER NOT NULL,
  enc_alg           TEXT NOT NULL,
  enc_key_id        TEXT NOT NULL,
  nonce             BLOB NOT NULL,
  aad               BLOB,
  ccache_blob_enc   BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ticket_vault_uid ON ticket_vault(uid);
CREATE INDEX IF NOT EXISTS idx_ticket_vault_expires ON ticket_vault(expires_at);

-- XRDP OTP gate
CREATE TABLE IF NOT EXISTS xrdp_otp (
  xrdp_otp_id       TEXT PRIMARY KEY,
  uid               TEXT NOT NULL,
  tenant_id         TEXT NOT NULL DEFAULT 'default',
  host_id           TEXT NOT NULL,
  otp_hash          BLOB NOT NULL,
  attempts          INTEGER NOT NULL DEFAULT 0,
  max_attempts      INTEGER NOT NULL DEFAULT 3,
  issued_at         INTEGER NOT NULL,
  expires_at        INTEGER NOT NULL,
  consumed_at       INTEGER,
  issued_by_sid     TEXT,
  ticket_id         TEXT NOT NULL,
  FOREIGN KEY (issued_by_sid) REFERENCES auth_session(sid) ON DELETE SET NULL,
  FOREIGN KEY (ticket_id) REFERENCES ticket_vault(ticket_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_xrdp_otp_uid ON xrdp_otp(uid);
CREATE INDEX IF NOT EXISTS idx_xrdp_otp_host ON xrdp_otp(host_id);
CREATE INDEX IF NOT EXISTS idx_xrdp_otp_expires ON xrdp_otp(expires_at);

-- Credential fetch token for XRDP host
CREATE TABLE IF NOT EXISTS cred_fetch_token (
  cft_id            TEXT PRIMARY KEY,
  uid               TEXT NOT NULL,
  tenant_id         TEXT NOT NULL DEFAULT 'default',
  host_id           TEXT NOT NULL,
  token_hash        BLOB NOT NULL,
  issued_at         INTEGER NOT NULL,
  expires_at        INTEGER NOT NULL,
  consumed_at       INTEGER,
  ticket_id         TEXT NOT NULL,
  xrdp_otp_id       TEXT,
  FOREIGN KEY (ticket_id) REFERENCES ticket_vault(ticket_id) ON DELETE CASCADE,
  FOREIGN KEY (xrdp_otp_id) REFERENCES xrdp_otp(xrdp_otp_id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_cft_uid_host ON cred_fetch_token(uid, host_id);
CREATE INDEX IF NOT EXISTS idx_cft_expires ON cred_fetch_token(expires_at);

-- Audit log (no secrets)
CREATE TABLE IF NOT EXISTS audit_log (
  audit_id          TEXT PRIMARY KEY,
  ts               INTEGER NOT NULL,
  tenant_id         TEXT NOT NULL DEFAULT 'default',
  uid               TEXT,
  event_type        TEXT NOT NULL,
  event_data_json   TEXT NOT NULL DEFAULT '{}',
  ip_hash           BLOB,
  ua_hash           BLOB
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_uid ON audit_log(uid);

