-- Schema v6: make cred_fetch_token.ticket_id nullable (ON DELETE SET NULL).
-- Allows reconnects after the PAM module has already fetched the Kerberos ticket,
-- since the vault entry is no longer deleted on cred-fetch (cred_fetch_token is
-- already single-use via VerifyAndConsume).

DROP TABLE IF EXISTS cred_fetch_token;

CREATE TABLE cred_fetch_token (
  cft_id            TEXT PRIMARY KEY,
  uid               TEXT NOT NULL,
  tenant_id         TEXT NOT NULL DEFAULT 'default',
  host_id           TEXT NOT NULL,
  token_hash        BLOB NOT NULL,
  issued_at         INTEGER NOT NULL,
  expires_at        INTEGER NOT NULL,
  consumed_at       INTEGER,
  ticket_id         TEXT,
  xrdp_otp_id       TEXT,
  FOREIGN KEY (ticket_id) REFERENCES ticket_vault(ticket_id) ON DELETE SET NULL,
  FOREIGN KEY (xrdp_otp_id) REFERENCES xrdp_otp(xrdp_otp_id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_cft_uid_host ON cred_fetch_token(uid, host_id);
CREATE INDEX IF NOT EXISTS idx_cft_expires   ON cred_fetch_token(expires_at);
