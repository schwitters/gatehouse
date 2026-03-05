PRAGMA foreign_keys = ON;

-- Email OTPs bound to invite_session (so one session, one OTP flow)
CREATE TABLE IF NOT EXISTS invite_otp (
  otp_id      TEXT PRIMARY KEY,
  sid         TEXT NOT NULL,            -- invite_session.sid
  otp_hash    BLOB NOT NULL,            -- SHA256(otp)
  issued_at   INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  attempts    INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 5,
  consumed_at INTEGER,
  FOREIGN KEY(sid) REFERENCES invite_session(sid)
);

CREATE INDEX IF NOT EXISTS idx_invite_otp_sid ON invite_otp(sid);
CREATE INDEX IF NOT EXISTS idx_invite_otp_expires ON invite_otp(expires_at);

-- Extend invite_session with stepup_verified_at if missing (best-effort via ALTER)
-- We'll not fail hard if it exists; migrator runs raw SQL, so we avoid ALTER here.
-- Instead, we store stepup verification as consumed_at on invite_otp plus a check in code.

PRAGMA user_version = 5;
