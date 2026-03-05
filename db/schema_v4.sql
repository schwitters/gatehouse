-- Gatehouse schema v4: invitation completion flow
PRAGMA foreign_keys = ON;

-- Add profile_json if missing (SQLite lacks IF NOT EXISTS for ADD COLUMN, so this is best-effort).
-- If column exists, this statement will fail; migrations run in a tx, so we avoid failing by checking in code later.
-- For simplicity we DO NOT ALTER here. We'll store profile in separate table instead.

CREATE TABLE IF NOT EXISTS invite_profile (
  invite_id     TEXT PRIMARY KEY,
  display_name  TEXT,
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL
);

-- Track invite sessions (created when invite link is opened)
CREATE TABLE IF NOT EXISTS invite_session (
  sid         TEXT PRIMARY KEY,
  invite_id   TEXT NOT NULL,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  consumed_at INTEGER,
  FOREIGN KEY(invite_id) REFERENCES invite(invite_id)
);

CREATE INDEX IF NOT EXISTS idx_invite_session_invite_id ON invite_session(invite_id);
CREATE INDEX IF NOT EXISTS idx_invite_session_expires ON invite_session(expires_at);

PRAGMA user_version = 4;
