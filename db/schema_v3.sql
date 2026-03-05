-- Gatehouse schema v3: invitations
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS invite (
  invite_id      TEXT PRIMARY KEY,
  tenant_id      TEXT NOT NULL,
  invited_email  TEXT NOT NULL,
  invited_uid    TEXT,
  roles_json     TEXT NOT NULL DEFAULT '[]',
  token_hash     BLOB NOT NULL,        -- SHA256(token)
  status         INTEGER NOT NULL,     -- InviteStatus
  created_at     INTEGER NOT NULL,
  expires_at     INTEGER NOT NULL,
  consumed_at    INTEGER,
  revoked_at     INTEGER,
  created_by     TEXT
);

CREATE INDEX IF NOT EXISTS idx_invite_tenant_created ON invite(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_invite_token_hash ON invite(token_hash);

PRAGMA user_version = 3;
