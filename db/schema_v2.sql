-- Gatehouse schema v2
PRAGMA foreign_keys = ON;

-- Link session to last-issued Kerberos ticket (ticket_vault.ticket_id)
ALTER TABLE auth_session ADD COLUMN ticket_id TEXT;

CREATE INDEX IF NOT EXISTS idx_auth_session_ticket_id ON auth_session(ticket_id);

PRAGMA user_version = 2;
