CREATE TABLE provisioning_job (
  invite_id TEXT PRIMARY KEY REFERENCES invite(invite_id),
  session_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  uid TEXT NOT NULL,
  stage INTEGER NOT NULL CHECK (stage BETWEEN 0 AND 5),
  updated_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX provisioning_active_user
  ON provisioning_job(tenant_id, uid) WHERE stage BETWEEN 1 AND 4;

-- A running or uncertain external operation must be reconciled before revocation.
CREATE TRIGGER protect_provisioning_revocation
BEFORE UPDATE OF status ON invite
WHEN NEW.status IN (5, 6) AND EXISTS (
  SELECT 1 FROM provisioning_job
  WHERE invite_id = OLD.invite_id AND stage BETWEEN 1 AND 4
)
BEGIN
  SELECT RAISE(ABORT, 'Provisioning must be reconciled before revocation');
END;
PRAGMA user_version = 7;

CREATE TABLE provisioning_event (
  event_id INTEGER PRIMARY KEY,
  invite_id TEXT NOT NULL,
  stage INTEGER NOT NULL,
  actor TEXT NOT NULL DEFAULT 'service',
  created_at INTEGER NOT NULL
);
CREATE TRIGGER provisioning_checkpoint
AFTER UPDATE OF stage ON provisioning_job
BEGIN
  INSERT INTO provisioning_event(invite_id, stage, created_at)
  VALUES (NEW.invite_id, NEW.stage, NEW.updated_at);
END;
