BEGIN;
ALTER TABLE users ADD COLUMN IF NOT EXISTS recovery_code_hash TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_version BIGINT NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_totp_step BIGINT;
CREATE TABLE IF NOT EXISTS recovery_attempts (
    key TEXT PRIMARY KEY,
    attempts INTEGER NOT NULL,
    window_started TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_recovery_attempts_window ON recovery_attempts(window_started);
GRANT SELECT, INSERT, UPDATE, DELETE ON recovery_attempts TO notities_app;
COMMIT;
