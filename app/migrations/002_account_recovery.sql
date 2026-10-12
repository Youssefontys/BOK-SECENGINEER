BEGIN;
ALTER TABLE users ADD COLUMN IF NOT EXISTS recovery_code_hash TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_version BIGINT NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_totp_step BIGINT;
-- De oude tabel recovery_attempts hoort hier niet meer: de pogingenlimiet
-- staat nu in auth_throttle (003). Zie 004 voor het opruimen van bestaande volumes.
COMMIT;
