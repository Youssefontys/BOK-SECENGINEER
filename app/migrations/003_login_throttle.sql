BEGIN;
-- Teller en blokkade per sleutel (ip, account+ip, account). De sleutels zijn
-- HMAC's, dus er staan geen leesbare IP-adressen of gebruikersnamen in.
CREATE TABLE IF NOT EXISTS auth_throttle (
    key            TEXT PRIMARY KEY,
    failures       INTEGER NOT NULL DEFAULT 0,
    window_started TIMESTAMPTZ NOT NULL DEFAULT now(),
    locked_until   TIMESTAMPTZ,
    lock_count     INTEGER NOT NULL DEFAULT 0,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_auth_throttle_updated ON auth_throttle(updated_at);
GRANT SELECT, INSERT, UPDATE, DELETE ON auth_throttle TO notities_app;
COMMIT;
