-- Notitie-app, databaseschema (eerste concept).

CREATE TABLE IF NOT EXISTS users (
    id            SERIAL PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,
    -- Alleen de Argon2-hash, nooit het wachtwoord zelf. De hash bevat de
    -- salt en de parameters al, dus die hoeven niet in een eigen kolom.
    password_hash TEXT NOT NULL,
    -- Let op: dit is een credential, net als een wachtwoord. Staat hier nu
    -- in plaintext, en dat is precies de kolom die straks de kandidaat is
    -- voor de column-level encryptie-PoC (BoK: database security).
    totp_secret   TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS notes (
    id         SERIAL PRIMARY KEY,
    -- ON DELETE CASCADE: notities van een verwijderde gebruiker blijven
    -- niet als wees achter in de database.
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title      TEXT NOT NULL,
    body       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_notes_user_id ON notes(user_id);
