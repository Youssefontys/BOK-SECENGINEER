-- Notitie-app, databaseschema.
-- Draait als de eigenaar van de database (POSTGRES_USER uit compose), niet
-- als de applicatierol. De applicatierol en zijn rechten worden daarna
-- gezet door 02-roles.sh.

-- pgcrypto levert pgp_sym_encrypt/pgp_sym_decrypt voor kolomencryptie.
-- Let op: lokaal mag de eigenaar dit zelf aanzetten omdat pgcrypto een
-- trusted extension is. Op Azure Database for PostgreSQL Flexible Server
-- moet de extensie eerst op de allow-list van de serverparameters staan.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
    id            SERIAL PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,
    -- Alleen de Argon2-hash, nooit het wachtwoord zelf. De hash bevat de
    -- salt en de parameters al, dus die hoeven niet in een eigen kolom.
    password_hash TEXT NOT NULL,
    -- Een TOTP-secret is een credential, net als een wachtwoord, maar moet
    -- leesbaar blijven om codes te kunnen verifieren: hashen kan dus niet,
    -- versleutelen wel. Daarom bytea en niet text: hier staat de uitvoer
    -- van pgp_sym_encrypt in, niet de sleutel zelf.
    --
    -- NOG TE DOEN, bewijsvoering voor het BoK-rapport (PoC database
    -- security, kolomniveau). Draai dit als je het rapport schrijft en
    -- maak er een screenshot van; de kolom moet onleesbare bytes tonen
    -- die met \x beginnen, niet de base32-secret:
    --
    --   docker compose exec db psql -U notities_owner -d notities \
    --     -c "SELECT username, totp_secret FROM users;"
    totp_secret   BYTEA NOT NULL,
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
