-- Ook uitvoeren bij een bestaand dbdata-volume; idempotent en zonder dataverlies.
-- Bestaande rijen blijven leesbaar. Nieuwe/bewerkte notities gebruiken Vault.
ALTER TABLE notes ADD COLUMN IF NOT EXISTS encrypted BOOLEAN NOT NULL DEFAULT FALSE;
