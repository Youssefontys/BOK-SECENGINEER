BEGIN;
-- Of de notitie met de afgeleide sleutel notes-bound is versleuteld (gebonden
-- aan de eigenaar), of nog met de oude sleutel zonder context. Bestaande
-- rijen zijn false tot `flask rewrap-notes` ze heeft omgezet.
ALTER TABLE notes ADD COLUMN IF NOT EXISTS bound BOOLEAN NOT NULL DEFAULT FALSE;
COMMIT;
