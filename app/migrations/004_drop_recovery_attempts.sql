BEGIN;
-- Vervangen door auth_throttle: /recover en de herstelcode gebruiken nu
-- dezelfde limietmodule (ratelimit.py) als het inloggen.
DROP TABLE IF EXISTS recovery_attempts;
COMMIT;
