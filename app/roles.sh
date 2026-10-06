#!/bin/sh
# Least privilege voor de applicatierol.
#
# Draait als init-script in de Postgres-container, na schema.sql, en dus als
# de eigenaar van de database. De applicatie verbindt NIET met dit account.
#
# Waarom dit nodig is: de rol uit POSTGRES_USER is in het officiele
# postgres-image een superuser. Als de applicatie daarmee zou verbinden,
# mag een gelukte SQL-injectie of een gestolen connectiestring ook tabellen
# weggooien, extensies laden en andere databases lezen. De applicatie heeft
# daarentegen alleen rijen hoeven lezen en schrijven.
#
# NOG TE DOEN, bewijsvoering voor het BoK-rapport (PoC database security,
# least privilege). Draai dit als je het rapport schrijft en maak er een
# screenshot van; dit MOET falen met "must be owner of table notes":
#
#   docker compose exec db psql -U notities_app -d notities \
#     -c "DROP TABLE notes;"
#
# Ter contrast kun je hetzelfde commando met -U notities_owner draaien, dat
# slaagt wel. Die twee naast elkaar zijn het bewijs dat de scheiding werkt
# en niet alleen op papier staat. Let op: daarna heb je je tabel echt
# weggegooid, dus doe dat alleen met een wegwerpvolume.

set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<SQL
-- Inloggen mag, verder standaard niets.
CREATE ROLE ${APP_DB_USER} LOGIN PASSWORD '${APP_DB_PASSWORD}';

-- Geen DDL: de rol mag de database en het schema gebruiken, niets aanmaken.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT CONNECT ON DATABASE ${POSTGRES_DB} TO ${APP_DB_USER};
GRANT USAGE ON SCHEMA public TO ${APP_DB_USER};

-- Alleen de vier bewerkingen die de applicatie echt uitvoert, en alleen op
-- deze twee tabellen. Geen TRUNCATE, geen REFERENCES, geen TRIGGER.
GRANT SELECT, INSERT, UPDATE, DELETE ON users, notes TO ${APP_DB_USER};

-- SERIAL-kolommen gebruiken een sequence; zonder dit recht mislukt elke
-- INSERT met een nieuw id.
GRANT USAGE, SELECT ON SEQUENCE users_id_seq, notes_id_seq TO ${APP_DB_USER};
SQL

echo "Applicatierol ${APP_DB_USER} aangemaakt met least-privilege rechten."
