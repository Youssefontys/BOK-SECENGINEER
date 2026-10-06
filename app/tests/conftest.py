"""Gedeelde testopzet.

De regel hieronder zet de bovenliggende map op het importpad, zodat
`import app` werkt vanuit deze testmap zonder dat er een package van
gemaakt hoeft te worden.
"""

import os
import sys

import psycopg
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app as flask_app, get_encryption_key  # noqa: E402


@pytest.fixture
def client():
    flask_app.config["TESTING"] = True
    return flask_app.test_client()


def log_in_as(client, user_id):
    """Zet de sessie rechtstreeks.

    Bewust niet via de echte inlogroute: deze tests gaan over autorisatie
    (mag deze gebruiker hierbij?), niet over authenticatie (is het de juiste
    gebruiker?). De 2FA-stroom erbij halen zou de test alleen langer en
    brozer maken zonder dat hij meer bewijst.
    """
    with client.session_transaction() as session:
        session["user_id"] = user_id


@pytest.fixture
def twee_gebruikers():
    """Twee gebruikers, elk met één notitie. Wordt na afloop opgeruimd."""
    namen = ["test_gebruiker_a", "test_gebruiker_b"]
    ids = {}

    with psycopg.connect(os.environ["DATABASE_URL"]) as conn, conn.cursor() as cur:
        # Opruimen vooraf, voor het geval een eerdere run is afgebroken.
        cur.execute("DELETE FROM users WHERE username = ANY(%s)", (namen,))
        for naam in namen:
            cur.execute(
                "INSERT INTO users (username, password_hash, totp_secret)"
                " VALUES (%s, %s, pgp_sym_encrypt(%s, %s)) RETURNING id",
                (naam, "hash-niet-gebruikt-in-deze-test", "AAAAAAAA", get_encryption_key()),
            )
            ids[naam] = cur.fetchone()[0]

            cur.execute(
                "INSERT INTO notes (user_id, title, body) VALUES (%s, %s, %s)"
                " RETURNING id",
                (ids[naam], f"notitie van {naam}", "inhoud"),
            )
            ids[naam + "_notitie"] = cur.fetchone()[0]

    yield ids

    with psycopg.connect(os.environ["DATABASE_URL"]) as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM users WHERE username = ANY(%s)", (namen,))
