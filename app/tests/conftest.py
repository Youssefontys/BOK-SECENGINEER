"""Gedeelde testopzet.

De regel hieronder zet de bovenliggende map op het importpad, zodat
`import app` werkt vanuit deze testmap zonder dat er een package van
gemaakt hoeft te worden.
"""

import os
import re
import secrets
import sys
import time

import psycopg
import pyotp
import pytest
from argon2 import PasswordHasher

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as application  # noqa: E402
from app import app as flask_app, get_encryption_key  # noqa: E402


@pytest.fixture
def client():
    flask_app.config["TESTING"] = True
    return flask_app.test_client()


TEST_CSRF = "test-csrf-token"


def log_in_as(client, user_id):
    """Zet de sessie rechtstreeks.

    Bewust niet via de echte inlogroute: deze tests gaan over autorisatie
    (mag deze gebruiker hierbij?), niet over authenticatie (is het de juiste
    gebruiker?). De 2FA-stroom erbij halen zou de test alleen langer en
    brozer maken zonder dat hij meer bewijst.

    Zet ook meteen een CSRF-token in de sessie, dat tests als TEST_CSRF
    meesturen. Een token ophalen via een GET zou bij tests met een
    database-double de gemockte antwoorden opmaken.
    """
    with client.session_transaction() as session:
        session["user_id"] = user_id
        session["auth_version"] = 0
        session["csrf_token"] = TEST_CSRF


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


# --- Opzet voor de tests van de login-throttling ---------------------------

WACHTWOORD = "een-lang-genoeg-wachtwoord"


@pytest.fixture
def snelle_hasher(monkeypatch):
    """Argon2 met minimale kosten, zodat tests met tientallen pogingen snel blijven.

    De kosten zijn voor wat hier getest wordt niet van belang: het gaat om
    hoe vaak er geverifieerd wordt, niet om hoe duur één verificatie is. De
    dummy-hash wordt mee vervangen, anders blijft die op de dure standaard.
    """
    snel = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1)
    monkeypatch.setattr(application, "ph", snel)
    monkeypatch.setattr(application, "DUMMY_RECOVERY_HASH", snel.hash("dummy-" + secrets.token_hex(8)))
    return snel


@pytest.fixture
def schone_teller():
    """Leeg de throttle-tabel voor en na de test.

    Alle tests komen van hetzelfde adres (127.0.0.1), dus zonder dit zou een
    blokkade uit de ene test de volgende raken.
    """
    def wissen():
        with application.db() as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM auth_throttle")

    wissen()
    yield
    wissen()


@pytest.fixture
def account(snelle_hasher, schone_teller):
    """Een echt account met bekend wachtwoord en een bekende TOTP-secret."""
    naam = "throttle_" + secrets.token_hex(5)
    secret = pyotp.random_base32()
    with application.db() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO users (username, password_hash, totp_secret)"
            " VALUES (%s, %s, pgp_sym_encrypt(%s, %s)) RETURNING id",
            (naam, application.ph.hash(WACHTWOORD), secret, get_encryption_key()),
        )
        gebruiker_id = cur.fetchone()[0]
    yield {"id": gebruiker_id, "username": naam, "password": WACHTWOORD, "secret": secret}
    with application.db() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM users WHERE id = %s", (gebruiker_id,))


def haal_csrf(client, path):
    pagina = client.get(path).get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', pagina).group(1)


def post_login(client, username, password, headers=None):
    token = haal_csrf(client, "/login")
    return client.post(
        "/login",
        data={"csrf_token": token, "username": username, "password": password},
        headers=headers or {},
    )


def post_2fa(client, code):
    token = haal_csrf(client, "/login/2fa")
    return client.post("/login/2fa", data={"csrf_token": token, "code": code})


def foute_code(secret):
    """Een zescijferige code die op dit moment zeker niet geldig is."""
    huidig = int(time.time()) // 30
    geldig = {pyotp.TOTP(secret).at(stap * 30) for stap in (huidig - 1, huidig, huidig + 1)}
    return next(f"{n:06d}" for n in range(1000) if f"{n:06d}" not in geldig)


class RijSlot:
    """Houdt het rijslot op een gebruiker vast, zodat verzoeken erop moeten wachten.

    Voor tests die willen bewijzen dat code iets pas doet nadat ze het slot
    heeft: de test houdt het slot, laat verzoeken eraan lopen, verandert iets
    terwijl ze wachten, en laat dan los. Wie nog vóór het slot telde of las,
    ziet de verandering niet en geeft het verkeerde antwoord.

    Een tweede verbinding in autocommit kijkt toe. Postgres cachet
    pg_stat_activity namelijk binnen een transactie, dus wie in dezelfde
    transactie blijft pollen ziet steeds dezelfde verouderde momentopname.

    Gebruik sluit() altijd in een finally, vóór een threadpool wordt
    afgesloten: wachtende threads hangen anders eindeloos op een slot dat
    alleen deze test kan loslaten.
    """

    def __init__(self, user_id):
        self.houder = psycopg.connect(os.environ["DATABASE_URL"])
        self.kijker = psycopg.connect(os.environ["DATABASE_URL"], autocommit=True)
        self.cur = self.houder.cursor()
        self.cur.execute("SELECT 1 FROM users WHERE id = %s FOR UPDATE", (user_id,))

    def wacht_op(self, aantal, seconden=15):
        """Wacht tot minstens `aantal` sessies op een slot staan te wachten."""
        wachtend = 0
        for _ in range(int(seconden * 10)):
            wachtend = self.kijker.execute(
                "SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock'"
            ).fetchone()[0]
            if wachtend >= aantal:
                return
            time.sleep(0.1)
        raise AssertionError(f"slechts {wachtend} van {aantal} verzoeken bereikte het rijslot")

    def commit(self):
        self.houder.commit()

    def sluit(self):
        self.houder.rollback()
        self.houder.close()
        self.kijker.close()
