"""Registreren: beperkt, en een poging kost pas iets als er echt werk volgt.

Elke registratie kost twee Argon2-berekeningen en meldt of een gebruikersnaam
al bestaat. Zonder limiet is dat een gratis manier om accounts op te sporen
en de server te belasten.
"""

import json
import logging
import secrets

import pytest

import app as application
import ratelimit
from conftest import WACHTWOORD, haal_csrf, post_login

PREFIX = "regtest_"


@pytest.fixture(autouse=True)
def ruim_op(snelle_hasher, schone_teller):
    def wissen():
        with application.db() as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM users WHERE username LIKE %s", (PREFIX + "%",))

    wissen()
    yield
    wissen()


def naam():
    return PREFIX + secrets.token_hex(5)


def registreer(client, username, password=WACHTWOORD):
    token = haal_csrf(client, "/register")
    return client.post("/register", data={"csrf_token": token, "username": username, "password": password})


def ip_teller():
    sleutel = application.rate_key("register_ip", "ip", "127.0.0.1")
    with application.db() as conn, conn.cursor() as cur:
        cur.execute("SELECT failures FROM auth_throttle WHERE key = %s", (sleutel,))
        rij = cur.fetchone()
    return rij[0] if rij else None


def zet_blokkade(seconden):
    sleutel = application.rate_key("register_ip", "ip", "127.0.0.1")
    with application.db() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO auth_throttle (key, locked_until) VALUES (%s, now() + make_interval(secs => %s)) "
            "ON CONFLICT (key) DO UPDATE SET locked_until = EXCLUDED.locked_until",
            (sleutel, seconden),
        )


def test_registreren_is_per_ip_beperkt(client):
    beleid = ratelimit.POLICIES["register_ip"]
    if not beleid.enforce:
        pytest.skip("de registratielimiet blokkeert niet in deze IP-modus")

    toegestaan = [registreer(client, naam()).status_code for _ in range(beleid.max_failures)]
    assert toegestaan == [200] * beleid.max_failures

    geblokkeerd = registreer(client, naam())
    assert geblokkeerd.status_code == 429
    assert int(geblokkeerd.headers["Retry-After"]) > 0
    assert "Te veel registratiepogingen" in geblokkeerd.get_data(as_text=True)


def test_een_geblokkeerd_verzoek_maakt_geen_account_aan(client):
    zet_blokkade(600)
    gebruikersnaam = naam()

    assert registreer(client, gebruikersnaam).status_code == 429

    with application.db() as conn, conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM users WHERE username = %s", (gebruikersnaam,))
        assert cur.fetchone()[0] == 0


def test_ongeldige_invoer_kost_geen_poging(client):
    """Een tikfout hoort het budget niet op te maken, en ongeldige invoer is goedkoop."""
    for _ in range(30):
        assert registreer(client, "FOUTE NAAM!").status_code == 400
        assert registreer(client, naam(), password="te-kort").status_code == 400

    assert ip_teller() is None
    assert registreer(client, naam()).status_code == 200
    assert ip_teller() == 1


def test_bestaande_gebruikersnaam_geeft_409_en_telt_wel_mee(client, caplog):
    caplog.set_level(logging.INFO)
    gebruikersnaam = naam()
    assert registreer(client, gebruikersnaam).status_code == 200

    assert registreer(client, gebruikersnaam).status_code == 409

    # Elke vraag "bestaat deze naam al?" kost een poging: dat is precies wat
    # het opsporen van accounts duur maakt.
    assert ip_teller() == 2
    events = [json.loads(r.getMessage()) for r in caplog.records if r.name == application.app.logger.name]
    assert any(e["event"] == "register_username_taken" and e["username"] == gebruikersnaam for e in events)


def test_na_afloop_van_de_blokkade_kan_registreren_weer(client):
    zet_blokkade(600)
    assert registreer(client, naam()).status_code == 429

    with application.db() as conn, conn.cursor() as cur:
        cur.execute("UPDATE auth_throttle SET locked_until = now() - interval '1 second' WHERE locked_until IS NOT NULL")

    assert registreer(client, naam()).status_code == 200


def test_een_registratieblokkade_raakt_het_inloggen_niet(client, account):
    zet_blokkade(600)
    assert registreer(client, naam()).status_code == 429

    assert post_login(client, account["username"], WACHTWOORD).status_code == 302


def test_aanmaken_wordt_gelogd_zonder_wachtwoord(client, caplog):
    caplog.set_level(logging.INFO)
    gebruikersnaam = naam()
    registreer(client, gebruikersnaam, password="geheim-wachtwoord-123")

    regels = [r.getMessage() for r in caplog.records if r.name == application.app.logger.name]
    assert all("geheim-wachtwoord" not in regel for regel in regels)
    assert any(json.loads(r)["event"] == "account_created" for r in regels)
