"""Hoe lang een sessie geldig is, en wat uitloggen echt doet.

Flask bewaart de sessie in de cookie zelf, ondertekend. De server onthoudt
niets. Daardoor is "de cookie wissen" bij uitloggen niet genoeg: wie een
kopie van de cookie heeft, blijft binnen. Twee dingen beperken dat: een korte
levensduur van de cookie, en een sessieversie in de database die bij
uitloggen omhooggaat, zodat elke bestaande cookie ongeldig wordt.
"""

from datetime import timedelta
import time

import app as application
from conftest import TEST_CSRF, log_in_as


def cookie_met_leeftijd(monkeypatch, user_id, uren):
    """Een geldig ondertekende sessiecookie, zo gemaakt alsof hij `uren` geleden is uitgegeven."""
    serializer = application.app.session_interface.get_signing_serializer(application.app)
    nu = time.time()
    with monkeypatch.context() as m:
        m.setattr(time, "time", lambda: nu - uren * 3600)
        return serializer.dumps({"user_id": user_id, "auth_version": 0, "csrf_token": TEST_CSRF})


def test_de_levensduur_van_de_cookie_is_kort():
    assert application.app.permanent_session_lifetime <= timedelta(hours=12)


def test_een_cookie_ouder_dan_de_levensduur_wordt_geweigerd(client, twee_gebruikers, monkeypatch):
    b = twee_gebruikers["test_gebruiker_b"]
    client.set_cookie("session", cookie_met_leeftijd(monkeypatch, b, uren=9))

    antwoord = client.get("/")

    assert antwoord.status_code == 302 and antwoord.headers["Location"] == "/login"


def test_een_verse_cookie_werkt_wel(client, twee_gebruikers, monkeypatch):
    """Tegenproef: de cookie is niet om een andere reden ongeldig."""
    b = twee_gebruikers["test_gebruiker_b"]
    client.set_cookie("session", cookie_met_leeftijd(monkeypatch, b, uren=1))

    assert client.get("/").status_code == 200


def test_een_gekopieerde_cookie_werkt_niet_meer_na_uitloggen(client, twee_gebruikers):
    b = twee_gebruikers["test_gebruiker_b"]
    log_in_as(client, b)
    kopie = client.get_cookie("session").value

    dief = application.app.test_client()
    dief.set_cookie("session", kopie)
    assert dief.get("/").status_code == 200, "een kopie werkt zolang je ingelogd bent"

    assert client.post("/logout", data={"csrf_token": TEST_CSRF}).status_code == 302

    antwoord = dief.get("/")
    assert antwoord.status_code == 302 and antwoord.headers["Location"] == "/login"


def test_uitloggen_logt_ook_andere_apparaten_van_dit_account_uit(client, twee_gebruikers):
    b = twee_gebruikers["test_gebruiker_b"]
    laptop, telefoon = client, application.app.test_client()
    log_in_as(laptop, b)
    log_in_as(telefoon, b)
    assert telefoon.get("/").status_code == 200

    laptop.post("/logout", data={"csrf_token": TEST_CSRF})

    assert telefoon.get("/").status_code == 302


def test_uitloggen_van_een_account_raakt_andere_accounts_niet(client, twee_gebruikers):
    a, b = twee_gebruikers["test_gebruiker_a"], twee_gebruikers["test_gebruiker_b"]
    andere = application.app.test_client()
    log_in_as(client, b)
    log_in_as(andere, a)

    client.post("/logout", data={"csrf_token": TEST_CSRF})

    assert andere.get("/").status_code == 200


def test_uitloggen_zonder_sessie_is_een_gewone_redirect(client):
    with client.session_transaction() as sessie:
        sessie["csrf_token"] = TEST_CSRF

    antwoord = client.post("/logout", data={"csrf_token": TEST_CSRF})

    assert antwoord.status_code == 302 and antwoord.headers["Location"] == "/login"
