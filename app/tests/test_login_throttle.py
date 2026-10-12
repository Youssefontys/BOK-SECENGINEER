"""De wachtwoordstap van het inloggen: tellen, blokkeren en niets verraden.

Elke test beschrijft een misuse case als iets dat een machine controleert:
wachtwoorden raden, password spraying, accounts opsporen, de server met
Argon2 uitputten, het adres vervalsen.
"""

import json
import logging
import re
import secrets

import pytest
from werkzeug.middleware.proxy_fix import ProxyFix

import app as application
import ratelimit
from conftest import WACHTWOORD, post_login

FOUT = "dit-is-niet-het-wachtwoord"


def fouten(client, username, aantal, wachtwoord=FOUT, headers=None):
    return [post_login(client, username, wachtwoord, headers).status_code for _ in range(aantal)]


def melding(response):
    """De tekst van de foutmelding, zodat we antwoorden kunnen vergelijken."""
    gevonden = re.search(r'<p class="error">(.*?)</p>', response.get_data(as_text=True), re.S)
    return gevonden.group(1).strip() if gevonden else None


def verloop_alle_blokkades():
    with application.db() as conn, conn.cursor() as cur:
        cur.execute("UPDATE auth_throttle SET locked_until = now() - interval '1 second' WHERE locked_until IS NOT NULL")


def teller(sleutel):
    with application.db() as conn, conn.cursor() as cur:
        cur.execute("SELECT failures FROM auth_throttle WHERE key = %s", (sleutel,))
        rij = cur.fetchone()
    return rij[0] if rij else None


def ip_sleutel(ip="127.0.0.1"):
    return application.rate_key("login_ip", "ip", ip)


def pair_sleutel(naam, ip="127.0.0.1"):
    return application.rate_key("login_pair", "account-ip", f"{naam}|{ip}")


def test_vijf_foute_wachtwoorden_blokkeren_ook_het_juiste_wachtwoord(client, account):
    assert fouten(client, account["username"], 5) == [401] * 5

    geblokkeerd = post_login(client, account["username"], WACHTWOORD)

    assert geblokkeerd.status_code == 429
    assert int(geblokkeerd.headers["Retry-After"]) > 0
    assert "Te veel mislukte pogingen" in melding(geblokkeerd)
    assert "Location" not in geblokkeerd.headers, "tijdens een blokkade mag zelfs het juiste wachtwoord niet door"


def test_een_onbekende_gebruiker_gedraagt_zich_precies_als_een_bekende(client, account):
    """Een blokkade mag niet verraden of een account bestaat."""
    def reeks(naam):
        antwoorden = [post_login(client, naam, FOUT) for _ in range(5)]
        antwoorden.append(post_login(client, naam, WACHTWOORD))
        return [r.status_code for r in antwoorden], [melding(r) for r in antwoorden]

    bekend = reeks(account["username"])
    with application.db() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM auth_throttle")
    onbekend = reeks("bestaat_niet_" + secrets.token_hex(3))

    assert bekend == onbekend
    assert bekend[0] == [401] * 5 + [429]


def test_na_afloop_van_de_blokkade_kan_inloggen_weer(client, account):
    fouten(client, account["username"], 5)
    assert post_login(client, account["username"], WACHTWOORD).status_code == 429

    verloop_alle_blokkades()

    verder = post_login(client, account["username"], WACHTWOORD)
    assert verder.status_code == 302 and verder.headers["Location"] == "/login/2fa"


def test_herhaalde_blokkade_duurt_langer(client, account):
    fouten(client, account["username"], 5)
    eerste = int(post_login(client, account["username"], WACHTWOORD).headers["Retry-After"])
    verloop_alle_blokkades()
    fouten(client, account["username"], 5)
    tweede = int(post_login(client, account["username"], WACHTWOORD).headers["Retry-After"])
    assert tweede > eerste


def test_ip_limiet_geldt_over_gebruikersnamen_heen(client, account):
    """Password spraying: weinig pogingen per account, veel accounts."""
    uitkomst = [post_login(client, f"onbekend_{i}", FOUT).status_code for i in range(20)]
    assert uitkomst == [401] * 20

    # Zelfs een volledig geldige login vanaf dit adres wordt nu tegengehouden.
    assert post_login(client, account["username"], WACHTWOORD).status_code == 429


def test_een_blokkade_van_een_account_raakt_een_ander_account_niet(client, account):
    fouten(client, account["username"], 5)
    assert post_login(client, account["username"], WACHTWOORD).status_code == 429

    # Zelfde adres, ander account: alleen de combinatie was geblokkeerd, en de
    # IP-teller staat op 5 van de 20.
    with application.db() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO users (username, password_hash, totp_secret)"
            " VALUES (%s, %s, pgp_sym_encrypt(%s, %s)) RETURNING id",
            ("ander_" + secrets.token_hex(4), application.ph.hash(WACHTWOORD), "AAAAAAAA", application.get_encryption_key()),
        )
        ander_id = cur.fetchone()[0]
        cur.execute("SELECT username FROM users WHERE id = %s", (ander_id,))
        ander = cur.fetchone()[0]
    try:
        assert post_login(client, ander, WACHTWOORD).status_code == 302
    finally:
        with application.db() as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM users WHERE id = %s", (ander_id,))


def test_geslaagde_login_wist_de_accountteller_maar_niet_de_ip_teller(client, account):
    fouten(client, account["username"], 3)
    assert post_login(client, account["username"], WACHTWOORD).status_code == 302

    assert teller(pair_sleutel(account["username"])) is None
    # Anders zou een aanvaller met één eigen account zijn IP-teller steeds
    # kunnen terugzetten door tussendoor in te loggen.
    assert teller(ip_sleutel()) == 3


def test_te_lang_wachtwoord_gaat_niet_naar_argon2_maar_telt_wel(client, account, monkeypatch):
    aanroepen = []
    echt = application.password_matches
    monkeypatch.setattr(application, "password_matches", lambda h, p: aanroepen.append(1) or echt(h, p))

    antwoord = post_login(client, account["username"], "x" * (application.MAX_PASSWORD_LENGTH + 1))

    assert antwoord.status_code == 401
    assert aanroepen == []
    assert teller(ip_sleutel()) == 1


def test_ongeldige_gebruikersnaam_kost_geen_argon2_maar_telt_wel(client, account, monkeypatch):
    aanroepen = []
    echt = application.password_matches
    monkeypatch.setattr(application, "password_matches", lambda h, p: aanroepen.append(1) or echt(h, p))

    assert post_login(client, "ADMIN';--", FOUT).status_code == 401
    assert aanroepen == []
    assert teller(ip_sleutel()) == 1


def test_onbekende_gebruiker_kost_evenveel_argon2_als_een_bekende(client, account, monkeypatch):
    """Anders is een onbekende gebruikersnaam meetbaar sneller (timing)."""
    aanroepen = []
    echt = application.password_matches
    monkeypatch.setattr(application, "password_matches", lambda h, p: aanroepen.append(1) or echt(h, p))

    post_login(client, account["username"], FOUT)
    bekend = len(aanroepen)
    post_login(client, "onbekend_" + secrets.token_hex(3), FOUT)

    assert bekend == 1
    assert len(aanroepen) - bekend == 1


def test_x_forwarded_for_wordt_standaard_genegeerd(client, account):
    """Zonder vertrouwde proxy mag een aanvaller zijn adres niet zelf kiezen."""
    for i in range(5):
        status = post_login(client, account["username"], FOUT, {"X-Forwarded-For": f"198.51.100.{i}"}).status_code
        assert status == 401
    vervalst = post_login(client, account["username"], WACHTWOORD, {"X-Forwarded-For": "198.51.100.99"})
    assert vervalst.status_code == 429


def test_met_een_vertrouwde_proxy_telt_het_adres_dat_de_proxy_toevoegde(client, account, monkeypatch):
    monkeypatch.setattr(application.app, "wsgi_app", application.app.wsgi_app)  # zet het na de test terug
    application.apply_proxy_config(application.app, 1)
    assert isinstance(application.app.wsgi_app, ProxyFix)

    # Links staat wat de aanvaller zelf verzint, rechts wat de proxy toevoegde.
    for i in range(5):
        status = post_login(client, account["username"], FOUT, {"X-Forwarded-For": f"9.9.9.{i}, 203.0.113.7"}).status_code
        assert status == 401
    assert post_login(client, account["username"], WACHTWOORD, {"X-Forwarded-For": "9.9.9.200, 203.0.113.7"}).status_code == 429

    # Een ander echt adres heeft een eigen teller.
    ander_adres = post_login(client, account["username"], WACHTWOORD, {"X-Forwarded-For": "9.9.9.1, 203.0.113.8"})
    assert ander_adres.status_code == 302


def test_observe_modus_blokkeert_nooit_op_ip_maar_meldt_het_wel(client, account, monkeypatch, caplog):
    monkeypatch.setitem(ratelimit.POLICIES, "login_ip", ratelimit.IP_POLICIES["observe"]["login_ip"])
    caplog.set_level(logging.INFO)

    statussen = [post_login(client, f"onbekend_{i}", FOUT).status_code for i in range(25)]

    assert statussen == [401] * 25
    assert post_login(client, account["username"], WACHTWOORD).status_code == 302
    events = [json.loads(r.getMessage()) for r in caplog.records if r.name == application.app.logger.name]
    assert any(e["event"] == "threshold_crossed" and e["scope"] == "login_ip" for e in events)


def test_hackweek_modus_laat_een_klas_door_en_blokkeert_kort(client, account, monkeypatch):
    monkeypatch.setitem(ratelimit.POLICIES, "login_ip", ratelimit.IP_POLICIES["hackweek"]["login_ip"])

    # Vijfentwintig fouten van verschillende mensen zijn onder strict al een
    # blokkade (drempel 20), maar hier niet.
    assert [post_login(client, f"onbekend_{i}", FOUT).status_code for i in range(25)] == [401] * 25
    assert post_login(client, account["username"], WACHTWOORD).status_code == 302

    # Wordt de drempel toch gehaald, dan is de blokkade kort en vast.
    with application.db() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO auth_throttle (key, failures) VALUES (%s, 99) "
            "ON CONFLICT (key) DO UPDATE SET failures = 99",
            (ip_sleutel(),),
        )
    post_login(client, "nog_een_onbekende", FOUT)
    geblokkeerd = post_login(client, account["username"], WACHTWOORD)
    assert geblokkeerd.status_code == 429
    assert 0 < int(geblokkeerd.headers["Retry-After"]) <= 300


def test_de_accountlimiet_blijft_in_hackweek_modus_even_streng(client, account, monkeypatch):
    """Ruimere IP-limieten mogen de bescherming van het account zelf niet raken."""
    monkeypatch.setitem(ratelimit.POLICIES, "login_ip", ratelimit.IP_POLICIES["hackweek"]["login_ip"])

    assert fouten(client, account["username"], 5) == [401] * 5
    assert post_login(client, account["username"], WACHTWOORD).status_code == 429


def test_mislukte_login_wordt_gelogd_zonder_wachtwoord_en_zonder_loginjectie(client, account, caplog):
    caplog.set_level(logging.INFO)

    post_login(client, "kwaad\nvalse_logregel", "geheim-wachtwoord-123")
    post_login(client, account["username"], "geheim-wachtwoord-456")

    regels = [r.getMessage() for r in caplog.records if r.name == application.app.logger.name]
    assert regels, "er is niets gelogd"
    for regel in regels:
        assert "\n" not in regel
        assert "geheim-wachtwoord" not in regel
        assert json.loads(regel)["event"]

    events = [json.loads(r) for r in regels]
    ongeldig = [e for e in events if e["event"] == "login_failed" and e["username"] is None]
    echt = [e for e in events if e["event"] == "login_failed" and e["username"] == account["username"]]
    assert len(ongeldig) == 1 and len(echt) == 1


def test_blokkade_en_start_ervan_worden_als_waarschuwing_gelogd(client, account, caplog):
    caplog.set_level(logging.INFO)
    fouten(client, account["username"], 5)
    post_login(client, account["username"], WACHTWOORD)

    waarschuwingen = [json.loads(r.getMessage()) for r in caplog.records
                      if r.levelno == logging.WARNING and r.name == application.app.logger.name]
    namen = {w["event"] for w in waarschuwingen}
    assert {"lockout_started", "login_blocked"} <= namen
    assert any(w.get("scope") == "login_pair" for w in waarschuwingen if w["event"] == "lockout_started")


def test_vrijgesteld_demoaccount_wordt_niet_op_account_en_ip_geblokkeerd(client, monkeypatch):
    """Het demoaccount blijft bereikbaar voor een klasgenoot op hetzelfde IP, een ander account niet."""
    monkeypatch.setattr(application, "PAIR_EXEMPT_USERS", {"hackingweek"})
    demo = "HackingWeek"  # hoofdletters tellen niet mee
    gewoon = "gewoon_" + secrets.token_hex(4)

    assert set(fouten(client, demo, 8)) == {401}
    assert 429 in fouten(client, gewoon, 8)
