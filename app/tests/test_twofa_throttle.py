"""De tweede factor: een zescijferige code is de zwakste schakel.

Met 10^6 mogelijke codes en drie tegelijk geldige (huidige, vorige en
volgende interval) is raden zonder limiet kansrijk. Deze tests leggen vast
dat het account na een paar foute codes dichtgaat, ook voor de juiste code,
ook voor een nieuwe sessie, en ook als de gokken tegelijk binnenkomen.
"""

from concurrent.futures import ThreadPoolExecutor
import json
import logging
import os
import time

import psycopg
import pyotp

import app as application
from conftest import WACHTWOORD, foute_code, post_2fa, post_login


def tot_de_tweede_factor(client, account):
    antwoord = post_login(client, account["username"], WACHTWOORD)
    assert antwoord.status_code == 302 and antwoord.headers["Location"] == "/login/2fa"


def juiste_code(account):
    return pyotp.TOTP(account["secret"]).now()


def verloop_alle_blokkades():
    with application.db() as conn, conn.cursor() as cur:
        cur.execute("UPDATE auth_throttle SET locked_until = now() - interval '1 second' WHERE locked_until IS NOT NULL")


def teller(sleutel):
    with application.db() as conn, conn.cursor() as cur:
        cur.execute("SELECT failures FROM auth_throttle WHERE key = %s", (sleutel,))
        rij = cur.fetchone()
    return rij[0] if rij else None


def test_vijf_foute_codes_blokkeren_ook_de_juiste_code(client, account):
    tot_de_tweede_factor(client, account)
    fout = foute_code(account["secret"])

    assert [post_2fa(client, fout).status_code for _ in range(5)] == [401] * 5

    geblokkeerd = post_2fa(client, juiste_code(account))
    assert geblokkeerd.status_code == 429
    assert int(geblokkeerd.headers["Retry-After"]) > 0
    assert "Te veel mislukte pogingen" in geblokkeerd.get_data(as_text=True)
    assert client.get("/").headers["Location"] == "/login", "er is niet ingelogd"


def test_een_nieuwe_sessie_ontloopt_de_blokkade_niet(client, account):
    """De aanvaller heeft het wachtwoord en logt gewoon opnieuw in."""
    tot_de_tweede_factor(client, account)
    fout = foute_code(account["secret"])
    for _ in range(5):
        post_2fa(client, fout)

    nieuwe_sessie = application.app.test_client()
    tot_de_tweede_factor(nieuwe_sessie, account)

    assert post_2fa(nieuwe_sessie, juiste_code(account)).status_code == 429


def test_na_afloop_van_de_blokkade_werkt_de_juiste_code_weer(client, account):
    tot_de_tweede_factor(client, account)
    fout = foute_code(account["secret"])
    for _ in range(5):
        post_2fa(client, fout)
    assert post_2fa(client, juiste_code(account)).status_code == 429

    verloop_alle_blokkades()

    verder = post_2fa(client, juiste_code(account))
    assert verder.status_code == 302 and verder.headers["Location"] == "/"
    assert client.get("/").status_code == 200


def test_geslaagde_tweede_factor_wist_de_accountteller_maar_niet_de_ip_teller(client, account):
    tot_de_tweede_factor(client, account)
    fout = foute_code(account["secret"])
    post_2fa(client, fout)
    post_2fa(client, fout)
    assert post_2fa(client, juiste_code(account)).status_code == 302

    assert teller(application.rate_key("twofa_account", "account", str(account["id"]))) is None
    assert teller(application.rate_key("twofa_ip", "ip", "127.0.0.1")) == 2


def test_ip_blokkade_in_de_tweede_stap_geldt_ook_voor_een_goede_code(client, account):
    tot_de_tweede_factor(client, account)
    with application.db() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO auth_throttle (key, locked_until) VALUES (%s, now() + interval '10 minutes')",
            (application.rate_key("twofa_ip", "ip", "127.0.0.1"),),
        )

    assert post_2fa(client, juiste_code(account)).status_code == 429


def test_parallelle_gokken_overschrijden_de_limiet_niet(account):
    """Acht gelijktijdige gokken van acht sessies: er mogen er precies vijf tellen.

    Zonder de tweede controle onder het rijslot passeren ze allemaal de
    eerste controle, omdat er op dat moment nog niets is geblokkeerd, en
    krijgt een aanvaller zoveel gokken als hij gelijktijdig kan versturen.
    """
    clients = [application.app.test_client() for _ in range(8)]
    for sessie in clients:
        tot_de_tweede_factor(sessie, account)
    fout = foute_code(account["secret"])

    with ThreadPoolExecutor(max_workers=8) as pool:
        statussen = list(pool.map(lambda sessie: post_2fa(sessie, fout).status_code, clients))

    assert sorted(statussen) == [401] * 5 + [429] * 3


def test_tweede_controle_onder_het_rijslot_ziet_een_blokkade_die_net_gezet_is(account):
    """Deterministische versie van de test hierboven.

    Of acht threads echt overlappen is toeval, dus die test kan slagen zonder
    dat de tweede controle iets doet. Hier dwingen we de volgorde af: de
    verzoeken passeren de eerste controle (nog niets geblokkeerd) en blijven
    dan hangen op het rijslot dat wij vasthouden. Pas daarna zetten wij de
    blokkade, zoals een eerder verzoek zou doen, en laten we los. Elk
    verzoek moet die blokkade nu onder het slot zien en met 429 antwoorden.
    Zonder de tweede controle zouden ze alle drie een code gaan controleren.
    """
    sessies = [application.app.test_client() for _ in range(3)]
    for sessie in sessies:
        tot_de_tweede_factor(sessie, account)
    fout = foute_code(account["secret"])
    account_sleutel = application.rate_key("twofa_account", "account", str(account["id"]))

    # Eén verbinding houdt het slot vast, een tweede (autocommit) kijkt toe.
    # Aparte verbinding en autocommit zijn nodig: Postgres cachet
    # pg_stat_activity binnen een transactie, dus wie binnen dezelfde
    # transactie blijft pollen ziet steeds dezelfde verouderde momentopname.
    houder = psycopg.connect(os.environ["DATABASE_URL"])
    kijker = psycopg.connect(os.environ["DATABASE_URL"], autocommit=True)
    pool = ThreadPoolExecutor(max_workers=3)
    try:
        houd = houder.cursor()
        houd.execute("SELECT 1 FROM users WHERE id = %s FOR UPDATE", (account["id"],))

        toekomst = [pool.submit(lambda s: post_2fa(s, fout).status_code, s) for s in sessies]

        # Wachten tot alle drie echt op het slot staan te wachten.
        wachtend = 0
        for _ in range(150):
            wachtend = kijker.execute(
                "SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock'"
            ).fetchone()[0]
            if wachtend >= 3:
                break
            time.sleep(0.1)
        assert wachtend >= 3, "de verzoeken bereikten het rijslot niet"

        houd.execute(
            "INSERT INTO auth_throttle (key, locked_until) VALUES (%s, now() + interval '10 minutes')"
            " ON CONFLICT (key) DO UPDATE SET locked_until = EXCLUDED.locked_until",
            (account_sleutel,),
        )
        houder.commit()
        statussen = [t.result(timeout=30) for t in toekomst]
    finally:
        # Het slot moet los vóór de pool wordt afgesloten. Anders wachten de
        # threads eindeloos op een slot dat alleen deze test kan loslaten,
        # en loopt een mislukte assert vast in plaats van te falen.
        houder.rollback()
        houder.close()
        kijker.close()
        pool.shutdown(wait=True)

    assert statussen == [429] * 3


def test_fouten_en_blokkade_worden_gelogd_zonder_de_code(client, account, caplog):
    caplog.set_level(logging.INFO)
    tot_de_tweede_factor(client, account)
    fout = foute_code(account["secret"])
    for _ in range(5):
        post_2fa(client, fout)
    post_2fa(client, juiste_code(account))

    regels = [r.getMessage() for r in caplog.records if r.name == application.app.logger.name]
    for regel in regels:
        assert fout not in regel and juiste_code(account) not in regel
    events = [json.loads(r) for r in regels]
    namen = [e["event"] for e in events]
    assert namen.count("twofa_failed") == 5
    assert "twofa_blocked" in namen
    assert any(e["event"] == "lockout_started" and e["scope"] == "twofa_account" for e in events)
