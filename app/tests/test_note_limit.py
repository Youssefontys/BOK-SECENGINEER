"""Maximaal MAX_NOTES_PER_USER notities per gebruiker.

Zonder grens kan één account de site vastzetten: elke notitie kost bij het
tonen twee Vault-aanroepen, en de app heeft twee workers die elk één verzoek
tegelijk afhandelen.
"""

from concurrent.futures import ThreadPoolExecutor
import os

import psycopg
import pytest

import app as application
from conftest import TEST_CSRF, RijSlot, log_in_as

GRENS = application.MAX_NOTES_PER_USER


def aantal(user_id):
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn, conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM notes WHERE user_id = %s", (user_id,))
        return cur.fetchone()[0]


def vul_aan_tot(user_id, totaal):
    """Voeg rechtstreeks rijen toe, zonder Vault: dat is snel en hier niet het onderwerp."""
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn, conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM notes WHERE user_id = %s", (user_id,))
        for i in range(totaal - cur.fetchone()[0]):
            cur.execute("INSERT INTO notes (user_id, title, body) VALUES (%s, %s, %s)", (user_id, f"vul {i}", "vul"))


def maak(client, titel="nieuw"):
    return client.post("/", data={"csrf_token": TEST_CSRF, "title": titel, "body": "inhoud"})


@pytest.fixture
def b(client, twee_gebruikers):
    gebruiker = twee_gebruikers["test_gebruiker_b"]
    log_in_as(client, gebruiker)
    return gebruiker


def test_de_laatste_toegestane_notitie_lukt_en_de_volgende_niet(client, b):
    vul_aan_tot(b, GRENS - 1)

    assert maak(client, "nummer laatste").status_code == 302
    assert aantal(b) == GRENS

    geweigerd = maak(client, "een te veel")
    assert geweigerd.status_code == 409
    assert str(GRENS) in geweigerd.get_data(as_text=True)
    assert aantal(b) == GRENS


def test_de_ingevoerde_tekst_blijft_behouden_bij_een_vol_account(client, b):
    vul_aan_tot(b, GRENS)

    pagina = maak(client, "bewaar deze titel").get_data(as_text=True)

    assert "bewaar deze titel" in pagina


def test_verwijderen_maakt_weer_ruimte(client, b, twee_gebruikers):
    vul_aan_tot(b, GRENS)
    assert maak(client).status_code == 409

    client.post(f"/notes/{twee_gebruikers['test_gebruiker_b_notitie']}/delete", data={"csrf_token": TEST_CSRF})

    assert maak(client).status_code == 302


def test_de_grens_geldt_per_gebruiker(client, twee_gebruikers):
    a, b = twee_gebruikers["test_gebruiker_a"], twee_gebruikers["test_gebruiker_b"]
    vul_aan_tot(a, GRENS)
    log_in_as(client, b)

    assert maak(client).status_code == 302


def test_het_aantal_wordt_getoond(client, b):
    pagina = client.get("/").get_data(as_text=True)
    assert f"van {GRENS} notities" in pagina


def test_aanmaken_telt_pas_nadat_het_rijslot_is_genomen(twee_gebruikers):
    """Deterministisch: bij 24 van 25 komen drie verzoeken tegelijk.

    De test houdt het rijslot op de gebruiker vast. De verzoeken versleutelen,
    en blijven dan op het slot hangen. Terwijl ze wachten voegt de test zelf de
    25e notitie toe en laat los. Elk verzoek moet nu tellen en "vol" zien.
    Telde de code vóór het slot (of nam hij het slot niet), dan zag hij nog
    24, en eindigde de gebruiker met meer dan 25.
    """
    b = twee_gebruikers["test_gebruiker_b"]
    vul_aan_tot(b, GRENS - 1)
    sessies = [application.app.test_client() for _ in range(3)]
    for sessie in sessies:
        log_in_as(sessie, b)

    slot = RijSlot(b)
    pool = ThreadPoolExecutor(max_workers=3)
    try:
        toekomst = [pool.submit(lambda s: maak(s).status_code, s) for s in sessies]
        slot.wacht_op(3)
        slot.cur.execute("INSERT INTO notes (user_id, title, body) VALUES (%s, 'door test', 'x')", (b,))
        slot.commit()
        statussen = [t.result(timeout=30) for t in toekomst]
    finally:
        slot.sluit()
        pool.shutdown(wait=True)

    assert statussen == [409] * 3
    assert aantal(b) == GRENS
