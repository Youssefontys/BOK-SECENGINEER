"""Autorisatietests.

Deze twee tests leggen misuse cases vast als uitvoerbare controle: een
gebruiker die de notities van een ander probeert te lezen of te
verwijderen. Zolang ze slagen is aantoonbaar dat de filter op user_id in
elke query staat en niet per ongeluk uit een query verdwijnt.
"""

import os

import psycopg

from conftest import log_in_as
from vault_crypto import decrypt_note


def test_profiel_vereist_volledige_login(client):
    with client.session_transaction() as session:
        session["pending_user_id"] = 1
    response = client.get("/account/profile")
    assert response.status_code == 302
    assert response.headers["Location"] == "/login"


def test_profiel_toont_alleen_de_ingelogde_gebruiker(client, twee_gebruikers):
    log_in_as(client, twee_gebruikers["test_gebruiker_b"])
    response = client.get("/account/profile")
    page = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "test_gebruiker_b" in page
    assert "test_gebruiker_a" not in page
    assert "password_hash" not in page and "totp_secret" not in page


def test_gebruiker_ziet_notities_van_een_ander_niet(client, twee_gebruikers):
    log_in_as(client, twee_gebruikers["test_gebruiker_b"])

    pagina = client.get("/").get_data(as_text=True)

    assert "notitie van test_gebruiker_b" in pagina, "eigen notitie hoort zichtbaar"
    assert "notitie van test_gebruiker_a" not in pagina, "notitie van een ander lekt"


def test_gebruiker_kan_notitie_van_een_ander_niet_verwijderen(client, twee_gebruikers):
    notitie_van_a = twee_gebruikers["test_gebruiker_a_notitie"]

    log_in_as(client, twee_gebruikers["test_gebruiker_b"])
    # B kent of gokt het id van de notitie van A en stuurt het verwijderverzoek.
    client.post(f"/notes/{notitie_van_a}/delete")

    with psycopg.connect(os.environ["DATABASE_URL"]) as conn, conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM notes WHERE id = %s", (notitie_van_a,))
        aantal = cur.fetchone()[0]

    assert aantal == 1, "de notitie van A is door B verwijderd"


def test_gebruiker_kan_zijn_eigen_notitie_wel_verwijderen(client, twee_gebruikers):
    """Tegenproef bij de test hierboven.

    Zonder deze test zou de vorige ook slagen als verwijderen helemaal niet
    werkt, of als de meting een verwijdering simpelweg niet opmerkt. Hier
    moet de telling juist naar nul gaan, en daarmee staat vast dat de vorige
    test echt iets controleert.
    """
    eigen_notitie = twee_gebruikers["test_gebruiker_b_notitie"]

    log_in_as(client, twee_gebruikers["test_gebruiker_b"])
    client.post(f"/notes/{eigen_notitie}/delete")

    with psycopg.connect(os.environ["DATABASE_URL"]) as conn, conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM notes WHERE id = %s", (eigen_notitie,))
        aantal = cur.fetchone()[0]

    assert aantal == 0, "eigen notitie kon niet verwijderd worden"


def test_gebruiker_kan_notitie_van_een_ander_niet_aanpassen(client, twee_gebruikers):
    note_id = twee_gebruikers["test_gebruiker_a_notitie"]
    log_in_as(client, twee_gebruikers["test_gebruiker_b"])
    assert client.get(f"/notes/{note_id}/edit").status_code == 404
    response = client.post(
        f"/notes/{note_id}/edit", data={"title": "gewijzigd", "body": "gewijzigd"}
    )
    assert response.status_code == 404
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn, conn.cursor() as cur:
        cur.execute("SELECT title, body FROM notes WHERE id = %s", (note_id,))
        assert cur.fetchone() == ("notitie van test_gebruiker_a", "inhoud")


def test_gebruiker_kan_zijn_eigen_notitie_aanpassen(client, twee_gebruikers):
    note_id = twee_gebruikers["test_gebruiker_b_notitie"]
    log_in_as(client, twee_gebruikers["test_gebruiker_b"])
    page = client.get(f"/notes/{note_id}/edit")
    assert page.status_code == 200
    assert "notitie van test_gebruiker_b" in page.get_data(as_text=True)
    response = client.post(
        f"/notes/{note_id}/edit", data={"title": "Nieuwe titel", "body": "Nieuwe inhoud"}
    )
    assert response.status_code == 302
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn, conn.cursor() as cur:
        cur.execute("SELECT title, body, encrypted FROM notes WHERE id = %s", (note_id,))
        title, body, encrypted = cur.fetchone()
        assert encrypted is True
        assert title.startswith("vault:v") and body.startswith("vault:v")
        assert (decrypt_note(title), decrypt_note(body)) == ("Nieuwe titel", "Nieuwe inhoud")
