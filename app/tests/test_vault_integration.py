"""Echte Vault/PostgreSQL-integratie; de Compose-stack moet draaien."""

import os
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import psycopg
import pytest

import app as application
from conftest import TEST_CSRF, log_in_as
import base64

import vault_crypto
from vault_crypto import CiphertextRejected, decrypt_note, encrypt_note


def legacy_encrypt(text):
    """Zoals de app vroeger deed: oude sleutel `notes`, zonder context."""
    return vault_crypto.transit("encrypt", base64.b64encode(text.encode()).decode(), vault_crypto.LEGACY_KEY)


def test_vault_roundtrip_en_willekeurige_ciphertext():
    first = encrypt_note("Een gevoelige notitie", 1)
    second = encrypt_note("Een gevoelige notitie", 1)
    assert first != second
    assert decrypt_note(first, 1) == decrypt_note(second, 1) == "Een gevoelige notitie"


def test_ciphertext_van_een_ander_is_niet_te_ontsleutelen():
    """Dezelfde ciphertext met de context van een andere gebruiker wordt door Vault geweigerd."""
    ciphertext = encrypt_note("alleen voor gebruiker 1", 1)
    with pytest.raises(CiphertextRejected):
        decrypt_note(ciphertext, 2)


def test_een_verwisselde_notitie_wordt_niet_getoond(client, twee_gebruikers):
    """Een beheerder kopieert de ciphertext van A naar de rij van B: B ziet hem niet, de rest blijft werken."""
    a, b = twee_gebruikers["test_gebruiker_a"], twee_gebruikers["test_gebruiker_b"]
    b_note = twee_gebruikers["test_gebruiker_b_notitie"]
    geheim = encrypt_note("geheim van A", a)
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn, conn.cursor() as cur:
        cur.execute("UPDATE notes SET title = %s, body = %s, encrypted = TRUE, bound = TRUE WHERE id = %s",
                    (geheim, geheim, b_note))
    log_in_as(client, b)

    pagina = client.get("/")

    assert pagina.status_code == 200
    assert "geheim van A" not in pagina.get_data(as_text=True)
    assert "kan niet worden ontsleuteld" in pagina.get_data(as_text=True)
    assert client.get(f"/notes/{b_note}/edit").status_code == 404


def test_oude_notitie_zonder_context_blijft_leesbaar_tot_omzetting(client, twee_gebruikers):
    b = twee_gebruikers["test_gebruiker_b"]
    b_note = twee_gebruikers["test_gebruiker_b_notitie"]
    oud = legacy_encrypt("oude notitie")
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn, conn.cursor() as cur:
        cur.execute("UPDATE notes SET title = %s, body = %s, encrypted = TRUE, bound = FALSE WHERE id = %s",
                    (oud, oud, b_note))
    log_in_as(client, b)

    assert "oude notitie" in client.get("/").get_data(as_text=True)
    assert application.app.test_cli_runner().invoke(args=["encrypt-notes"]).exit_code == 0
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn, conn.cursor() as cur:
        cur.execute("SELECT bound FROM notes WHERE id = %s", (b_note,))
        assert cur.fetchone()[0] is True
    assert "oude notitie" in client.get("/").get_data(as_text=True)


@pytest.mark.parametrize("path,method,payload", [
    ("transit/keys/notes", "GET", None),
    ("transit/keys/notes/rotate", "POST", b'{}'),
    ("sys/mounts", "GET", None),
])
def test_app_token_heeft_geen_beheerrechten(path, method, payload):
    token = Path(os.environ["VAULT_TOKEN_FILE"]).read_text().strip()
    request = Request(f"{os.environ['VAULT_ADDR']}/v1/{path}",
        data=payload, method=method,
        headers={"X-Vault-Token": token, "Content-Type": "application/json"})
    with pytest.raises(HTTPError) as result:
        urlopen(request, timeout=5)
    assert result.value.code == 403


def test_nieuwe_notitie_staat_versleuteld_in_database(client, twee_gebruikers):
    user_id = twee_gebruikers["test_gebruiker_b"]
    log_in_as(client, user_id)
    response = client.post("/", data={"csrf_token": TEST_CSRF, "title": "Geheime titel", "body": "Geheime inhoud"})
    assert response.status_code == 302
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn, conn.cursor() as cur:
        cur.execute("SELECT title, body, encrypted FROM notes WHERE user_id = %s ORDER BY id DESC LIMIT 1", (user_id,))
        title, body, encrypted = cur.fetchone()
    assert encrypted is True
    assert title.startswith("vault:v") and body.startswith("vault:v")
    page = client.get("/").get_data(as_text=True)
    assert "Geheime titel" in page and "Geheime inhoud" in page
    assert "vault:v" not in page


def test_legacy_migratie_is_idempotent(client, twee_gebruikers):
    note_id = twee_gebruikers["test_gebruiker_a_notitie"]
    runner = application.app.test_cli_runner()
    assert runner.invoke(args=["encrypt-notes"]).exit_code == 0
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn, conn.cursor() as cur:
        cur.execute("SELECT title, body, encrypted FROM notes WHERE id = %s", (note_id,))
        first = cur.fetchone()
    assert first[2] is True
    assert decrypt_note(first[0], twee_gebruikers["test_gebruiker_a"]) == "notitie van test_gebruiker_a"
    assert runner.invoke(args=["encrypt-notes"]).exit_code == 0
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn, conn.cursor() as cur:
        cur.execute("SELECT title, body, encrypted FROM notes WHERE id = %s", (note_id,))
        assert cur.fetchone() == first
