"""Echte Vault/PostgreSQL-integratie; de Compose-stack moet draaien."""

import os
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import psycopg
import pytest

import app as application
from conftest import log_in_as
from vault_crypto import decrypt_note, encrypt_note


def test_vault_roundtrip_en_willekeurige_ciphertext():
    first = encrypt_note("Een gevoelige notitie")
    second = encrypt_note("Een gevoelige notitie")
    assert first != second
    assert decrypt_note(first) == decrypt_note(second) == "Een gevoelige notitie"


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
    response = client.post("/", data={"title": "Geheime titel", "body": "Geheime inhoud"})
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
    assert decrypt_note(first[0]) == "notitie van test_gebruiker_a"
    assert runner.invoke(args=["encrypt-notes"]).exit_code == 0
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn, conn.cursor() as cur:
        cur.execute("SELECT title, body, encrypted FROM notes WHERE id = %s", (note_id,))
        assert cur.fetchone() == first
