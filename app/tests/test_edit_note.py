"""Bewerkroute: sessie, validatie, escaping en verdwijnen tijdens bewerken.

Deze tests gebruiken een database-double; de eigendomscontrole wordt ook
met echte PostgreSQL-rijen getest in test_autorisatie.py.
"""

from unittest.mock import MagicMock

import pytest

import app as application
from conftest import log_in_as


@pytest.fixture
def cursor(monkeypatch):
    connection = MagicMock()
    cursor = connection.__enter__.return_value.cursor.return_value.__enter__.return_value
    monkeypatch.setattr(application, "db", lambda: connection)
    return cursor


@pytest.mark.parametrize("method", ["get", "post"])
@pytest.mark.parametrize("pending", [False, True])
def test_bewerken_vereist_volledige_login(client, cursor, method, pending):
    if pending:
        with client.session_transaction() as session:
            session["pending_user_id"] = 7
    response = getattr(client, method)("/notes/12/edit")
    assert response.status_code == 302
    assert response.headers["Location"] == "/login"
    cursor.execute.assert_not_called()


@pytest.mark.parametrize("title,body", [
    ("", "inhoud"), ("x" * 121, "inhoud"), ("titel", ""),
    ("titel", "x" * 4001), ("a\nb", "inhoud"), ("titel", "a\x00b"),
])
def test_ongeldige_invoer_wordt_niet_opgeslagen(client, cursor, title, body):
    log_in_as(client, 7)
    cursor.fetchone.return_value = ("Oud", "Bestaande inhoud")
    response = client.post("/notes/12/edit", data={"title": title, "body": body})
    assert response.status_code == 400
    assert cursor.execute.call_count == 1


def test_bewerkformulier_escapet_inhoud_en_behoudt_invoer_bij_fout(client, cursor):
    log_in_as(client, 7)
    cursor.fetchone.return_value = ('"><script>alert(1)</script>', "</textarea><script>x</script>")
    page = client.get("/notes/12/edit").get_data(as_text=True)
    assert "<script>" not in page
    assert "&lt;script&gt;" in page
    response = client.post("/notes/12/edit", data={"title": "", "body": "Bewaar mijn tekst"})
    assert "Bewaar mijn tekst" in response.get_data(as_text=True)


def test_verdwenen_notitie_tijdens_opslaan_geeft_404(client, cursor):
    log_in_as(client, 7)
    cursor.fetchone.side_effect = [("Oud", "Inhoud"), None]
    response = client.post("/notes/12/edit", data={"title": "Nieuw", "body": "Inhoud"})
    assert response.status_code == 404


def test_geldige_wijziging_slaat_op_en_keert_terug(client, cursor):
    log_in_as(client, 7)
    cursor.fetchone.side_effect = [("Oud", "Inhoud"), (12,)]
    response = client.post(
        "/notes/12/edit", data={"title": " Nieuw ", "body": " Nieuwe inhoud "}
    )
    assert response.status_code == 302
    assert response.headers["Location"] == "/"
    assert cursor.execute.call_args.args[1] == ("Nieuw", "Nieuwe inhoud", 12, 7)
