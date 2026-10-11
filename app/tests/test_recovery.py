"""Herstel vereist alle bewijzen, valideert CSRF en verbruikt TOTP-codes."""

import re
from unittest.mock import MagicMock

from argon2 import PasswordHasher
import pyotp
import pytest

import app as application


def form_token(client, path):
    page = client.get(path).get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)


@pytest.fixture
def recovery(monkeypatch):
    fast_hasher = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1)
    monkeypatch.setattr(application, "ph", fast_hasher)
    display, stored_hash = application.generate_recovery_code()
    secret = pyotp.random_base32()
    conn = MagicMock()
    cursor = conn.__enter__.return_value.cursor.return_value.__enter__.return_value
    cursor.fetchone.return_value = (42, stored_hash, secret, None)
    monkeypatch.setattr(application, "db", lambda: conn)
    monkeypatch.setattr(application, "allow_recovery_attempt", lambda scope, account: True)
    return cursor, display, secret


def payload(client, recovery):
    cursor, display, secret = recovery
    return {"csrf_token": form_token(client, "/recover"), "username": "alice",
            "recovery_code": display, "code": pyotp.TOTP(secret).now(),
            "password": "nieuw-veilig-wachtwoord", "password_confirm": "nieuw-veilig-wachtwoord"}


def updates(cursor):
    return [call for call in cursor.execute.call_args_list if call.args[0].startswith("UPDATE")]


@pytest.mark.parametrize("field,value", [
    ("recovery_code", ""), ("recovery_code", "A" * 48),
    ("code", ""), ("code", "123"),
])
def test_ieder_ontbrekend_of_onjuist_bewijs_blokkeert_herstel(client, recovery, field, value):
    data = payload(client, recovery)
    data[field] = value
    assert client.post("/recover", data=data).status_code == 401
    assert not updates(recovery[0])


def test_gebruikersnaam_is_ook_verplicht(client, recovery):
    data = payload(client, recovery)
    data["username"] = "onbekend"
    recovery[0].fetchone.return_value = None
    response = client.post("/recover", data=data)
    assert response.status_code == 401
    assert "Herstelgegevens zijn onjuist, gebruikt of verlopen." in response.get_data(as_text=True)
    assert not updates(recovery[0])


@pytest.mark.parametrize("password,confirmation", [("kort", "kort"), ("x" * 1025, "x" * 1025),
    ("lang-genoeg-wachtwoord", "ander-wachtwoord")])
def test_ongeldig_nieuw_wachtwoord_verbruikt_geen_herstelcode(client, recovery, password, confirmation):
    data = payload(client, recovery)
    data.update(password=password, password_confirm=confirmation)
    assert client.post("/recover", data=data).status_code == 400
    assert not updates(recovery[0])


def test_succes_verbruikt_code_hash_wachtwoord_en_trekt_sessies_in(client, recovery):
    data = payload(client, recovery)
    response = client.post("/recover", data=data)
    assert response.status_code == 303 and response.headers["Location"] == "/login"
    update = updates(recovery[0])[0]
    assert "recovery_code_hash = NULL" in update.args[0]
    assert "auth_version = auth_version + 1" in update.args[0]
    assert application.password_matches(update.args[1][0], data["password"])
    assert data["recovery_code"] not in str(update)
    with client.session_transaction() as session:
        assert "user_id" not in session and "pending_user_id" not in session
        assert "recovery_code" not in session
    assert "Je wachtwoord is hersteld" in client.get("/login").get_data(as_text=True)


def test_herstelbevestiging_blijft_zichtbaar_na_redirect_en_refresh(client, recovery):
    response = client.post("/recover", data=payload(client, recovery), follow_redirects=True)
    assert response.status_code == 200
    assert response.request.path == "/login"
    assert response.history[0].status_code == 303
    assert "Wachtwoordherstel gelukt" in response.get_data(as_text=True)
    assert "Wachtwoordherstel gelukt" in client.get("/login").get_data(as_text=True)


@pytest.mark.parametrize("token", ["", "verkeerd", "\u00e9"])
def test_csrf_blokkeert_herstel_voordat_bewijzen_worden_verwerkt(client, recovery, token):
    data = payload(client, recovery)
    data["csrf_token"] = token
    assert client.post("/recover", data=data).status_code == 400
    recovery[0].execute.assert_not_called()


def test_poginglimiet_blokkeert_reset(client, recovery, monkeypatch):
    data = payload(client, recovery)
    monkeypatch.setattr(application, "allow_recovery_attempt", lambda *args: False)
    assert client.post("/recover", data=data).status_code == 429
    recovery[0].execute.assert_not_called()


def test_gebruikte_totp_is_geen_herstelbewijs(client, recovery):
    data = payload(client, recovery)
    old = recovery[0].fetchone.return_value
    recovery[0].fetchone.return_value = (*old[:3], int(application.time.time()) // 30)
    assert client.post("/recover", data=data).status_code == 401
    assert not updates(recovery[0])


def test_verbruikte_herstelcode_faalt_ook_met_geldige_totp(client, recovery):
    data = payload(client, recovery)
    recovery[0].fetchone.return_value = (42, None, recovery[2], None)
    assert client.post("/recover", data=data).status_code == 401
    assert not updates(recovery[0])


def test_registratie_toont_code_en_slaat_alleen_hash_op(client, recovery):
    response = client.post("/register", data={
        "csrf_token": form_token(client, "/register"), "username": "nieuwe_user",
        "password": "veilig-lang-wachtwoord"})
    assert response.status_code == 200
    page = response.get_data(as_text=True)
    code = re.search(r'id="recovery-code" class="recovery-code">([^<]+)', page).group(1)
    parameters = recovery[0].execute.call_args.args[1]
    assert code not in parameters
    assert application.password_matches(parameters[-1], application.normalize_recovery_code(code))
    assert response.headers["Cache-Control"] == "no-store"
    with client.session_transaction() as session:
        assert code not in str(dict(session))


def test_verouderde_sessie_wordt_geweigerd(client, monkeypatch):
    monkeypatch.setattr(application, "is_session_current", lambda user_id, version: version == 1)
    with client.session_transaction() as session:
        session["user_id"] = 42
        session["auth_version"] = 0
    response = client.get("/")
    assert response.status_code == 302 and response.headers["Location"] == "/login"
    with client.session_transaction() as session:
        assert "user_id" not in session


def test_pending_login_van_voor_reset_wordt_geweigerd(client, recovery):
    with client.session_transaction() as session:
        session["pending_user_id"] = 42
        session["pending_auth_version"] = 0
        session["pending_since"] = application.time.time()
    recovery[0].fetchone.return_value = (recovery[2], 1, None)
    token = form_token(client, "/login/2fa")
    response = client.post("/login/2fa", data={"csrf_token": token, "code": pyotp.TOTP(recovery[2]).now()})
    assert response.status_code == 302 and response.headers["Location"] == "/login"
    with client.session_transaction() as session:
        assert "user_id" not in session


def test_totp_window_en_replay(monkeypatch):
    monkeypatch.setattr(application.time, "time", lambda: 1_800_000_000)
    secret = pyotp.random_base32()
    current = 1_800_000_000 // 30
    for step in (current - 1, current, current + 1):
        code = pyotp.TOTP(secret).at(step * 30)
        assert application.matching_totp_step(secret, code) == step
        assert application.matching_totp_step(secret, code, step) is None
    assert application.matching_totp_step(secret, pyotp.TOTP(secret).at((current - 2) * 30)) is None
