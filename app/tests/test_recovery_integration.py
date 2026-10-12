"""Echte database: eenmaligheid, races, sessierevocatie en gedeelde limieten."""

from concurrent.futures import ThreadPoolExecutor
import os
import re
import secrets

import psycopg
import pyotp
import pytest

import app as application
from conftest import log_in_as
from test_recovery import form_token


PASSWORD = "origineel-veilig-wachtwoord"
NEW_PASSWORD = "nieuw-veilig-wachtwoord"


@pytest.fixture
def person():
    username = "recover_" + secrets.token_hex(6)
    code, hashed = application.generate_recovery_code()
    secret = pyotp.random_base32()
    with application.db() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO users (username, password_hash, totp_secret, recovery_code_hash)"
            " VALUES (%s, %s, pgp_sym_encrypt(%s, %s), %s) RETURNING id",
            (username, application.ph.hash(PASSWORD), secret, application.get_encryption_key(), hashed),
        )
        user_id = cur.fetchone()[0]
        keys = [application.rate_key("recover_account", "account", username),
                application.rate_key("recover_ip", "ip", "127.0.0.1"),
                application.rate_key("issue_recovery_account", "account", str(user_id))]
        cur.execute("DELETE FROM auth_throttle WHERE key = ANY(%s)", (keys,))
    yield {"username": username, "id": user_id, "code": code, "secret": secret}
    with application.db() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
        cur.execute("DELETE FROM auth_throttle WHERE key = ANY(%s)", (keys,))


def reset_data(client, person):
    return {"csrf_token": form_token(client, "/recover"), "username": person["username"],
            "recovery_code": person["code"], "code": pyotp.TOTP(person["secret"]).now(),
            "password": NEW_PASSWORD, "password_confirm": NEW_PASSWORD}


def test_reset_verbruikt_code_vervangt_wachtwoord_en_weigert_oude_sessies(client, person):
    old_session = application.app.test_client()
    log_in_as(old_session, person["id"])
    assert old_session.get("/").status_code == 200
    response = client.post("/recover", data=reset_data(client, person), follow_redirects=True)
    assert response.status_code == 200
    assert response.request.path == "/login"
    assert response.history[0].status_code == 303
    assert "Wachtwoordherstel gelukt" in response.get_data(as_text=True)
    with application.db() as conn, conn.cursor() as cur:
        cur.execute("SELECT password_hash, recovery_code_hash, auth_version FROM users WHERE id = %s", (person["id"],))
        stored, recovery, version = cur.fetchone()
    assert application.password_matches(stored, NEW_PASSWORD)
    assert not application.password_matches(stored, PASSWORD)
    assert recovery is None and version == 1
    assert old_session.get("/").headers["Location"] == "/login"
    assert client.post("/recover", data=reset_data(client, person)).status_code == 401


def test_gelijktijdige_resets_kunnen_code_maar_een_keer_gebruiken(person):
    clients = [application.app.test_client(), application.app.test_client()]
    requests = [reset_data(client, person) for client in clients]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda pair: pair[0].post("/recover", data=pair[1]).status_code,
                                zip(clients, requests)))
    assert sorted(results) == [303, 401]
    with application.db() as conn, conn.cursor() as cur:
        cur.execute("SELECT auth_version FROM users WHERE id = %s", (person["id"],))
        assert cur.fetchone()[0] == 1


def test_vijf_pogingen_per_account_en_window_reset(client, person):
    for _ in range(5):
        data = reset_data(client, person)
        data["recovery_code"] = "onjuist"
        assert client.post("/recover", data=data).status_code == 401
    assert client.post("/recover", data=reset_data(client, person)).status_code == 429
    with application.db() as conn, conn.cursor() as cur:
        cur.execute("UPDATE auth_throttle SET locked_until = now() - interval '1 second' WHERE key = %s",
                    (application.rate_key("recover_account", "account", person["username"]),))
    assert client.post("/recover", data=reset_data(client, person)).status_code == 303


def test_ip_limiet_geldt_ook_bij_andere_gebruikersnamen(client, person):
    with application.db() as conn, conn.cursor() as cur:
        cur.execute("INSERT INTO auth_throttle (key, failures, locked_until) VALUES (%s, 0, now() + interval '10 minutes')",
                    (application.rate_key("recover_ip", "ip", "127.0.0.1"),))
    data = reset_data(client, person)
    data["username"] = "andere_gebruikersnaam"
    assert client.post("/recover", data=data).status_code == 429


def test_herstelcode_aanmaken_vervangt_oude_code_en_is_niet_opnieuw_zichtbaar(client, person):
    log_in_as(client, person["id"])
    token = form_token(client, "/account/recovery-code")
    response = client.post("/account/recovery-code", data={"csrf_token": token,
        "password": PASSWORD, "code": pyotp.TOTP(person["secret"]).now()})
    assert response.status_code == 200
    code = re.search(r'id="recovery-code" class="recovery-code">([^<]+)', response.get_data(as_text=True)).group(1)
    assert code != person["code"]
    with application.db() as conn, conn.cursor() as cur:
        cur.execute("SELECT recovery_code_hash FROM users WHERE id = %s", (person["id"],))
        hashed = cur.fetchone()[0]
    assert application.password_matches(hashed, application.normalize_recovery_code(code))
    assert not application.password_matches(hashed, application.normalize_recovery_code(person["code"]))
    assert code not in client.get("/account/recovery-code").get_data(as_text=True)
    assert response.headers["Cache-Control"] == "no-store"


def test_gestolen_herstelcode_zonder_correcte_totp_verandert_niets(client, person):
    data = reset_data(client, person)
    valid = pyotp.TOTP(person["secret"])
    current = int(application.time.time()) // 30
    acceptable = {valid.at(step * 30) for step in (current - 1, current, current + 1)}
    data["code"] = next(f"{candidate:06d}" for candidate in range(10) if f"{candidate:06d}" not in acceptable)
    assert client.post("/recover", data=data).status_code == 401
    with application.db() as conn, conn.cursor() as cur:
        cur.execute("SELECT password_hash, recovery_code_hash FROM users WHERE id = %s", (person["id"],))
        password, recovery = cur.fetchone()
    assert application.password_matches(password, PASSWORD)
    assert application.password_matches(recovery, application.normalize_recovery_code(person["code"]))


def test_login_werkt_na_reset_met_nieuwe_totp_en_oude_login_is_ongeldig(client, person):
    pending = application.app.test_client()
    token = form_token(pending, "/login")
    assert pending.post("/login", data={"csrf_token": token, "username": person["username"], "password": PASSWORD}).status_code == 302
    assert client.post("/recover", data=reset_data(client, person)).status_code == 303
    token = form_token(pending, "/login/2fa")
    assert pending.post("/login/2fa", data={"csrf_token": token, "code": pyotp.TOTP(person["secret"]).now()}).headers["Location"] == "/login"
    token = form_token(client, "/login")
    assert client.post("/login", data={"csrf_token": token, "username": person["username"], "password": NEW_PASSWORD}).headers["Location"] == "/login/2fa"
    token = form_token(client, "/login/2fa")
    current = int(application.time.time()) // 30
    fresh = pyotp.TOTP(person["secret"]).at((current + 1) * 30)
    assert client.post("/login/2fa", data={"csrf_token": token, "code": fresh}).headers["Location"] == "/"
    assert client.get("/").status_code == 200
