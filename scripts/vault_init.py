"""Lokale/CI-bootstrap: persistent Vault initialiseren, unsealen en token vernieuwen.

De root-token en unseal-key blijven in een afzonderlijk volume dat de app
niet kan lezen. Automatisch unsealen met lokaal bewaarde sleutels is alleen
voor ontwikkeling: productie vereist apart beheerde unseal/identity-secrets.
"""

import base64
import json
import os
from pathlib import Path
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


ADDRESS = os.environ.get("VAULT_ADDR", "http://vault:8200").rstrip("/")
STATE = Path("/bootstrap-state/init.json")
TOKEN = Path("/app-token/token")
POLICY = '''path "transit/encrypt/notes" { capabilities = ["update"] }
path "transit/decrypt/notes" { capabilities = ["update"] }
path "transit/encrypt/notes-bound" { capabilities = ["update"] }
path "transit/decrypt/notes-bound" { capabilities = ["update"] }
'''


def request(path, payload=None, token=None, method=None, timeout=10):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Vault-Token"] = token
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = Request(f"{ADDRESS}/v1/{path}", data=data, headers=headers, method=method)
    try:
        with urlopen(req, timeout=timeout) as response:
            raw = response.read()
            return json.loads(raw) if raw else {}
    except HTTPError as error:
        # Alleen het vaste API-pad en de status mogen in diagnostiek komen.
        error.vault_operation = path
        raise


def write_secret(path, content, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    # Maak het bestand meteen met de juiste rechten, ook voor de eerste write.
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.chmod(mode)
    temporary.replace(path)


def unseal():
    initialized = request("sys/init")["initialized"]
    if not initialized:
        # Een bestaand bootstrap-volume bij een lege Vault wijst op dataverlies.
        if STATE.exists():
            raise RuntimeError("Vault-data ontbreekt bij bestaande bootstrap-state")
        state = request("sys/init", {"secret_shares": 1, "secret_threshold": 1}, timeout=60)
        write_secret(STATE, json.dumps(state), 0o600)
    else:
        if not STATE.exists():
            raise RuntimeError("Bootstrap-state ontbreekt voor bestaande Vault")
        state = json.loads(STATE.read_text(encoding="utf-8"))
    if request("sys/seal-status")["sealed"]:
        request("sys/unseal", {"key": state["keys_base64"][0]})
    return state["root_token"]


def configure(root):
    mounts = request("sys/mounts", token=root)
    if "transit/" not in mounts["data"]:
        request("sys/mounts/transit", {"type": "transit"}, root)
    # Idempotent: bestaande key-versies blijven behouden.
    request("transit/keys/notes", {"type": "aes256-gcm96"}, root)
    # De sleutel waarmee nieuwe notities gebonden worden aan hun eigenaar. Een
    # `derived` sleutel kan niet achteraf op een bestaande sleutel gezet
    # worden; daarom een tweede sleutel en `rewrap-notes` voor de oude notities.
    request("transit/keys/notes-bound", {"type": "aes256-gcm96", "derived": True}, root)
    request("sys/policies/acl/notes-app", {"policy": POLICY}, root, method="PUT")


def renew_or_create_token(root):
    if TOKEN.exists():
        try:
            request("auth/token/renew", {"token": TOKEN.read_text().strip()}, root)
            return
        except HTTPError as error:
            if error.code not in (400, 403):
                raise
    result = request("auth/token/create", {
        "policies": ["notes-app"], "no_default_policy": True,
        "no_parent": True, "period": "1h", "display_name": "notes-app",
    }, root)
    # De non-root app kan lezen; alleen de bootstrap-service kan schrijven.
    write_secret(TOKEN, result["auth"]["client_token"], 0o644)


def health():
    token = TOKEN.read_text().strip()
    result = request("transit/encrypt/notes", {
        "plaintext": base64.b64encode(b"health").decode("ascii")
    }, token, timeout=2)
    return result["data"]["ciphertext"].startswith("vault:v")


def failure_reason(error):
    if isinstance(error, HTTPError):
        return f"HTTP {error.code} bij {getattr(error, 'vault_operation', 'Vault API')}"
    if isinstance(error, PermissionError):
        return "geen lees-/schrijfrechten op het bootstrap- of tokenvolume"
    if isinstance(error, FileNotFoundError):
        return "bootstrap- of tokenbestand ontbreekt"
    if isinstance(error, TimeoutError):
        return "Vault-aanvraag heeft de tijdslimiet overschreden"
    if isinstance(error, URLError):
        return "verbinding met Vault mislukt"
    return "lokale bestands- of verbindingsfout"


def main():
    configured = False
    retry_delay = 2
    previous_failure = None
    last_log = 0
    while True:
        stage = "initialiseren/unsealen"
        try:
            root = unseal()
            if not configured:
                stage = "Transit configureren"
                configure(root)
                configured = True
            stage = "applicatietoken vernieuwen"
            renew_or_create_token(root)
        except (HTTPError, URLError, TimeoutError, OSError) as error:
            failure = (stage, failure_reason(error))
            now = time.monotonic()
            if failure != previous_failure or now - last_log >= 60:
                print(f"Vault-stap '{stage}' mislukt: {failure[1]}."
                      " Opnieuw proberen met wachttijd tot 30 seconden.", flush=True)
                last_log = now
            previous_failure = failure
            time.sleep(retry_delay)
            retry_delay = min(retry_delay * 2, 30)
            continue
        if previous_failure is not None:
            print("Vault weer beschikbaar; applicatietoken vernieuwd.", flush=True)
        previous_failure = None
        retry_delay = 2
        time.sleep(30)


if __name__ == "__main__":
    if "--health" in sys.argv:
        try:
            sys.exit(0 if health() else 1)
        except (HTTPError, URLError, TimeoutError, OSError, ValueError, KeyError):
            sys.exit(1)
    main()
