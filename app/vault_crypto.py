"""Vault Transit voor notitietekst; sleutelmaterialen verlaten Vault niet.

Twee sleutels:

- `notes-bound`: een afgeleide sleutel (`derived`). Bij elke aanroep gaat het
  gebruikers-id mee als `context`, en Vault leidt daar de eigenlijke sleutel
  uit af. Ciphertext van gebruiker A is daardoor met de context van gebruiker
  B niet te ontsleutelen. Wie in de database schrijft (een beheerder, een
  teruggezette backup) kan een notitie dus niet naar een andere rij kopieren
  om hem door de app te laten tonen.
- `notes`: de oorspronkelijke sleutel zonder context. Alleen nog om oude
  notities te lezen tot `rewrap-notes` ze heeft omgezet; nieuwe tekst gaat er
  nooit meer naartoe.
"""

import base64
import json
import os
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class VaultUnavailable(Exception):
    """Geen veilige encryptie/decryptie mogelijk; nooit terugvallen op plaintext."""


class CiphertextRejected(VaultUnavailable):
    """Vault weigert deze ciphertext met deze context: andere eigenaar of aangepast."""


BOUND_KEY = "notes-bound"
LEGACY_KEY = "notes"


def owner_context(user_id):
    return base64.b64encode(f"user:{int(user_id)}".encode("ascii")).decode("ascii")


def transit(operation, value, key=LEGACY_KEY, context=None):
    try:
        address = os.environ["VAULT_ADDR"].rstrip("/")
        token_file = os.environ.get("VAULT_TOKEN_FILE")
        token = Path(token_file).read_text().strip() if token_file else os.environ["VAULT_TOKEN"]
        if not token:
            raise ValueError("Leeg Vault-token")
        payload = {"plaintext" if operation == "encrypt" else "ciphertext": value}
        if context is not None:
            payload["context"] = context
        request = Request(
            f"{address}/v1/transit/{operation}/{key}",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-Vault-Token": token},
            method="POST",
        )
        with urlopen(request, timeout=5) as response:
            result = json.load(response)["data"]
        output = result["ciphertext" if operation == "encrypt" else "plaintext"]
        if not isinstance(output, str):
            raise ValueError("Ongeldig Vault-antwoord")
        return output
    except HTTPError as error:
        # 400 bij ontsleutelen: Vault bereikbaar, maar de authenticatie van de
        # ciphertext klopt niet. Dat is geen storing en geen reden voor een 503.
        if error.code == 400 and operation == "decrypt":
            raise CiphertextRejected("Vault weigert deze ciphertext") from error
        raise VaultUnavailable("Vault-bewerking mislukt") from error
    except (URLError, OSError, ValueError, KeyError, TypeError) as error:
        raise VaultUnavailable("Vault-bewerking mislukt") from error


def encrypt_note(text, user_id):
    """Altijd met de afgeleide sleutel, gebonden aan de eigenaar."""
    encoded = base64.b64encode(text.encode("utf-8")).decode("ascii")
    ciphertext = transit("encrypt", encoded, BOUND_KEY, owner_context(user_id))
    if not ciphertext.startswith("vault:v"):
        raise VaultUnavailable("Ongeldige ciphertext")
    return ciphertext


def decrypt_note(ciphertext, user_id):
    try:
        return base64.b64decode(
            transit("decrypt", ciphertext, BOUND_KEY, owner_context(user_id)), validate=True
        ).decode("utf-8")
    except (ValueError, UnicodeError) as error:
        raise VaultUnavailable("Ongeldige ontsleutelde tekst") from error


def decrypt_legacy_note(ciphertext):
    """Oude notities (sleutel zonder context). Alleen voor het omzetten en de overgang."""
    try:
        return base64.b64decode(transit("decrypt", ciphertext), validate=True).decode("utf-8")
    except (ValueError, UnicodeError) as error:
        raise VaultUnavailable("Ongeldige ontsleutelde tekst") from error
