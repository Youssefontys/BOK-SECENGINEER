"""Vault Transit voor notitietekst; sleutelmaterialen verlaten Vault niet."""

import base64
import json
import os
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen


class VaultUnavailable(Exception):
    """Geen veilige encryptie/decryptie mogelijk; nooit terugvallen op plaintext."""


def transit(operation, value):
    try:
        address = os.environ["VAULT_ADDR"].rstrip("/")
        token_file = os.environ.get("VAULT_TOKEN_FILE")
        token = Path(token_file).read_text().strip() if token_file else os.environ["VAULT_TOKEN"]
        if not token:
            raise ValueError("Leeg Vault-token")
        payload = {"plaintext" if operation == "encrypt" else "ciphertext": value}
        request = Request(
            f"{address}/v1/transit/{operation}/notes",
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
    except (URLError, OSError, ValueError, KeyError, TypeError) as error:
        raise VaultUnavailable("Vault-bewerking mislukt") from error


def encrypt_note(text):
    encoded = base64.b64encode(text.encode("utf-8")).decode("ascii")
    ciphertext = transit("encrypt", encoded)
    if not ciphertext.startswith("vault:v"):
        raise VaultUnavailable("Ongeldige ciphertext")
    return ciphertext


def decrypt_note(ciphertext):
    try:
        return base64.b64decode(transit("decrypt", ciphertext), validate=True).decode("utf-8")
    except (ValueError, UnicodeError) as error:
        raise VaultUnavailable("Ongeldige ontsleutelde tekst") from error
