"""CI-probe: ciphertext opslaan en na een Vault-herstart weer ontsleutelen."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vault_crypto import VaultUnavailable, decrypt_note, encrypt_note  # noqa: E402

path = Path("/tmp/vault-restart-check.txt")
if sys.argv[1] == "save":
    path.write_text(encrypt_note("CI herstartcontrole"), encoding="utf-8")
else:
    try:
        if decrypt_note(path.read_text(encoding="utf-8")) != "CI herstartcontrole":
            sys.exit(1)
    except VaultUnavailable:
        sys.exit(1)
