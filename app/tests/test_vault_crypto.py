"""Transit-request, UTF-8, tokenvernieuwing en veilig falen zonder echte Vault."""

import base64
import io
import json
from urllib.error import HTTPError, URLError

import pytest

import vault_crypto


@pytest.fixture
def vault(monkeypatch, tmp_path):
    token = tmp_path / "token"
    token.write_text("limited-token")
    monkeypatch.setenv("VAULT_ADDR", "http://vault:8200")
    monkeypatch.setenv("VAULT_TOKEN_FILE", str(token))
    return token


def test_encryptie_stuurt_utf8_en_beperkt_token(vault, monkeypatch):
    def respond(request, timeout):
        assert request.full_url == "http://vault:8200/v1/transit/encrypt/notes-bound"
        assert request.get_header("X-vault-token") == "limited-token"
        payload = json.loads(request.data)
        assert base64.b64decode(payload["plaintext"]).decode() == "Notitie: caf\u00e9"
        assert payload["context"] == base64.b64encode(b"user:7").decode()
        assert timeout == 5
        return io.BytesIO(b'{"data":{"ciphertext":"vault:v1:ciphertext"}}')

    monkeypatch.setattr(vault_crypto, "urlopen", respond)
    assert vault_crypto.encrypt_note("Notitie: caf\u00e9", 7) == "vault:v1:ciphertext"


def test_decryptie_en_tokenbestand_worden_opnieuw_gelezen(vault, monkeypatch):
    vault.write_text("renewed-token")

    def respond(request, timeout):
        assert request.get_header("X-vault-token") == "renewed-token"
        assert request.full_url.endswith("/transit/decrypt/notes-bound")
        assert json.loads(request.data) == {"ciphertext": "vault:v2:ciphertext", "context": base64.b64encode(b"user:7").decode()}
        return io.BytesIO(json.dumps({"data": {
            "plaintext": base64.b64encode("caf\u00e9".encode()).decode()
        }}).encode())

    monkeypatch.setattr(vault_crypto, "urlopen", respond)
    assert vault_crypto.decrypt_note("vault:v2:ciphertext", 7) == "caf\u00e9"


@pytest.mark.parametrize("error", [URLError("connection refused"),
    HTTPError("http://vault", 403, "denied", {}, None), TimeoutError("timeout")])
def test_netwerk_of_authfout_is_geen_plaintext_fallback(vault, monkeypatch, error):
    def fail(*args, **kwargs):
        raise error
    monkeypatch.setattr(vault_crypto, "urlopen", fail)
    with pytest.raises(vault_crypto.VaultUnavailable):
        vault_crypto.encrypt_note("Geheime tekst", 7)


@pytest.mark.parametrize("response", [b'{}', b'{"data":{"ciphertext":"plaintext"}}',
    b'{"data":{"ciphertext":null}}', b'not json'])
def test_ongeldig_encryptieantwoord_faalt(vault, monkeypatch, response):
    monkeypatch.setattr(vault_crypto, "urlopen", lambda *a, **kw: io.BytesIO(response))
    with pytest.raises(vault_crypto.VaultUnavailable):
        vault_crypto.encrypt_note("Geheime tekst", 7)


def test_ongeldige_base64_faalt(vault, monkeypatch):
    monkeypatch.setattr(vault_crypto, "urlopen",
        lambda *a, **kw: io.BytesIO(b'{"data":{"plaintext":"!invalid!"}}'))
    with pytest.raises(vault_crypto.VaultUnavailable):
        vault_crypto.decrypt_note("vault:v1:ciphertext", 7)


def test_vault_weigering_van_de_ciphertext_is_geen_storing(vault, monkeypatch):
    """Vault antwoordt 400 als de ciphertext bij een andere eigenaar hoort: dat is geen 503-situatie."""
    def reject(*args, **kwargs):
        raise HTTPError("http://vault", 400, "bad request", {}, None)
    monkeypatch.setattr(vault_crypto, "urlopen", reject)
    with pytest.raises(vault_crypto.CiphertextRejected):
        vault_crypto.decrypt_note("vault:v1:ciphertext", 7)


def test_andere_httpfouten_blijven_een_storing(vault, monkeypatch):
    def denied(*args, **kwargs):
        raise HTTPError("http://vault", 403, "denied", {}, None)
    monkeypatch.setattr(vault_crypto, "urlopen", denied)
    with pytest.raises(vault_crypto.VaultUnavailable) as caught:
        vault_crypto.decrypt_note("vault:v1:ciphertext", 7)
    assert not isinstance(caught.value, vault_crypto.CiphertextRejected)
