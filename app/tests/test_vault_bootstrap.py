"""Bootstrap-diagnostiek: veilig loggen, herstel en begrensd retrygedrag."""

import importlib.util
from pathlib import Path
from urllib.error import HTTPError, URLError

import pytest


@pytest.fixture
def bootstrap():
    path = Path(__file__).resolve().parents[2] / "scripts" / "vault_init.py"
    if not path.exists():
        # CI zet de bron apart klaar: de app heeft geen bootstrap-volume.
        path = Path("/tmp/vault_init.py")
    spec = importlib.util.spec_from_file_location("vault_bootstrap_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_http_diagnostiek_bevat_geen_url_body_of_token(bootstrap, monkeypatch):
    def fail(*args, **kwargs):
        raise HTTPError("http://vault/?token=PRIVATE-TOKEN", 403, "PRIVATE-BODY", {}, None)
    monkeypatch.setattr(bootstrap, "urlopen", fail)
    with pytest.raises(HTTPError) as result:
        bootstrap.request("auth/token/create", {}, "ROOT-SECRET")
    reason = bootstrap.failure_reason(result.value)
    assert reason == "HTTP 403 bij auth/token/create"
    assert "PRIVATE" not in reason and "ROOT" not in reason


@pytest.mark.parametrize("error,expected", [
    (URLError("PRIVATE-HOST"), "verbinding met Vault mislukt"),
    (PermissionError("PRIVATE-FILE"), "geen lees-/schrijfrechten op het bootstrap- of tokenvolume"),
    (TimeoutError("PRIVATE-CONTENT"), "Vault-aanvraag heeft de tijdslimiet overschreden"),
])
def test_oorzaken_worden_zonder_gevoelige_details_getoond(bootstrap, error, expected):
    assert bootstrap.failure_reason(error) == expected


def test_retry_vertraagt_en_logt_herhaalde_fout_niet_steeds(bootstrap, monkeypatch, capsys):
    class StopLoop(BaseException):
        pass
    attempts = 0
    waits = []

    def unseal():
        nonlocal attempts
        attempts += 1
        if attempts <= 3:
            raise URLError("PRIVATE-HOST")
        return "ROOT-SECRET"

    def sleep(delay):
        waits.append(delay)
        if delay == 30:
            raise StopLoop()

    monkeypatch.setattr(bootstrap, "unseal", unseal)
    monkeypatch.setattr(bootstrap, "configure", lambda root: None)
    monkeypatch.setattr(bootstrap, "renew_or_create_token", lambda root: None)
    monkeypatch.setattr(bootstrap.time, "sleep", sleep)
    monkeypatch.setattr(bootstrap.time, "monotonic", lambda: 10)
    with pytest.raises(StopLoop):
        bootstrap.main()
    assert waits == [2, 4, 8, 30]
    output = capsys.readouterr().out
    assert output.count("Vault-stap") == 1
    assert "Vault weer beschikbaar" in output
    assert "ROOT-SECRET" not in output and "PRIVATE-HOST" not in output
