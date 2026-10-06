"""Regressietest op de securityheaders.

Een control die niemand controleert verdwijnt vanzelf. Deze test faalt
zodra de Content-Security-Policy wordt afgezwakt of een header sneuvelt
bij een refactor.
"""


def test_csp_staat_en_staat_geen_inline_scripts_toe(client):
    headers = client.get("/login").headers
    csp = headers["Content-Security-Policy"]

    assert "script-src 'self'" in csp
    # Dit is het verschil tussen een CSP die beschermt en een die er alleen
    # maar staat: met unsafe-inline mag geinjecteerde markup alsnog draaien.
    assert "unsafe-inline" not in csp
    assert "frame-ancestors 'none'" in csp


def test_overige_securityheaders(client):
    headers = client.get("/login").headers

    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Referrer-Policy"] == "no-referrer"
