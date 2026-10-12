"""CSRF: elke POST heeft een token, en elk formulier dat post bevat er een.

Een cross-site formulier kan een ingelogde gebruiker een verzoek laten doen
dat hij niet bedoelde. SameSite=Lax houdt dat in moderne browsers meestal
tegen, maar dat is dan de enige laag. Het token is de tweede.
"""

import os
import re

import psycopg
import pytest

import app as application
from conftest import TEST_CSRF, log_in_as

FORMULIER = re.compile(r'<form\b[^>]*\bmethod="post"[^>]*>(.*?)</form>', re.S)


def tel(query, params=()):
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn, conn.cursor() as cur:
        cur.execute(query, params)
        return cur.fetchone()[0]


@pytest.fixture
def ingelogd(client, twee_gebruikers):
    log_in_as(client, twee_gebruikers["test_gebruiker_b"])
    return {"user": twee_gebruikers["test_gebruiker_b"], "note": twee_gebruikers["test_gebruiker_b_notitie"]}


# (naam, pad, formulierdata, controle dat er niets is veranderd)
def routes(note):
    return [
        ("aanmaken", "/", {"title": "nieuw", "body": "nieuw"}),
        ("aanpassen", f"/notes/{note}/edit", {"title": "gewijzigd", "body": "gewijzigd"}),
        ("verwijderen", f"/notes/{note}/delete", {}),
        ("uitloggen", "/logout", {}),
    ]


@pytest.mark.parametrize("token", [None, "", "een-ander-token"])
def test_elke_muterende_route_weigert_zonder_geldig_token_en_verandert_niets(client, ingelogd, token):
    notities_voor = tel("SELECT count(*) FROM notes WHERE user_id = %s", (ingelogd["user"],))
    titel_voor = tel("SELECT title FROM notes WHERE id = %s", (ingelogd["note"],))

    for naam, pad, data in routes(ingelogd["note"]):
        formulier = dict(data)
        if token is not None:
            formulier["csrf_token"] = token
        assert client.post(pad, data=formulier).status_code == 400, naam

    assert tel("SELECT count(*) FROM notes WHERE user_id = %s", (ingelogd["user"],)) == notities_voor
    assert tel("SELECT title FROM notes WHERE id = %s", (ingelogd["note"],)) == titel_voor
    assert client.get("/").status_code == 200, "de sessie is door een zonder-token-uitlog niet verbroken"


def test_met_een_geldig_token_werkt_elke_route(client, ingelogd):
    for naam, pad, data in routes(ingelogd["note"]):
        antwoord = client.post(pad, data={"csrf_token": TEST_CSRF, **data})
        assert antwoord.status_code == 302, naam
        if naam == "uitloggen":
            break  # na uitloggen is de sessie weg, dus het token ook
        # Opnieuw inloggen is niet nodig: de andere routes komen vóór uitloggen.


def test_een_post_naar_een_onbestaand_pad_is_een_404_en_geen_400(client):
    assert client.post("/bestaat-niet").status_code == 404


@pytest.mark.parametrize("pad,minimum", [
    ("/login", 1), ("/register", 1), ("/recover", 1),
    ("/", 3),                     # aanmaken, verwijderen, uitloggen
    ("/notes/{note}/edit", 1),    # alleen aanpassen; deze pagina heeft geen accountmenu
    ("/account/profile", 1),      # uitloggen
    ("/account/recovery-code", 2),
])
def test_elk_formulier_dat_post_bevat_een_csrf_token(client, ingelogd, pad, minimum):
    """Faalt zodra iemand een POST-formulier toevoegt zonder token.

    De ondergrens zorgt dat de test niet leeg slaagt als een pagina geen
    formulieren meer zou tonen.
    """
    pagina = client.get(pad.format(note=ingelogd["note"])).get_data(as_text=True)
    formulieren = FORMULIER.findall(pagina)

    assert len(formulieren) >= minimum, f"{pad}: verwacht minstens {minimum} formulieren"
    for formulier in formulieren:
        assert 'name="csrf_token"' in formulier, f"{pad}: formulier zonder token"
