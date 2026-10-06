"""
Notitie-app, eerste concept.

Het kleinste werkende geheel waarop de BoK-onderwerpen authentication,
secure password storage, secure coding en database security aantoonbaar
zijn. Bewust nog niet compleet: zie de lijst onderaan dit bestand.
"""

import base64
import io
import os
import re
import unicodedata

import psycopg
import pyotp
import qrcode
import qrcode.image.svg
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerificationError
from flask import Flask, redirect, render_template, request, session, url_for

app = Flask(__name__)

# Sleutel waarmee sessiecookies worden ondertekend. Uit de omgeving, nooit
# uit de code: anders staat hij in git en kan iedereen die de repo leest
# sessies namaken.
app.secret_key = os.environ["FLASK_SECRET_KEY"]

app.config.update(
    # Cookie niet leesbaar vanuit JavaScript, beperkt de impact van XSS.
    SESSION_COOKIE_HTTPONLY=True,
    # Cookie alleen over HTTPS. Lokaal draai je via http, zet dan
    # COOKIE_SECURE=false in je omgeving, in Azure blijft dit true.
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "true").lower() == "true",
    # Beperkt dat de cookie meegaat bij cross-site requests (CSRF).
    SESSION_COOKIE_SAMESITE="Lax",
)

DATABASE_URL = os.environ["DATABASE_URL"]

# Argon2id met de defaults van argon2-cffi. Argon2id is de eerste keuze in
# de OWASP Password Storage Cheat Sheet; de salt wordt per wachtwoord
# automatisch gegenereerd en zit in de resulterende hashstring.
ph = PasswordHasher()

USERNAME_PATTERN = re.compile(r"[a-z0-9_]{3,32}")
MAX_TITLE = 120
MAX_BODY = 4000


def db():
    """Nieuwe databaseverbinding. Nog geen connection pooling in dit concept."""
    return psycopg.connect(DATABASE_URL)


def get_encryption_key() -> str:
    """De sleutel voor de kolomencryptie van users.totp_secret.

    Nu uit de omgeving, later uit Key Vault. Dit is bewust de enige plek in
    de applicatie waar de herkomst van de sleutel staat: die overstap is
    dan een wijziging in deze functie en nergens anders. Blijft de
    sleutelwaarde daarbij gelijk, dan hoeft bestaande data niet opnieuw
    versleuteld te worden.

    Bekende zwakte van deze pgcrypto-aanpak, en precies het punt van de
    vergelijking in het BoK-rapport: de sleutel gaat als queryparameter
    naar de database en is daardoor zichtbaar in pg_stat_activity en in
    eventuele querylogs. Bij encryptie aan de applicatiezijde ziet de
    database de sleutel nooit.
    """
    return os.environ["DB_ENCRYPTION_KEY"]


@app.after_request
def security_headers(response):
    """Securityheaders op elk antwoord.

    De Content-Security-Policy is de tweede verdedigingslaag onder de
    HTML-escaping van Jinja: mocht er ooit toch ongeescapete uitvoer in een
    pagina belanden, dan mag de browser die nog steeds niet uitvoeren.

    script-src stond eerst op 'none' omdat er geen JavaScript was. Met de
    decoratieve animatie is dat 'self' geworden. Dat is bewust geen echte
    verzwakking: zonder 'unsafe-inline' mag alleen een script uit deze
    applicatie zelf draaien, dus geinjecteerde markup voert nog steeds
    niets uit. Dat onderscheid, 'self' versus 'unsafe-inline', is waar het
    bij een CSP om gaat.
    """
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        # data: is nodig voor de QR-code, die als data-URI wordt meegegeven.
        "img-src 'self' data:; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'none'; "
        "object-src 'none'"
    )
    # Browser mag het content-type niet zelf gaan raden.
    response.headers["X-Content-Type-Options"] = "nosniff"
    # Geen URL's van deze app meesturen naar externe sites.
    response.headers["Referrer-Policy"] = "no-referrer"
    # HSTS hoort hier nog niet: dat zet je pas aan achter HTTPS in Azure,
    # anders maak je localhost over http onbruikbaar.
    return response


def has_disallowed_control_chars(text: str, allow_newlines: bool = False) -> bool:
    """True als er controletekens in de tekst zitten.

    Controletekens hebben in een notitie niets te zoeken en kunnen bij
    verwerking of in logregels voor verrassingen zorgen (log injection).
    Regeleindes en tabs zijn in een notitietekst wel legitiem.
    """
    allowed = {"\n", "\r", "\t"} if allow_newlines else set()
    return any(
        char not in allowed and unicodedata.category(char) == "Cc" for char in text
    )


def qr_data_uri(provisioning_uri: str) -> str:
    """De TOTP-URI als SVG QR-code, verpakt in een data-URI.

    SVG en niet PNG, zodat er geen Pillow bij hoeft: minder dependencies
    betekent minder kwetsbaarheden om bij te houden.
    """
    image = qrcode.make(provisioning_uri, image_factory=qrcode.image.svg.SvgPathImage)
    buffer = io.BytesIO()
    image.save(buffer)
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/svg+xml;base64,{encoded}"


def password_matches(stored_hash: str, password: str) -> bool:
    """True als het wachtwoord bij de hash hoort.

    Specifieke excepties, geen kale except: een onleesbare hash in de
    database is iets anders dan een fout wachtwoord, en dat onderscheid wil
    je kunnen loggen.
    """
    try:
        return ph.verify(stored_hash, password)
    except (VerificationError, InvalidHash):
        return False


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    # Inputvalidatie op basis van een whitelist: alleen wat expliciet is
    # toegestaan komt door. Een blacklist van "gevaarlijke" tekens is altijd
    # incompleet.
    if not USERNAME_PATTERN.fullmatch(username):
        return render_template(
            "register.html",
            error="Gebruikersnaam: 3 tot 32 tekens, alleen a-z, 0-9 en _.",
        ), 400

    # Lengte-eis in plaats van complexiteitsregels met verplichte
    # hoofdletters en tekens, conform de aanbeveling in NIST SP 800-63B.
    if len(password) < 12:
        return render_template(
            "register.html", error="Wachtwoord moet minimaal 12 tekens zijn."
        ), 400

    totp_secret = pyotp.random_base32()

    try:
        with db() as conn, conn.cursor() as cur:
            # Parameterized query: de waarden gaan los van de SQL-string mee
            # naar de database. Dit is wat SQL-injectie onmogelijk maakt, niet
            # het filteren van quotes.
            # De TOTP-secret gaat versleuteld de kolom in (pgcrypto), de
            # wachtwoord-hash niet: die is al onomkeerbaar.
            cur.execute(
                "INSERT INTO users (username, password_hash, totp_secret)"
                " VALUES (%s, %s, pgp_sym_encrypt(%s, %s))",
                (username, ph.hash(password), totp_secret, get_encryption_key()),
            )
    except psycopg.errors.UniqueViolation:
        return render_template(
            "register.html", error="Die gebruikersnaam is al in gebruik."
        ), 409

    # De secret wordt één keer getoond zodat je hem in een authenticator-app
    # kunt zetten. Daarna staat hij alleen nog in de database.
    uri = pyotp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name="Notitie-app")
    return render_template("enroll.html", secret=totp_secret, qr=qr_data_uri(uri))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    with db() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT id, password_hash FROM users WHERE username = %s", (username,)
        )
        row = cur.fetchone()

    # Eén generieke melding voor "gebruiker bestaat niet" en "wachtwoord is
    # fout". Onderscheid maken verklapt welke accounts bestaan (user
    # enumeration) en maakt een aanval gerichter.
    if row is None or not password_matches(row[1], password):
        return render_template("login.html", error="Onjuiste gebruikersnaam of wachtwoord."), 401

    # Nog niet ingelogd: dat gebeurt pas na de tweede factor. Daarom een
    # aparte sessiesleutel, zodat een halve login nergens toegang geeft.
    session.clear()
    session["pending_user_id"] = row[0]
    return redirect(url_for("login_2fa"))


@app.route("/login/2fa", methods=["GET", "POST"])
def login_2fa():
    user_id = session.get("pending_user_id")
    if user_id is None:
        return redirect(url_for("login"))

    if request.method == "GET":
        return render_template("twofactor.html")

    code = request.form.get("code", "").strip()

    with db() as conn, conn.cursor() as cur:
        # Ontsleutelen gebeurt in de database, want daar staat de versleutelde
        # kolom. De applicatie krijgt de leesbare secret terug.
        cur.execute(
            "SELECT pgp_sym_decrypt(totp_secret, %s) FROM users WHERE id = %s",
            (get_encryption_key(), user_id),
        )
        row = cur.fetchone()

    if row is None:
        session.clear()
        return redirect(url_for("login"))

    # valid_window=1 accepteert ook de vorige en volgende code van 30
    # seconden, zodat een klein klokverschil geen mislukte login oplevert.
    if not pyotp.TOTP(row[0]).verify(code, valid_window=1):
        return render_template("twofactor.html", error="Ongeldige code."), 401

    # Nieuwe sessie-inhoud na het voltooien van de login, zodat de
    # pending-status niet blijft staan.
    session.clear()
    session["user_id"] = user_id
    # Eenmalige vlag voor de "access granted"-melding op de notitiepagina.
    session["just_logged_in"] = True
    return redirect(url_for("notes"))


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/", methods=["GET", "POST"])
def notes():
    user_id = session.get("user_id")
    if user_id is None:
        return redirect(url_for("login"))

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        body = request.form.get("body", "").strip()

        # Validatie volgens bedrijfsregels: lengte, verplicht veld, geen
        # controletekens. Let op wat hier NIET gebeurt: HTML of quotes
        # wegfilteren. Een notitie met <script> erin is geldige inhoud; die
        # wordt veilig gemaakt bij het weergeven (escaping plus CSP), niet
        # bij het opslaan.
        error = None
        if not (1 <= len(title) <= MAX_TITLE):
            error = f"Titel is verplicht en maximaal {MAX_TITLE} tekens."
        elif not (1 <= len(body) <= MAX_BODY):
            error = f"Notitie is verplicht en maximaal {MAX_BODY} tekens."
        elif has_disallowed_control_chars(title):
            error = "Titel mag geen regeleindes of andere controletekens bevatten."
        elif has_disallowed_control_chars(body, allow_newlines=True):
            error = "Notitie bevat ongeldige controletekens."

        if error:
            return render_template(
                "notes.html",
                notes=fetch_notes(user_id),
                error=error,
                form_title=title,
                form_body=body,
            ), 400

        with db() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO notes (user_id, title, body) VALUES (%s, %s, %s)",
                (user_id, title, body),
            )
        return redirect(url_for("notes"))

    # pop en niet get: de melding hoort één keer te verschijnen, niet bij
    # elke keer dat de notitiepagina wordt opgevraagd.
    return render_template(
        "notes.html",
        notes=fetch_notes(user_id),
        just_logged_in=session.pop("just_logged_in", False),
    )


def fetch_notes(user_id: int):
    with db() as conn, conn.cursor() as cur:
        # De filter op user_id staat er altijd bij. Zonder die filter kan een
        # gebruiker de notities van anderen zien.
        #
        # MUTATIETEST (voor de bewijsvoering): vervang "WHERE user_id = %s"
        # hieronder tijdelijk door niets en draai
        #   tests/test_autorisatie.py::test_gebruiker_ziet_notities_van_een_ander_niet
        # Die hoort dan rood te worden. Daarna meteen terugzetten.
        cur.execute(
            "SELECT id, title, body, created_at FROM notes"
            " WHERE user_id = %s ORDER BY created_at DESC",
            (user_id,),
        )
        return cur.fetchall()


@app.route("/notes/<int:note_id>/delete", methods=["POST"])
def delete_note(note_id: int):
    user_id = session.get("user_id")
    if user_id is None:
        return redirect(url_for("login"))

    with db() as conn, conn.cursor() as cur:
        # user_id hoort in de WHERE, niet alleen note_id: anders verwijdert
        # iemand met een gegokt id de notitie van een ander.
        #
        # MUTATIETEST (voor de bewijsvoering): haal "AND user_id = %s"
        # hieronder tijdelijk weg, en haal dan ook user_id uit de tuple met
        # parameters, anders klopt het aantal placeholders niet. Draai daarna
        #   tests/test_autorisatie.py::test_gebruiker_kan_notitie_van_een_ander_niet_verwijderen
        # Die hoort rood te worden; de tegenproef eronder blijft groen, wat
        # laat zien dat alleen de beveiliging weg is en niet de functie.
        # Daarna meteen terugzetten.
        cur.execute(
            "DELETE FROM notes WHERE id = %s AND user_id = %s", (note_id, user_id)
        )
    return redirect(url_for("notes"))


if __name__ == "__main__":
    # Alleen voor lokaal testen. De ingebouwde Flask-server is expliciet niet
    # bedoeld voor productie; in Azure draait dit achter een echte WSGI-server
    # (gunicorn) in de container.
    app.run(host="127.0.0.1", port=5000, debug=True)


# ---------------------------------------------------------------------------
# Bewust nog niet in dit concept, in de volgorde van de BoK-onderwerpen:
#
# - Rate limiting en account lockout op /login en /login/2fa. Nu is brute
#   force op de tweede factor mogelijk (6 cijfers, geen limiet).
# - CSRF-tokens op alle POST-formulieren. SameSite=Lax dekt een deel, maar
#   niet alles.
# - Pepper naast de Argon2-salt, met de pepper in Key Vault in plaats van in
#   de database (BoK: key management en secrets handling).
# - Column-level encryptie op users.totp_secret (BoK: database security).
# - Gestructureerde security-logging van de events die in de risicoanalyse
#   zijn gedefinieerd, en doorzetten naar Log Analytics (BoK: logging en
#   monitoring, forensic readiness).
# - Timing gelijktrekken bij een onbekende gebruikersnaam: nu wordt er geen
#   Argon2-verificatie gedaan als de gebruiker niet bestaat, wat meetbaar
#   sneller is.
# - Seed-script met het tweede testaccount en de verstopte flag voor de
#   hacking week.
#
# Nog vast te leggen als bewijsvoering, wanneer er tijd is om te
# documenteren (de commando's staan bij de code die ze bewijzen):
# - Kolomencryptie zichtbaar maken: zie schema.sql bij users.totp_secret.
# - Least-privilege rol aantonen: zie roles.sh.
# - De vier misuse cases die moeten falen: verkeerde 2FA-code, SQL-injectie
#   in de gebruikersnaam, <script> in een notitie, en andermans notitie
#   opvragen via een gegokt id.
# - Sterk bewijs dat de autorisatietests echt iets controleren: voer de twee
#   mutatietests uit die als "MUTATIETEST" bij fetch_notes() en bij
#   delete_note() staan beschreven. Een test die alleen groen is gezien
#   bewijst minder dan een test waarvan je ook hebt laten zien wanneer hij
#   rood wordt.
# ---------------------------------------------------------------------------
