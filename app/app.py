"""
Notitie-app, eerste concept.

Het kleinste werkende geheel waarop de BoK-onderwerpen authentication,
secure password storage, secure coding en database security aantoonbaar
zijn. Bewust nog niet compleet: zie de lijst onderaan dit bestand.
"""

import os
import re

import psycopg
import pyotp
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
            cur.execute(
                "INSERT INTO users (username, password_hash, totp_secret)"
                " VALUES (%s, %s, %s)",
                (username, ph.hash(password), totp_secret),
            )
    except psycopg.errors.UniqueViolation:
        return render_template(
            "register.html", error="Die gebruikersnaam is al in gebruik."
        ), 409

    # De secret wordt één keer getoond zodat je hem in een authenticator-app
    # kunt zetten. Daarna staat hij alleen nog in de database.
    uri = pyotp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name="Notitie-app")
    return render_template("enroll.html", secret=totp_secret, uri=uri)


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
        cur.execute("SELECT totp_secret FROM users WHERE id = %s", (user_id,))
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

        if not (1 <= len(title) <= MAX_TITLE) or not (1 <= len(body) <= MAX_BODY):
            return render_template(
                "notes.html",
                notes=fetch_notes(user_id),
                error=f"Titel maximaal {MAX_TITLE} tekens, notitie maximaal {MAX_BODY}.",
            ), 400

        with db() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO notes (user_id, title, body) VALUES (%s, %s, %s)",
                (user_id, title, body),
            )
        return redirect(url_for("notes"))

    return render_template("notes.html", notes=fetch_notes(user_id))


def fetch_notes(user_id: int):
    with db() as conn, conn.cursor() as cur:
        # De filter op user_id staat er altijd bij. Zonder die filter kan een
        # gebruiker de notities van anderen zien.
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
# ---------------------------------------------------------------------------
