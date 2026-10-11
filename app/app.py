"""
Notitie-app, eerste concept.

Het kleinste werkende geheel waarop de BoK-onderwerpen authentication,
secure password storage, secure coding en database security aantoonbaar
zijn. Bewust nog niet compleet: zie de lijst onderaan dit bestand.
"""

import base64
import hashlib
import hmac
import io
import os
import re
import secrets
import time
import unicodedata

import psycopg
import pyotp
import qrcode
import qrcode.image.svg
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerificationError
from flask import Flask, abort, redirect, render_template, request, session, url_for
from vault_crypto import VaultUnavailable, decrypt_note, encrypt_note

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
    MAX_CONTENT_LENGTH=64 * 1024,
)

DATABASE_URL = os.environ["DATABASE_URL"]

# Argon2id met de defaults van argon2-cffi. Argon2id is de eerste keuze in
# de OWASP Password Storage Cheat Sheet; de salt wordt per wachtwoord
# automatisch gegenereerd en zit in de resulterende hashstring.
ph = PasswordHasher()

USERNAME_PATTERN = re.compile(r"[a-z0-9_]{3,32}")
MAX_TITLE = 120
MAX_BODY = 4000
DUMMY_RECOVERY_HASH = ph.hash(secrets.token_hex(24))
AUTH_FORMS = {"register", "login", "login_2fa", "recover", "issue_recovery_code"}


def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = csrf_token


def is_session_current(user_id, version):
    if version is None:
        return False
    with db() as conn, conn.cursor() as cur:
        cur.execute("SELECT auth_version FROM users WHERE id = %s", (user_id,))
        row = cur.fetchone()
    return row is not None and row[0] == version


@app.before_request
def protect_authentication():
    if request.endpoint == "static":
        return None
    user_id = session.get("user_id")
    if user_id is not None and not is_session_current(user_id, session.get("auth_version")):
        session.clear()
        if request.endpoint not in {"login", "register", "recover"}:
            return redirect(url_for("login"))
    if request.method == "POST" and request.endpoint in AUTH_FORMS:
        expected = session.get("csrf_token", "")
        received = request.form.get("csrf_token", "")
        if not expected or not hmac.compare_digest(expected.encode(), received.encode()):
            abort(400, description="Formulier verlopen. Open de pagina opnieuw.")


def generate_recovery_code():
    raw = secrets.token_hex(24).upper()
    display = "-".join(raw[i:i + 8] for i in range(0, len(raw), 8))
    return display, ph.hash(raw)


def normalize_recovery_code(value):
    if len(value) > 80:
        return ""
    normalized = value.replace("-", "").replace(" ", "").upper()
    return normalized if re.fullmatch(r"[0-9A-F]{48}", normalized) else ""


def matching_totp_step(secret, code, last_used=None):
    if not re.fullmatch(r"[0-9]{6}", code):
        return None
    current = int(time.time()) // 30
    totp = pyotp.TOTP(secret)
    for step in (current + 1, current, current - 1):
        if (last_used is None or step > last_used) and hmac.compare_digest(totp.at(step * 30), code):
            return step
    return None


def rate_key(scope, kind, value):
    return hmac.new(app.secret_key.encode(), f"{scope}:{kind}:{value}".encode(), hashlib.sha256).hexdigest()


def allow_recovery_attempt(scope, account):
    """Gedeelde PostgreSQL-limiet, dus ook effectief met meerdere workers."""
    keys = [(rate_key(scope, "ip", request.remote_addr or "unknown"), 20),
            (rate_key(scope, "account", account), 5)]
    with db() as conn, conn.cursor() as cur:
        for key, maximum in keys:
            cur.execute(
                "INSERT INTO recovery_attempts (key, attempts, window_started) VALUES (%s, 1, now())"
                " ON CONFLICT (key) DO UPDATE SET"
                " attempts = CASE WHEN recovery_attempts.window_started < now() - interval '15 minutes'"
                " THEN 1 ELSE recovery_attempts.attempts + 1 END,"
                " window_started = CASE WHEN recovery_attempts.window_started < now() - interval '15 minutes'"
                " THEN now() ELSE recovery_attempts.window_started END RETURNING attempts", (key,)
            )
            if cur.fetchone()[0] > maximum:
                return False
        cur.execute(
            "DELETE FROM recovery_attempts WHERE key IN (SELECT key FROM recovery_attempts"
            " WHERE window_started < now() - interval '1 day' LIMIT 100 FOR UPDATE SKIP LOCKED)"
        )
    return True


def db():
    """Nieuwe databaseverbinding. Nog geen connection pooling in dit concept."""
    return psycopg.connect(DATABASE_URL)


@app.errorhandler(VaultUnavailable)
def vault_unavailable(error):
    # Geen API-errors met secrets teruggeven, en nooit plaintext opslaan als fallback.
    return "Notities zijn tijdelijk niet beschikbaar. Probeer het later opnieuw.", 503


@app.cli.command("encrypt-notes")
def encrypt_existing_notes():
    """Bestaande plaintext-notities transactioneel naar Vault omzetten."""
    with db() as conn, conn.cursor() as cur:
        cur.execute("SELECT id, title, body FROM notes WHERE NOT encrypted FOR UPDATE")
        for note_id, title, body in cur.fetchall():
            cur.execute(
                "UPDATE notes SET title = %s, body = %s, encrypted = TRUE WHERE id = %s",
                (encrypt_note(title), encrypt_note(body), note_id),
            )


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
    if request.endpoint in AUTH_FORMS:
        response.headers["Cache-Control"] = "no-store"
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
    if not 12 <= len(password) <= 1024:
        return render_template(
            "register.html", error="Wachtwoord moet 12 tot 1024 tekens zijn."
        ), 400

    totp_secret = pyotp.random_base32()
    recovery_code, recovery_hash = generate_recovery_code()

    try:
        with db() as conn, conn.cursor() as cur:
            # Parameterized query: de waarden gaan los van de SQL-string mee
            # naar de database. Dit is wat SQL-injectie onmogelijk maakt, niet
            # het filteren van quotes.
            # De TOTP-secret gaat versleuteld de kolom in (pgcrypto), de
            # wachtwoord-hash niet: die is al onomkeerbaar.
            cur.execute(
                "INSERT INTO users (username, password_hash, totp_secret, recovery_code_hash)"
                " VALUES (%s, %s, pgp_sym_encrypt(%s, %s), %s)",
                (username, ph.hash(password), totp_secret, get_encryption_key(), recovery_hash),
            )
    except psycopg.errors.UniqueViolation:
        return render_template(
            "register.html", error="Die gebruikersnaam is al in gebruik."
        ), 409

    # De secret wordt één keer getoond zodat je hem in een authenticator-app
    # kunt zetten. Daarna staat hij alleen nog in de database.
    uri = pyotp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name="Notitie-app")
    return render_template("enroll.html", secret=totp_secret, qr=qr_data_uri(uri), recovery_code=recovery_code)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", password_reset=session.pop("password_reset", False))

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    with db() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT id, password_hash, auth_version FROM users WHERE username = %s", (username,)
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
    session["pending_auth_version"] = row[2]
    session["pending_since"] = time.time()
    return redirect(url_for("login_2fa"))


@app.route("/login/2fa", methods=["GET", "POST"])
def login_2fa():
    user_id = session.get("pending_user_id")
    if user_id is None or time.time() - session.get("pending_since", 0) > 600:
        session.clear()
        return redirect(url_for("login"))

    if request.method == "GET":
        return render_template("twofactor.html")

    code = request.form.get("code", "").strip()

    with db() as conn, conn.cursor() as cur:
        # Ontsleutelen gebeurt in de database, want daar staat de versleutelde
        # kolom. De applicatie krijgt de leesbare secret terug.
        cur.execute(
            "SELECT pgp_sym_decrypt(totp_secret, %s), auth_version, last_totp_step"
            " FROM users WHERE id = %s FOR UPDATE",
            (get_encryption_key(), user_id),
        )
        row = cur.fetchone()
        if row is None or row[1] != session.get("pending_auth_version"):
            session.clear()
            return redirect(url_for("login"))
        step = matching_totp_step(row[0], code, row[2])
        if step is None:
            return render_template("twofactor.html", error="Ongeldige of al gebruikte code. Wacht op een nieuwe code."), 401
        cur.execute("UPDATE users SET last_totp_step = %s WHERE id = %s", (step, user_id))

    # Nieuwe sessie-inhoud na het voltooien van de login, zodat de
    # pending-status niet blijft staan.
    session.clear()
    session["user_id"] = user_id
    session["auth_version"] = row[1]
    # Eenmalige vlag voor de "access granted"-melding op de notitiepagina.
    session["just_logged_in"] = True
    return redirect(url_for("notes"))


@app.route("/recover", methods=["GET", "POST"])
def recover():
    if request.method == "GET":
        return render_template("recover.html")
    username = request.form.get("username", "").strip()
    if not allow_recovery_attempt("recover", username):
        return render_template("recover.html", error="Te veel pogingen. Probeer het over 15 minuten opnieuw.", username=username), 429
    password = request.form.get("password", "")
    if not 12 <= len(password) <= 1024 or password != request.form.get("password_confirm", ""):
        return render_template("recover.html", error="Kies twee keer hetzelfde wachtwoord van 12 tot 1024 tekens.", username=username), 400
    code = normalize_recovery_code(request.form.get("recovery_code", ""))
    otp = request.form.get("code", "").strip()
    with db() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT id, recovery_code_hash, pgp_sym_decrypt(totp_secret, %s), last_totp_step"
            " FROM users WHERE username = %s FOR UPDATE", (get_encryption_key(), username)
        )
        row = cur.fetchone()
        stored = row[1] if row and row[1] else DUMMY_RECOVERY_HASH
        code_matches = password_matches(stored, code)
        step = matching_totp_step(row[2] if row else "A" * 32, otp, row[3] if row else None)
        if row is None or row[1] is None or not code_matches or step is None:
            return render_template("recover.html", error="Herstelgegevens zijn onjuist, gebruikt of verlopen.", username=username), 401
        # Row lock voorkomt dubbel gebruik; alles wordt samen gecommit.
        cur.execute(
            "UPDATE users SET password_hash = %s, recovery_code_hash = NULL,"
            " auth_version = auth_version + 1, last_totp_step = %s WHERE id = %s",
            (ph.hash(password), step, row[0]),
        )
    session.clear()
    session["password_reset"] = True
    return redirect(url_for("login"))


@app.route("/account/recovery-code", methods=["GET", "POST"])
def issue_recovery_code():
    user_id = session.get("user_id")
    if user_id is None:
        return redirect(url_for("login"))
    if request.method == "GET":
        return render_template("recovery_code.html")
    if not allow_recovery_attempt("issue-recovery", str(user_id)):
        return render_template("recovery_code.html", error="Te veel pogingen. Probeer het over 15 minuten opnieuw."), 429
    with db() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT password_hash, pgp_sym_decrypt(totp_secret, %s), last_totp_step, auth_version"
            " FROM users WHERE id = %s FOR UPDATE", (get_encryption_key(), user_id)
        )
        row = cur.fetchone()
        if row is None or row[3] != session.get("auth_version"):
            session.clear()
            return redirect(url_for("login"))
        password_ok = password_matches(row[0], request.form.get("password", ""))
        step = matching_totp_step(row[1], request.form.get("code", "").strip(), row[2])
        if not password_ok or step is None:
            return render_template("recovery_code.html", error="Onjuist wachtwoord of ongeldige/al gebruikte 2FA-code."), 401
        recovery_code, recovery_hash = generate_recovery_code()
        cur.execute("UPDATE users SET recovery_code_hash = %s, last_totp_step = %s WHERE id = %s",
                    (recovery_hash, step, user_id))
    return render_template("recovery_code.html", recovery_code=recovery_code)


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
        error = validate_note(title, body)

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
                "INSERT INTO notes (user_id, title, body, encrypted) VALUES (%s, %s, %s, TRUE)",
                (user_id, encrypt_note(title), encrypt_note(body)),
            )
        return redirect(url_for("notes"))

    # pop en niet get: de melding hoort één keer te verschijnen, niet bij
    # elke keer dat de notitiepagina wordt opgevraagd.
    return render_template(
        "notes.html",
        notes=fetch_notes(user_id),
        just_logged_in=session.pop("just_logged_in", False),
    )


def validate_note(title: str, body: str):
    """Dezelfde invoerregels voor aanmaken en aanpassen."""
    if not (1 <= len(title) <= MAX_TITLE):
        return f"Titel is verplicht en maximaal {MAX_TITLE} tekens."
    if not (1 <= len(body) <= MAX_BODY):
        return f"Notitie is verplicht en maximaal {MAX_BODY} tekens."
    if has_disallowed_control_chars(title):
        return "Titel mag geen regeleindes of andere controletekens bevatten."
    if has_disallowed_control_chars(body, allow_newlines=True):
        return "Notitie bevat ongeldige controletekens."
    return None


@app.route("/notes/<int:note_id>/edit", methods=["GET", "POST"])
def edit_note(note_id: int):
    user_id = session.get("user_id")
    if user_id is None:
        return redirect(url_for("login"))

    with db() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT title, body, encrypted FROM notes WHERE id = %s AND user_id = %s",
            (note_id, user_id),
        )
        note = cur.fetchone()
    # Dezelfde reactie voor een ontbrekende notitie en die van een ander.
    if note is None:
        abort(404)

    title, body, encrypted = note
    if encrypted:
        title, body = decrypt_note(title), decrypt_note(body)
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        body = request.form.get("body", "").strip()
        error = validate_note(title, body)
        if error:
            return render_template(
                "edit_note.html", title=title, body=body, error=error
            ), 400

        with db() as conn, conn.cursor() as cur:
            # Controleer het eigendom ook bij de mutatie zelf.
            cur.execute(
                "UPDATE notes SET title = %s, body = %s, encrypted = TRUE"
                " WHERE id = %s AND user_id = %s RETURNING id",
                (encrypt_note(title), encrypt_note(body), note_id, user_id),
            )
            if cur.fetchone() is None:
                abort(404)
        return redirect(url_for("notes"))

    return render_template("edit_note.html", title=title, body=body)


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
            "SELECT id, title, body, created_at, encrypted FROM notes"
            " WHERE user_id = %s ORDER BY created_at DESC",
            (user_id,),
        )
        rows = cur.fetchall()
    return [
        (note_id, decrypt_note(title) if encrypted else title,
         decrypt_note(body) if encrypted else body, created_at)
        for note_id, title, body, created_at, encrypted in rows
    ]


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
