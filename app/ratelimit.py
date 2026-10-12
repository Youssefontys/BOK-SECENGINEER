"""Throttling van inlogpogingen, gedeeld via PostgreSQL.

Waarom PostgreSQL en geen geheugen in het proces: gunicorn draait met twee
workers en in Azure straks met meerdere instanties. Een teller in het
geheugen zou per proces apart tellen, waardoor een aanvaller zijn pogingen
simpelweg over de workers verdeelt. De database is de ene plek die ze
allemaal delen.

Wat dit doet, per sleutel (een HMAC van ip, account of account+ip):

- mislukte pogingen tellen binnen een vast venster;
- bij te veel mislukkingen volgt een blokkade;
- een herhaalde blokkade binnen 24 uur duurt twee keer zo lang, tot een
  plafond (progressieve blokkade).

De beleidskeuzes staan in POLICIES, met hieronder waarom ze zo zijn.
"""

import ipaddress
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Policy:
    max_failures: int
    window_seconds: int
    base_lock_seconds: int
    max_lock_seconds: int
    # False betekent: wel tellen en melden, nooit blokkeren.
    enforce: bool = True


# Limieten die aan een account hangen. Die staan los van het IP-adres en
# veranderen NIET met de IP-modus hieronder: wat ook met de IP-limieten
# gebeurt, de accounts zelf blijven even streng beschermd.
ACCOUNT_POLICIES = {
    # Per account vanaf één IP-adres: gericht raden op één account. Bewust
    # de combinatie en niet het account alleen, zie "login_account".
    #
    # BEPERKING: wie vijf keer een verkeerd wachtwoord invoert voor jouw
    # gebruikersnaam vanaf hetzelfde IP-adres als jij (school, NAT) maakt
    # dezelfde combinatie en sluit je daar 15 tot 60 minuten buiten. Vanaf een
    # ander netwerk kom je gewoon binnen. De IP-modus verandert dit niet, want
    # dit is een accountlimiet. Een mogelijke oplossing voor later: een
    # "bekend apparaat"-cookie na een geslaagde login.
    "login_pair": Policy(5, 900, 900, 3600),

    # Per account, over alle IP's heen, in de wachtwoordstap: NIET blokkerend.
    # Een blokkade per account zou iedereen die een gebruikersnaam kent in
    # staat stellen dat account te vergrendelen (denial of service tegen een
    # ander). Dit is dus alleen een meldsignaal voor een verspreide aanval.
    # De bescherming daartegen is de tweede factor en de IP-limiet.
    "login_account": Policy(30, 3600, 0, 0, enforce=False),

    # Per account in de tweede-factorstap. Hier wel blokkeren, en strenger:
    # een zescijferige code heeft maar 10^6 mogelijkheden. Dit kan ook geen
    # DoS-hefboom zijn voor een buitenstaander, want je bereikt deze stap
    # alleen met het juiste wachtwoord. Plafond 24 uur.
    "twofa_account": Policy(5, 900, 900, 86400),

    # Wachtwoordherstel met herstelcode. Hier is de gebruikersnaam het enige
    # wat een aanvaller hoeft te kennen, dus per account blokkeren (een
    # zelfde afweging als bij twofa_account, maar zonder wachtwoordstap
    # ervoor). Elke poging telt, een geslaagd herstel wist de teller.
    "recover_account": Policy(5, 900, 900, 86400),

    # Een ingelogde gebruiker die een nieuwe herstelcode aanvraagt moet
    # wachtwoord en TOTP-code geven. Alleen bereikbaar met een sessie, dus
    # geen DoS-hefboom voor een buitenstaander.
    "issue_recovery_account": Policy(5, 900, 900, 86400),
}

# Limieten die aan een IP-adres hangen. Het probleem met IP-limieten is een
# gedeeld netwerk: op school of achter een NAT zitten veel onschuldige
# gebruikers achter hetzelfde adres, en één aanvaller kan dan iedereen
# buitensluiten. Daarom zijn er drie standen, te kiezen met THROTTLE_IP_MODE.
IP_POLICIES = {
    # Standaard. Streng en met escalatie, bedoeld voor een app met
    # gebruikers van overal.
    "strict": {
        # Stopt password spraying (een paar veelgebruikte wachtwoorden over
        # veel accounts) en credential stuffing vanaf een enkele bron.
        "login_ip": Policy(20, 900, 900, 3600),
        "twofa_ip": Policy(20, 900, 900, 3600),
        # Elke registratie kost twee Argon2-berekeningen, en een
        # gebruikersnaam die al bestaat wordt gemeld: zonder limiet is dit
        # een gratis manier om accounts op te sporen en de server te belasten.
        "register_ip": Policy(10, 3600, 3600, 14400),
        "recover_ip": Policy(20, 900, 900, 3600),
    },
    # Voor een omgeving met veel gebruikers achter één adres, zoals een
    # klaslokaal tijdens de hacking week. Ruimere drempels en een vaste,
    # korte blokkade zonder escalatie: een snelle scanner wordt nog steeds
    # afgeremd, maar de rest van de klas wacht hooguit vijf minuten.
    "hackweek": {
        "login_ip": Policy(100, 900, 300, 300),
        "twofa_ip": Policy(100, 900, 300, 300),
        "register_ip": Policy(30, 3600, 300, 300),
        "recover_ip": Policy(100, 900, 300, 300),
    },
    # Alleen tellen en melden, nooit op IP blokkeren. Het risico: niets stopt
    # nog een aanvaller die massaal verschillende accounts probeert, en elke
    # poging kost een Argon2-berekening, dus de app kan daardoor traag worden.
    # De accounts zelf blijven beschermd door ACCOUNT_POLICIES.
    "observe": {
        "login_ip": Policy(20, 900, 0, 0, enforce=False),
        "twofa_ip": Policy(20, 900, 0, 0, enforce=False),
        "register_ip": Policy(10, 3600, 0, 0, enforce=False),
        "recover_ip": Policy(20, 900, 0, 0, enforce=False),
    },
}


def build_policies(mode):
    """Het volledige beleid voor een IP-modus: accountregels plus IP-regels."""
    if mode not in IP_POLICIES:
        # Bewust een fout en geen stille terugval op "strict": een typfout in
        # de configuratie moet opvallen, niet onopgemerkt een andere stand geven.
        raise ValueError(f"Onbekende THROTTLE_IP_MODE {mode!r}; kies uit {sorted(IP_POLICIES)}")
    return {**ACCOUNT_POLICIES, **IP_POLICIES[mode]}


POLICIES = build_policies(os.environ.get("THROTTLE_IP_MODE", "strict"))


@dataclass(frozen=True)
class Outcome:
    failures: int
    # Blokkadeduur in seconden als deze mislukking een blokkade startte.
    locked_for: int = 0
    # Alleen voor niet-blokkerende beleidsregels: de drempel is net bereikt.
    threshold_crossed: bool = False


def client_bucket(remote_addr):
    """Normaliseer een client-adres tot de sleutel waarop gelimiteerd wordt.

    IPv4 blijft een adres. IPv6 wordt een /64: een aanvaller met een
    standaardtoewijzing heeft 2^64 adressen en zou anders bij elke poging een
    nieuw adres kunnen nemen. Een IPv4-mapped IPv6-adres wordt het IPv4-adres,
    zodat dezelfde bron niet onder twee sleutels valt.
    """
    try:
        address = ipaddress.ip_address(remote_addr)
    except (ValueError, TypeError):
        # Onbekend of onleesbaar valt in één gedeelde bak: liever te streng
        # dan een manier om de limiet te omzeilen.
        return "unknown"
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            return str(address.ipv4_mapped)
        return str(ipaddress.ip_network(f"{address}/64", strict=False))
    return str(address)


def blocked_seconds(cur, keys):
    """Resterende blokkade in seconden over de gegeven sleutels (0 = vrij)."""
    cur.execute(
        "SELECT COALESCE(MAX(CEIL(EXTRACT(EPOCH FROM (locked_until - now())))), 0)::int"
        " FROM auth_throttle WHERE key = ANY(%s) AND locked_until > now()",
        (list(keys),),
    )
    return cur.fetchone()[0]


def record_failure(cur, policy_name, key):
    """Registreer een mislukking en start zo nodig een blokkade.

    Alles gebeurt in SQL, zodat twee gelijktijdige verzoeken elkaar niet
    kunnen overschrijven: de upsert telt atomair, en de blokkade wordt alleen
    gezet als er nog geen actieve blokkade is, zodat twee verzoeken die
    tegelijk de drempel halen niet allebei de duur verdubbelen.
    """
    policy = POLICIES[policy_name]
    cur.execute(
        "INSERT INTO auth_throttle (key, failures, window_started, updated_at)"
        " VALUES (%(key)s, 1, now(), now())"
        " ON CONFLICT (key) DO UPDATE SET"
        "  failures = CASE WHEN auth_throttle.window_started < now() - make_interval(secs => %(window)s)"
        "                  THEN 1 ELSE auth_throttle.failures + 1 END,"
        "  window_started = CASE WHEN auth_throttle.window_started < now() - make_interval(secs => %(window)s)"
        "                  THEN now() ELSE auth_throttle.window_started END,"
        # Na 24 uur zonder activiteit begint de escalatie weer bij het begin.
        "  lock_count = CASE WHEN auth_throttle.updated_at < now() - interval '24 hours'"
        "                  THEN 0 ELSE auth_throttle.lock_count END,"
        "  updated_at = now()"
        " RETURNING failures",
        {"key": key, "window": policy.window_seconds},
    )
    failures = cur.fetchone()[0]

    if failures < policy.max_failures:
        return Outcome(failures)

    if not policy.enforce:
        return Outcome(failures, threshold_crossed=failures == policy.max_failures)

    cur.execute(
        "UPDATE auth_throttle SET"
        "  locked_until = now() + make_interval(secs => LEAST(%(base)s * power(2, lock_count), %(cap)s)),"
        "  lock_count = lock_count + 1,"
        # Na afloop van de blokkade krijgt de bron weer een vers venster,
        # maar de volgende blokkade duurt dan langer (lock_count).
        "  failures = 0,"
        "  window_started = now()"
        # MUTATIETEST (voor de bewijsvoering): haal de voorwaarde hieronder
        # tijdelijk weg en draai
        #   tests/test_ratelimit.py::test_gelijktijdige_mislukkingen_starten_precies_een_blokkade
        # Die hoort dan rood te worden, want elke mislukking boven de drempel
        # zou de blokkade opnieuw verdubbelen. Daarna meteen terugzetten.
        " WHERE key = %(key)s AND (locked_until IS NULL OR locked_until <= now())"
        " RETURNING CEIL(EXTRACT(EPOCH FROM (locked_until - now())))::int",
        {"key": key, "base": policy.base_lock_seconds, "cap": policy.max_lock_seconds},
    )
    row = cur.fetchone()
    return Outcome(failures, locked_for=row[0] if row else 0)


def reset(cur, key):
    """Wis de teller na een geslaagde stap.

    Bewust alleen aanroepen voor sleutels die bij het geslaagde account
    horen, nooit voor de IP-sleutel: anders kan een aanvaller met één eigen
    geldig account zijn IP-teller steeds terugzetten door tussendoor in te
    loggen, en daarmee de IP-limiet omzeilen.
    """
    cur.execute(
        "DELETE FROM auth_throttle WHERE key = %s AND (locked_until IS NULL OR locked_until <= now())",
        (key,),
    )


def purge_stale(cur):
    """Ruim oude rijen op, zodat aanvallers de tabel niet kunnen laten groeien."""
    cur.execute(
        "DELETE FROM auth_throttle WHERE key IN ("
        " SELECT key FROM auth_throttle"
        " WHERE updated_at < now() - interval '1 day'"
        "   AND (locked_until IS NULL OR locked_until < now())"
        " LIMIT 100 FOR UPDATE SKIP LOCKED)"
    )
