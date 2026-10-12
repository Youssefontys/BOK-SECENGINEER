"""De limiter zelf, tegen de echte database.

Klein beleid met een korte drempel, zodat een test geen vijftien minuten
hoeft te wachten: verlopen tijd wordt nagebootst door tijdstempels in de
database terug te zetten, niet door te slapen.
"""

from concurrent.futures import ThreadPoolExecutor
import secrets

import pytest

import app as application
import ratelimit
from ratelimit import Policy

# Drempel 3, venster 60 s, eerste blokkade 100 s, plafond 350 s:
# blokkades duren dus 100, 200, 350, 350.
TEST_POLICY = Policy(3, 60, 100, 350)


@pytest.fixture
def key(monkeypatch):
    monkeypatch.setitem(ratelimit.POLICIES, "test", TEST_POLICY)
    value = "test-" + secrets.token_hex(8)
    yield value
    with application.db() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM auth_throttle WHERE key = %s", (value,))


def fail(key, times=1, policy="test"):
    outcome = None
    for _ in range(times):
        with application.db() as conn, conn.cursor() as cur:
            outcome = ratelimit.record_failure(cur, policy, key)
    return outcome


def wait_for(key):
    with application.db() as conn, conn.cursor() as cur:
        return ratelimit.blocked_seconds(cur, [key])


def expire_lock(key):
    with application.db() as conn, conn.cursor() as cur:
        cur.execute("UPDATE auth_throttle SET locked_until = now() - interval '1 second' WHERE key = %s", (key,))


def test_ipv4_blijft_een_adres():
    assert ratelimit.client_bucket("203.0.113.7") == "203.0.113.7"


def test_ipv6_wordt_een_64_netwerk_zodat_adreswisselen_niets_oplevert():
    assert ratelimit.client_bucket("2001:db8:abcd:12::1") == ratelimit.client_bucket("2001:db8:abcd:12:ffff::9")
    assert ratelimit.client_bucket("2001:db8:abcd:12::1") == "2001:db8:abcd:12::/64"
    assert ratelimit.client_bucket("2001:db8:abcd:13::1") != ratelimit.client_bucket("2001:db8:abcd:12::1")


def test_ipv4_mapped_ipv6_valt_onder_het_ipv4_adres():
    assert ratelimit.client_bucket("::ffff:203.0.113.7") == "203.0.113.7"


@pytest.mark.parametrize("onleesbaar", [None, "", "geen-adres", "999.1.1.1"])
def test_onleesbaar_adres_valt_in_een_gedeelde_strenge_bak(onleesbaar):
    assert ratelimit.client_bucket(onleesbaar) == "unknown"


def test_onder_de_drempel_geen_blokkade(key):
    outcome = fail(key, 2)
    assert outcome.failures == 2 and outcome.locked_for == 0
    assert wait_for(key) == 0


def test_op_de_drempel_start_de_eerste_blokkade(key):
    outcome = fail(key, 3)
    assert 99 <= outcome.locked_for <= 100
    assert 99 <= wait_for(key) <= 100


def test_herhaalde_blokkade_duurt_langer_tot_het_plafond(key):
    duur = []
    for _ in range(4):
        duur.append(fail(key, 3).locked_for)
        expire_lock(key)
    assert [round(d, -1) for d in duur] == [100, 200, 350, 350]


def test_escalatie_begint_opnieuw_na_24_uur_rust(key):
    fail(key, 3)
    expire_lock(key)
    with application.db() as conn, conn.cursor() as cur:
        cur.execute("UPDATE auth_throttle SET updated_at = now() - interval '25 hours' WHERE key = %s", (key,))
    assert 99 <= fail(key, 3).locked_for <= 100


def test_venster_verloopt_en_de_teller_begint_opnieuw(key):
    fail(key, 2)
    with application.db() as conn, conn.cursor() as cur:
        cur.execute("UPDATE auth_throttle SET window_started = now() - interval '2 minutes' WHERE key = %s", (key,))
    outcome = fail(key, 1)
    assert outcome.failures == 1 and outcome.locked_for == 0


def test_niet_blokkerend_beleid_telt_en_meldt_maar_blokkeert_nooit(key, monkeypatch):
    monkeypatch.setitem(ratelimit.POLICIES, "alleen_melden", Policy(3, 60, 0, 0, enforce=False))
    resultaten = [fail(key, 1, "alleen_melden") for _ in range(6)]
    assert [r.threshold_crossed for r in resultaten] == [False, False, True, False, False, False]
    assert wait_for(key) == 0


def test_reset_wist_de_teller(key):
    fail(key, 2)
    with application.db() as conn, conn.cursor() as cur:
        ratelimit.reset(cur, key)
    assert fail(key, 1).failures == 1


def test_reset_haalt_een_actieve_blokkade_niet_weg(key):
    fail(key, 3)
    with application.db() as conn, conn.cursor() as cur:
        ratelimit.reset(cur, key)
    assert wait_for(key) > 0


def test_gelijktijdige_mislukkingen_starten_precies_een_blokkade(key):
    """Twaalf verzoeken tegelijk over de drempel: de blokkade mag niet
    meerdere keren verdubbelen doordat ze elkaar in de weg zitten."""
    with ThreadPoolExecutor(max_workers=12) as pool:
        list(pool.map(lambda _: fail(key, 1), range(12)))
    with application.db() as conn, conn.cursor() as cur:
        cur.execute("SELECT lock_count FROM auth_throttle WHERE key = %s", (key,))
        assert cur.fetchone()[0] == 1


def test_oude_rijen_worden_opgeruimd_maar_actieve_blokkades_blijven(key):
    oud = "test-oud-" + secrets.token_hex(6)
    with application.db() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO auth_throttle (key, failures, updated_at) VALUES (%s, 1, now() - interval '3 days')",
            (oud,),
        )
    fail(key, 3)
    with application.db() as conn, conn.cursor() as cur:
        cur.execute("UPDATE auth_throttle SET updated_at = now() - interval '3 days' WHERE key = %s", (key,))
        ratelimit.purge_stale(cur)
        cur.execute("SELECT key FROM auth_throttle WHERE key = ANY(%s)", ([oud, key],))
        over = {row[0] for row in cur.fetchall()}
    assert oud not in over
    assert key in over
