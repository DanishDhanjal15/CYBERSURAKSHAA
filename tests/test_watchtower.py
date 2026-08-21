"""
The lifecycle modules: certificate monitoring, takedown outcomes, resurrection.

Nothing here touches the network. The CT tests exercise the matcher against
hand-written hostnames, and the takedown tests inject probe results directly —
a test suite whose result depends on crt.sh being up would fail for reasons
that have nothing to do with this code, and crt.sh is down often enough that
this is not hypothetical.

The properties under test are mostly about *not* overclaiming: a source outage
must not read as a quiet day, a network blip must not read as a takedown, and a
shared payment handle must not read as one operator.
"""

import sqlite3
from datetime import datetime, timedelta

import pytest

from services.intel import ctlog, takedown, resurrection, graph
from services.intel.db import get_db_connection


def stamp(days_ago=0):
    return (datetime.now() - timedelta(days=days_ago)).strftime("%Y-%m-%d %H:%M:%S")


@pytest.fixture
def watch_db(temp_db):
    """The lifecycle tables on top of the shared temp database."""
    ctlog.init_ctlog_db()
    takedown.init_takedown_db()
    resurrection.init_resurrection_db()
    return temp_db


# ══════════════════════════════════════════════════════════════════════════
# Certificate Transparency
# ══════════════════════════════════════════════════════════════════════════

class TestBrandTokens:
    def test_simple_brand(self):
        assert ctlog.brand_tokens("sbi.co.in") == {"sbi"}

    def test_compound_brand_yields_its_stem(self):
        """Operators register both `hdfcbank-kyc.com` and `hdfc-secure.com`."""
        tokens = ctlog.brand_tokens("hdfcbank.com")
        assert "hdfcbank" in tokens and "hdfc" in tokens

    def test_short_fragments_are_dropped(self):
        """A two-character token would match half the internet."""
        assert all(len(t) >= 3 for t in ctlog.brand_tokens("ab.com"))


class TestScoring:
    @pytest.mark.parametrize("host", [
        "sbi-verify-kyc.com",
        "sbi-online.co",
        "secure-sbi-login.xyz",
        "sb1-netbanking.com",          # digit-for-letter on the brand itself
    ])
    def test_typosquats_score_actionably(self, host):
        score, reasons = ctlog.score_domain(host, "sbi.co.in")
        assert score >= ctlog.SCORE_REPORT_THRESHOLD, "%s scored %d" % (host, score)
        assert reasons

    @pytest.mark.parametrize("host", [
        "sbi.co.in",                   # the brand itself
        "www.sbi.co.in",               # its subdomain
        "onlinesbi.sbi",               # a domain SBI actually operates
        "retail.onlinesbi.sbi",
    ])
    def test_the_brands_own_infrastructure_scores_zero(self, host):
        """
        Without the alias list, every routine renewal on State Bank's real
        net-banking domain fires an alert -- it is *supposed* to look like SBI.
        An alert stream that cries wolf on the brand's own certificates is one
        nobody reads.
        """
        assert ctlog.score_domain(host, "sbi.co.in")[0] == 0

    @pytest.mark.parametrize("host", ["github.com", "subscribe.example.com",
                                      "business.example.org"])
    def test_unrelated_domains_score_zero(self, host):
        assert ctlog.score_domain(host, "sbi.co.in")[0] == 0

    def test_scam_vocabulary_raises_the_score(self):
        """A typo is a typo; a typo plus 'verify-kyc' is a lure."""
        plain, _ = ctlog.score_domain("sbibank.com", "sbi.co.in")
        lure, _ = ctlog.score_domain("sbibank-verify.com", "sbi.co.in")
        assert lure > plain

    def test_longest_token_wins(self):
        """
        `hdfcbank` must beat its stem `hdfc`, or a domain containing the full
        brand name scores as though it only contained the stem. Iterating a
        set made this depend on hash ordering.
        """
        _, reasons = ctlog.score_domain("hdfcbank-login.com", "hdfcbank.com")
        assert any("hdfcbank" in r for r in reasons)

    def test_scoring_is_deterministic(self):
        first = ctlog.score_domain("secure-hdfcbank-login.xyz", "hdfcbank.com")
        for _ in range(10):
            assert ctlog.score_domain("secure-hdfcbank-login.xyz", "hdfcbank.com") == first

    def test_malformed_hostnames_are_rejected(self):
        for junk in ("", None, "not a hostname", "http://sbi.co.in/path"):
            assert ctlog.score_domain(junk, "sbi.co.in")[0] == 0


class TestSourceHealth:
    def test_never_contacted_is_not_reachable(self, watch_db):
        """
        Three states, not two. Reporting an uncontacted feed as reachable is
        the same false all-clear the module exists to prevent, one step
        earlier.
        """
        ctlog._source_health["crt.sh"]["ok"] = None
        health = ctlog.source_health()
        assert health["discovery_state"] == "unknown"
        assert health["discovery_degraded"] is True

    def test_outage_is_reported_as_degraded(self, watch_db):
        ctlog._mark_source("crt.sh", False, "HTTP 502")
        health = ctlog.source_health()
        assert health["discovery_state"] == "down"
        assert health["discovery_degraded"] is True
        assert "not that no lookalike" in health["note"]

    def test_healthy_feed_is_not_degraded(self, watch_db):
        ctlog._mark_source("crt.sh", True)
        assert ctlog.source_health()["discovery_degraded"] is False

    def test_stats_carry_health(self, watch_db):
        assert "health" in ctlog.stats()


class TestObservationStorage:
    def _obs(self, domain, score=80):
        return {"domain": domain, "brand": "sbi.co.in", "score": score,
                "reasons": ["test"], "issuer": "Let's Encrypt", "cert_id": "1",
                "not_before": stamp(1), "not_after": stamp(-90), "source": "test"}

    def test_new_observations_are_returned(self, watch_db):
        fresh = ctlog._store_observations([self._obs("sbi-fake.com")], ingest=False)
        assert len(fresh) == 1

    def test_reobserving_does_not_realert(self, watch_db):
        """A certificate renewal on a domain already known is not news."""
        ctlog._store_observations([self._obs("sbi-fake2.com")], ingest=False)
        again = ctlog._store_observations([self._obs("sbi-fake2.com")], ingest=False)
        assert again == []

    def test_batch_duplicates_collapse_to_the_highest_score(self, watch_db):
        """One certificate's SAN list routinely repeats the same name."""
        fresh = ctlog._store_observations([
            self._obs("sbi-dup.com", 60), self._obs("sbi-dup.com", 90),
        ], ingest=False)
        assert len(fresh) == 1 and fresh[0]["score"] == 90

    def test_low_scores_stay_out_of_the_graph(self, watch_db):
        """
        A weak brand collision is worth an analyst's glance but must not become
        a graph node, or every site containing "sbi" drowns the thing the graph
        is for.
        """
        ctlog._store_observations([self._obs("sbi-weak.com", 30)], ingest=True)
        conn = get_db_connection()
        n = conn.execute("SELECT COUNT(*) AS n FROM entities WHERE value = ?",
                         ("sbi-weak.com",)).fetchone()["n"]
        conn.close()
        assert n == 0


# ══════════════════════════════════════════════════════════════════════════
# Takedown outcome tracking
# ══════════════════════════════════════════════════════════════════════════

def _probe_result(target_id, alive, when=None):
    """Inject a probe result without touching the network."""
    conn = get_db_connection()
    conn.execute("""INSERT INTO enforcement_probes (target_id, timestamp, alive, method, detail)
                    VALUES (?, ?, ?, 'test', 'injected')""",
                 (target_id, when or stamp(), 1 if alive else 0))
    row = conn.execute("SELECT * FROM enforcement_targets WHERE id = ?", (target_id,)).fetchone()
    target = dict(row)
    if alive:
        conn.execute("""UPDATE enforcement_targets SET state='LIVE', consecutive_dead=0,
                        last_alive=?, last_probe=?, probe_count=probe_count+1 WHERE id=?""",
                     (when or stamp(), when or stamp(), target_id))
    else:
        streak = (target["consecutive_dead"] or 0) + 1
        dead = streak >= takedown.CONSECUTIVE_DEAD_PROBES
        conn.execute("""UPDATE enforcement_targets
                        SET state=?, consecutive_dead=?, last_probe=?, probe_count=probe_count+1,
                            died_at = CASE WHEN ? AND died_at IS NULL THEN ? ELSE died_at END
                        WHERE id=?""",
                     ('DEAD' if dead else target["state"], streak, when or stamp(),
                      1 if dead else 0, when or stamp(), target_id))
    conn.commit()
    conn.close()


class TestRegistration:
    def test_probeable_kinds_start_filed(self, watch_db):
        tid, _ = takedown.register_target("domain", "evil.example", "REGISTRAR")
        target = takedown.list_targets()[0]
        assert target["state"] == takedown.ST_FILED and target["probeable"] == 1

    def test_unprobeable_kinds_start_unknown(self, watch_db):
        """
        There is no public endpoint that reports whether a UPI handle was
        frozen, and probing payment rails to find out would be
        indistinguishable from abuse.
        """
        takedown.register_target("upi", "scam@okaxis", "BANK")
        target = takedown.list_targets()[0]
        assert target["state"] == takedown.ST_UNKNOWN and target["probeable"] == 0

    def test_refiling_does_not_duplicate(self, watch_db):
        """
        Two notices about one domain to one registrar is one enforcement
        effort. Counting it twice inflates every rate computed downstream.
        """
        takedown.register_target("domain", "dup.example", "REGISTRAR")
        takedown.register_target("domain", "dup.example", "REGISTRAR")
        assert len(takedown.list_targets()) == 1

    def test_same_target_to_different_channels_is_two_efforts(self, watch_db):
        takedown.register_target("domain", "multi.example", "REGISTRAR")
        takedown.register_target("domain", "multi.example", "HOSTING")
        assert len(takedown.list_targets()) == 2

    def test_missing_value_is_rejected(self, watch_db):
        tid, err = takedown.register_target("domain", "", "REGISTRAR")
        assert tid is None and err


class TestDeadDeclaration:
    def test_one_failure_is_not_a_takedown(self, watch_db):
        """A resolver hiccup must not become an enforcement success."""
        tid, _ = takedown.register_target("domain", "flaky.example", "REGISTRAR")
        _probe_result(tid, alive=False)
        assert takedown.list_targets()[0]["state"] != takedown.ST_DEAD

    def test_consecutive_failures_confirm_it(self, watch_db):
        tid, _ = takedown.register_target("domain", "gone.example", "REGISTRAR")
        for _ in range(takedown.CONSECUTIVE_DEAD_PROBES):
            _probe_result(tid, alive=False)
        assert takedown.list_targets()[0]["state"] == takedown.ST_DEAD

    def test_a_single_success_resets_the_streak(self, watch_db):
        """
        Otherwise three unrelated blips spread over three weeks add up to a
        fictional takedown.
        """
        tid, _ = takedown.register_target("domain", "resilient.example", "REGISTRAR")
        _probe_result(tid, alive=False)
        _probe_result(tid, alive=False)
        _probe_result(tid, alive=True)
        _probe_result(tid, alive=False)
        assert takedown.list_targets()[0]["state"] != takedown.ST_DEAD


class TestEffectiveness:
    def test_unmeasurable_targets_are_excluded_not_counted_as_failures(self, watch_db):
        """
        Folding payment rails into the denominator drags every rate down for a
        reason unrelated to whether enforcement worked.
        """
        tid, _ = takedown.register_target("domain", "dead.example", "REGISTRAR")
        for _ in range(takedown.CONSECUTIVE_DEAD_PROBES):
            _probe_result(tid, alive=False)
        takedown.register_target("upi", "scam@okaxis", "BANK")
        takedown.register_target("phone", "9876543210", "SANCHAR")

        e = takedown.effectiveness()
        assert e["filed"] == 3
        assert e["measurable"] == 1
        assert e["rate"] == 1.0
        assert e["no_recorded_outcome"] == 2

    def test_coverage_caveat_appears_when_outcomes_are_missing(self, watch_db):
        takedown.register_target("upi", "scam@okaxis", "BANK")
        assert takedown.effectiveness()["coverage_caveat"]

    def test_attribution_caveat_is_always_present(self, watch_db):
        """
        "66% success rate" is a causal claim the data cannot support. The
        caveat travels with the number so it cannot be quoted without it.
        """
        caveat = takedown.effectiveness()["attribution_caveat"]
        assert "not that the" in caveat and "control group" in caveat

    def test_rate_is_none_rather_than_zero_when_nothing_is_measurable(self, watch_db):
        """0% reads as total failure; None reads as unmeasured. They differ."""
        takedown.register_target("upi", "scam@okaxis", "BANK")
        assert takedown.effectiveness()["rate"] is None

    def test_manual_outcome_moves_a_payment_rail_out_of_unknown(self, watch_db):
        """
        The only route by which a UPI freeze is ever recorded. Payment-rail
        action is the most effective enforcement available in India, so
        leaving it unrecordable would make the best channel look like the
        least measurable one.
        """
        tid, _ = takedown.register_target("upi", "frozen@okaxis", "BANK")
        ok, err = takedown.record_outcome(tid, "DEAD", note="PSP confirmed freeze",
                                          recorded_by="analyst")
        assert ok and err is None
        e = takedown.effectiveness()
        assert e["measurable"] == 1 and e["went_dark"] == 1

    def test_invalid_outcome_is_rejected(self, watch_db):
        tid, _ = takedown.register_target("upi", "x@okaxis", "BANK")
        ok, err = takedown.record_outcome(tid, "PROBABLY_GONE")
        assert not ok and err

    def test_per_channel_breakdown(self, watch_db):
        tid, _ = takedown.register_target("domain", "a.example", "REGISTRAR")
        for _ in range(takedown.CONSECUTIVE_DEAD_PROBES):
            _probe_result(tid, alive=False)
        takedown.register_target("domain", "b.example", "HOSTING")
        channels = {c["channel"]: c for c in takedown.effectiveness()["by_channel"]}
        assert channels["REGISTRAR"]["dead"] == 1
        assert channels["HOSTING"]["dead"] == 0


class TestSurvivalCurve:
    def test_empty_history_is_empty_not_an_error(self, watch_db):
        assert takedown.survival_curve()["points"] == []

    def test_curve_only_counts_elapsed_days(self, watch_db):
        """
        Including a target filed yesterday in the day-30 bucket would report
        survival over a period that has not happened yet.
        """
        takedown.register_target("domain", "young.example", "REGISTRAR")
        _probe_result(1, alive=True)
        curve = takedown.survival_curve(days=30)
        assert all(p["of"] > 0 for p in curve["points"])
        assert max((p["day"] for p in curve["points"]), default=0) < 30


# ══════════════════════════════════════════════════════════════════════════
# Resurrection detection
# ══════════════════════════════════════════════════════════════════════════

def _entity(kind, value, when, scan_id, risk=90):
    conn = get_db_connection()
    eid = graph.upsert_entity(conn, kind, value, risk=risk)
    conn.execute("UPDATE entities SET first_seen = ?, last_seen = ? WHERE id = ?",
                 (when, when, eid))
    conn.execute("""INSERT INTO entity_sightings
                    (entity_id, scan_id, module, verdict, score, source, timestamp)
                    VALUES (?, ?, 'Betting Content', 'BETTING', ?, 'test', ?)""",
                 (eid, scan_id, risk, when))
    conn.commit()
    conn.close()
    return eid


def _sighting(entity_id, when, scan_id):
    conn = get_db_connection()
    conn.execute("""INSERT INTO entity_sightings
                    (entity_id, scan_id, module, verdict, score, source, timestamp)
                    VALUES (?, ?, 'Betting Content', 'BETTING', 95, 'test', ?)""",
                 (entity_id, scan_id, when))
    conn.execute("UPDATE entities SET last_seen = ? WHERE id = ?", (when, entity_id))
    conn.commit()
    conn.close()


def _link(a, b):
    conn = get_db_connection()
    graph.link_entities(conn, a, b)
    conn.commit()
    conn.close()


def build_resurrection(watch_db, anchor_kind="upi", anchor="kingbet@okaxis",
                       gap_days=30, new_domains=3):
    """The canonical scenario: campaign, takedown, rebuild on the same rail."""
    upi = _entity(anchor_kind, anchor, stamp(gap_days + 10), 101)
    for i in range(2):
        d = _entity("domain", "royalbet-%d.com" % i, stamp(gap_days + 10), 101)
        _link(upi, d)

    _sighting(upi, stamp(3), 201)
    for i in range(new_domains):
        d = _entity("domain", "imperialbet-%d.com" % i, stamp(3), 201)
        _link(upi, d)
    return upi


class TestActivityGaps:
    def test_finds_a_gap(self):
        gaps = resurrection.activity_gaps([stamp(40), stamp(3)])
        assert len(gaps) == 1 and 35 < gaps[0]["days"] < 39

    def test_continuous_activity_has_no_gaps(self):
        stamps = [stamp(d) for d in range(10, 0, -1)]
        assert resurrection.activity_gaps(stamps) == []

    def test_unparseable_timestamps_are_skipped(self):
        assert resurrection.activity_gaps(["not a date", None, stamp(1)]) == []


class TestDetection:
    def test_detects_the_canonical_rebuild(self, watch_db):
        build_resurrection(watch_db)
        events = resurrection.detect()
        assert len(events) == 1
        e = events[0]
        assert e["anchor_value"] == "kingbet@okaxis"
        assert len(e["new_infrastructure"]) == 3
        assert e["confidence"] > 0.5

    def test_counts_real_sightings_not_the_cached_column(self, watch_db):
        """
        `entities.sightings` is a denormalized counter maintained only by
        upsert_entity(). Any path that records a sighting without it -- the
        crawler, a backfill -- leaves the counter behind, and filtering on it
        made the detector skip exactly the anchors with the most history.
        """
        upi = build_resurrection(watch_db)
        conn = get_db_connection()
        conn.execute("UPDATE entities SET sightings = 1 WHERE id = ?", (upi,))
        conn.commit()
        conn.close()
        assert len(resurrection.detect()) == 1

    def test_continuous_activity_is_not_a_resurrection(self, watch_db):
        upi = _entity("upi", "steady@okaxis", stamp(20), 301)
        for day in (15, 10, 5, 1):
            _sighting(upi, stamp(day), 300 + day)
            _link(upi, _entity("domain", "steady-%d.com" % day, stamp(day), 300 + day))
        assert resurrection.detect() == []

    def test_anchor_alone_is_not_a_resurrection(self, watch_db):
        """
        An anchor reappearing with no new disposable infrastructure is a
        straggling sighting, not a rebuild.
        """
        upi = _entity("upi", "lonely@okaxis", stamp(40), 401)
        _sighting(upi, stamp(2), 402)
        assert resurrection.detect() == []

    def test_disposable_kinds_do_not_anchor(self, watch_db):
        """
        A shared domain is not evidence of a common operator -- domains are
        what gets replaced. Only durable anchors drive detection.
        """
        dom = _entity("domain", "shared.example", stamp(40), 501)
        _sighting(dom, stamp(2), 502)
        _link(dom, _entity("domain", "new.example", stamp(2), 502))
        assert resurrection.detect() == []

    def test_widely_shared_anchors_are_suppressed(self, watch_db):
        """
        A payment aggregator handle appearing across dozens of unrelated
        artefacts is infrastructure, not identity — and would generate a
        resurrection alert every time any of them resurfaced.
        """
        upi = _entity("upi", "aggregator@okaxis", stamp(40), 601)
        for i in range(resurrection.ANCHOR_SHARING_LIMIT + 5):
            _sighting(upi, stamp(40), 700 + i)
        _sighting(upi, stamp(2), 900)
        _link(upi, _entity("domain", "after.example", stamp(2), 900))
        assert resurrection.detect() == []

    def test_confidence_reflects_anchor_durability(self, watch_db):
        """A mule bank account is harder to replace than an IFSC code."""
        build_resurrection(watch_db, "bank_account", "38472910556677")
        strong = resurrection.detect()[0]["confidence"]

        for t in ("entities", "entity_edges", "entity_sightings", "resurrection_events"):
            conn = get_db_connection()
            conn.execute("DELETE FROM %s" % t)
            conn.commit()
            conn.close()

        build_resurrection(watch_db, "ifsc", "SBIN0001234")
        weak = resurrection.detect()[0]["confidence"]
        assert strong > weak

    def test_events_are_persisted_and_deduplicated(self, watch_db):
        build_resurrection(watch_db)
        resurrection.detect()
        resurrection.detect()
        assert len(resurrection.recent_events()) == 1

    def test_stats_carry_the_shared_infrastructure_caveat(self, watch_db):
        caveat = resurrection.stats()["caveat"]
        assert "attribution" in caveat.lower()


class TestChurnProfile:
    def test_names_the_durable_anchor_as_the_bottleneck(self, watch_db):
        """
        The output an investigator actually acts on: where the operation is
        least able to absorb pressure.
        """
        upi = build_resurrection(watch_db)
        profile = resurrection.churn_profile(anchor_id=upi)
        assert profile["bottleneck"]["kind"] == "upi"
        assert profile["bottleneck"]["durable"] is True

    def test_the_anchor_appears_in_its_own_profile(self, watch_db):
        """
        The comparison is anchor-lifespan against disposable-lifespan.
        Querying only neighbours left the one row carrying the answer out.
        """
        upi = build_resurrection(watch_db)
        kinds = {p["kind"] for p in resurrection.churn_profile(anchor_id=upi)["profile"]}
        assert "upi" in kinds

    def test_requires_a_subject(self, watch_db):
        assert "error" in resurrection.churn_profile()
