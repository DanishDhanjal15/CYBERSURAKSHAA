"""
Harm quantification.

Money is the one thing here where a quiet arithmetic bug produces a plausible
wrong answer rather than a crash, so these lean heavily on the properties that
would be silently violated: float drift, double-counting, inferred recovery,
and ratios computed between differently-sourced numbers.
"""

import pytest

from services.intel import harm, graph
from services.intel.db import get_db_connection


@pytest.fixture
def harm_db(temp_db):
    harm.init_harm_db()
    return temp_db


def report(amount, **kw):
    kw.setdefault("category", "investment")
    rid, err = harm.record_report(amount, **kw)
    assert err is None, err
    return rid


# ══════════════════════════════════════════════════════════════════════════
# Money representation
# ══════════════════════════════════════════════════════════════════════════

class TestMoney:
    @pytest.mark.parametrize("given,paise", [
        (100, 10_000), ("100", 10_000), (0.01, 1), ("₹1,23,456.78", 12_345_678),
        ("1234.567", 123_457),          # rounds half-up at the paisa
        (0, 0),
    ])
    def test_rupees_to_paise(self, given, paise):
        assert harm.to_paise(given) == paise

    def test_summing_does_not_drift(self, harm_db):
        """
        The reason money is integer paise. Ten thousand additions of ₹0.10 as
        a float lands near 999.99999 and a national total inherits that error;
        as paise it is exact.
        """
        total = sum(harm.to_paise("0.10") for _ in range(10_000))
        assert total == 100_000          # exactly ₹1,000.00

    @pytest.mark.parametrize("paise,expected", [
        (12_345_678_900, "₹12.35 crore"),   # 1,23,45,678.90 rupees
        (4_720_000_00, "₹47.20 lakh"),
        (150_000_00, "₹1.50 lakh"),
        (5_000_00, "₹5.0k"),
        (250_00, "₹250"),
    ])
    def test_indian_short_form(self, paise, expected):
        """Figures here are spoken in lakh and crore, not millions."""
        assert harm.format_inr(paise) == expected

    def test_indian_digit_grouping(self):
        """Indian grouping is 2,2,3 — not the western 3,3,3."""
        assert harm.format_inr(12_345_678_00, short=False) == "₹1,23,45,678.00"

    def test_none_renders_as_a_dash_not_zero(self):
        """Unknown and zero are different facts."""
        assert harm.format_inr(None) == "—"
        assert harm.format_inr(0) == "₹0"


# ══════════════════════════════════════════════════════════════════════════
# Recording
# ══════════════════════════════════════════════════════════════════════════

class TestRecording:
    def test_records_a_report(self, harm_db):
        rid = report(50_000)
        assert harm.get_report(rid)["amount_paise"] == 5_000_000

    def test_rejects_a_negative_amount(self, harm_db):
        rid, err = harm.record_report(-100, category="investment")
        assert rid is None and err

    def test_rejects_an_unknown_category(self, harm_db):
        rid, err = harm.record_report(100, category="not-a-category")
        assert rid is None and "unknown category" in err

    def test_implausible_amounts_are_flagged_not_counted(self, harm_db):
        """
        One mistyped figure can dominate a national total. It is held for
        review rather than silently accepted or silently discarded.
        """
        report(1_000)
        big = report(500_00_00_000)          # ₹500 crore from one victim
        assert harm.get_report(big)["plausible"] == 0

        totals = harm.national_totals()
        assert totals["reports"] == 1
        assert totals["reported_paise"] == 100_000
        assert totals["held_for_review"] == 1

    def test_beneficiary_enters_the_entity_graph(self, harm_db):
        """
        The whole point of the module: a UPI ID a victim paid becomes the same
        graph node the detectors create from a poster.
        """
        report(25_000, beneficiary_kind="upi", beneficiary_value="mule@okaxis")
        ent = graph.get_entity("upi", "mule@okaxis")
        assert ent is not None

    def test_a_graph_failure_does_not_lose_the_report(self, harm_db, monkeypatch):
        """The victim's report is the part that matters."""
        def boom(*a, **k):
            raise RuntimeError("graph unavailable")
        monkeypatch.setattr(harm, "_link_beneficiary", boom, raising=False)
        rid, err = harm.record_report(
            1_000, category="investment",
            beneficiary_kind="upi", beneficiary_value="x@okaxis",
            link_to_graph=False)
        assert err is None and rid


# ══════════════════════════════════════════════════════════════════════════
# Recovery
# ══════════════════════════════════════════════════════════════════════════

class TestRecovery:
    def test_recovery_starts_at_zero(self, harm_db):
        """
        Nothing infers recovery from a takedown or the passage of time. The
        platform cannot see a bank ledger.
        """
        rid = report(10_000)
        assert harm.get_report(rid)["amount_recovered_paise"] == 0

    def test_analyst_confirmation_is_the_only_route(self, harm_db):
        rid = report(10_000)
        ok, err = harm.confirm_recovery(rid, 7_500, confirmed_by="analyst")
        assert ok and err is None
        row = harm.get_report(rid)
        assert row["amount_recovered_paise"] == 750_000
        assert row["verified"] == 1

    def test_cannot_recover_more_than_was_lost(self, harm_db):
        rid = report(10_000)
        ok, err = harm.confirm_recovery(rid, 50_000)
        assert not ok and "exceeds" in err

    def test_rejects_an_unknown_status(self, harm_db):
        rid = report(10_000)
        ok, err = harm.confirm_recovery(rid, 100, status="PROBABLY_BACK")
        assert not ok and err


# ══════════════════════════════════════════════════════════════════════════
# Exposure
# ══════════════════════════════════════════════════════════════════════════

class TestExposure:
    def test_entity_exposure_sums_its_reports(self, harm_db):
        for amount in (10_000, 25_000, 5_000):
            report(amount, beneficiary_kind="upi", beneficiary_value="mule@okaxis")
        ent = graph.get_entity("upi", "mule@okaxis")
        exposure = harm.entity_exposure(ent["id"])
        assert exposure["reports"] == 3
        assert exposure["total_paise"] == 4_000_000

    def test_campaign_exposure_counts_each_report_once(self, harm_db):
        """
        A victim who paid two indicators that both belong to one campaign is
        one loss, not two. Without the DISTINCT the biggest number would
        belong to the best-connected campaign rather than the costliest one.
        """
        report(30_000, beneficiary_kind="upi", beneficiary_value="a@okaxis")
        report(30_000, beneficiary_kind="upi", beneficiary_value="b@okaxis")

        a = graph.get_entity("upi", "a@okaxis")
        b = graph.get_entity("upi", "b@okaxis")

        conn = get_db_connection()
        conn.execute("""INSERT INTO campaigns (label, method, size, risk, updated_at)
                        VALUES ('Test', 'union-find', 2, 90, '2026-01-01 00:00:00')""")
        cid = conn.execute("SELECT id FROM campaigns").fetchone()["id"]
        for eid in (a["id"], b["id"]):
            conn.execute("INSERT INTO campaign_entities (campaign_id, entity_id) VALUES (?,?)",
                         (cid, eid))
        conn.commit()
        conn.close()

        exposure = harm.campaign_exposure(cid)
        assert exposure["reports"] == 2
        assert exposure["total_paise"] == 6_000_000

    def test_top_beneficiaries_ranks_by_money_not_count(self, harm_db):
        """An account taking one large payment outranks one taking many small."""
        report(500_000, beneficiary_kind="bank_account", beneficiary_value="BIG")
        for _ in range(5):
            report(1_000, beneficiary_kind="upi", beneficiary_value="small@okaxis")

        top = harm.top_beneficiaries()
        assert top[0]["beneficiary_value"] == "BIG"


# ══════════════════════════════════════════════════════════════════════════
# National figures
# ══════════════════════════════════════════════════════════════════════════

class TestNationalTotals:
    def test_reported_and_verified_are_kept_apart(self, harm_db):
        """
        Quoting self-reported losses as audited is how a national figure gets
        discredited.
        """
        a = report(100_000)
        report(50_000)
        harm.confirm_recovery(a, 40_000, confirmed_by="analyst")

        totals = harm.national_totals()
        assert totals["reported_paise"] == 15_000_000
        assert totals["verified_paise"] == 10_000_000

    def test_recovery_rate_uses_verified_losses_only(self, harm_db):
        """
        A ratio between confirmed recoveries and self-reported losses is not a
        rate — it moves whenever a report is exaggerated or missing.
        """
        a = report(100_000)
        report(900_000)                       # unverified, must not dilute
        harm.confirm_recovery(a, 50_000, confirmed_by="analyst")

        assert harm.national_totals()["recovery_rate"] == 0.5

    def test_rate_is_none_rather_than_zero_when_nothing_is_verified(self, harm_db):
        """0% reads as total failure; None reads as unmeasured."""
        report(10_000)
        assert harm.national_totals()["recovery_rate"] is None

    def test_totals_always_carry_the_caveat(self, harm_db):
        assert "no bank has confirmed" in harm.national_totals()["caveat"]

    def test_breakdowns_group_correctly(self, harm_db):
        report(100_000, category="investment", state_code="MH")
        report(50_000, category="gambling", state_code="MH")
        report(25_000, category="investment", state_code="DL")

        by_cat = {c["key"]: c for c in harm.by_category()}
        assert by_cat["investment"]["total"] == 12_500_000
        by_st = {s["key"]: s for s in harm.by_state()}
        assert by_st["MH"]["reports"] == 2


# ══════════════════════════════════════════════════════════════════════════
# Golden hour
# ══════════════════════════════════════════════════════════════════════════

class TestGoldenHour:
    def test_band_is_computed_from_incident_time(self, harm_db):
        """
        Not from report time. The window that matters runs from when the money
        moved, not from when we happened to hear about it.
        """
        rid = report(10_000, incident_at="2026-08-19 10:00:00",
                     reported_at="2026-08-19 10:30:00")
        row = harm.get_report(rid)
        assert row["minutes_to_report"] == 30.0
        assert row["golden_hour"] is True
        assert row["report_band"] == "within_1h"

    def test_outside_the_hour_is_not_golden(self, harm_db):
        rid = report(10_000, incident_at="2026-08-19 10:00:00",
                     reported_at="2026-08-19 18:00:00")
        row = harm.get_report(rid)
        assert row["golden_hour"] is False
        assert row["report_band"] == "6h_to_24h"

    def test_missing_incident_time_is_untimed_not_slow(self, harm_db):
        """Unknown must not be silently bucketed as the worst case."""
        rid = report(10_000)
        row = harm.get_report(rid)
        assert row["minutes_to_report"] is None
        assert row["golden_hour"] is False
        assert row["report_band"] is None
        assert harm.golden_hour_stats()["no_incident_time"] == 1

    def test_a_report_before_the_incident_is_rejected_as_untimed(self, harm_db):
        """Clock skew or a typo, not a negative response time."""
        rid = report(10_000, incident_at="2026-08-19 18:00:00",
                     reported_at="2026-08-19 10:00:00")
        assert harm.get_report(rid)["minutes_to_report"] is None

    def test_stats_carry_the_observational_caveat(self, harm_db):
        assert "causal" in harm.golden_hour_stats()["caveat"]


class TestTaxonomy:
    def test_every_module_maps_to_a_real_category(self):
        """
        Replaces the five-branch substring match on module name in
        actions._ncrp_category().
        """
        for module, key in harm.MODULE_CATEGORY.items():
            assert key in harm.CATEGORIES, "%s maps to unknown %s" % (module, key)
