"""
Emergency vocabulary and commercial metering.

These two modules answer the round-2 criteria in code rather than in slides:
adaptability (a new threat class ships as a keyword bank, behind a switch) and
monetisation (usage becomes an invoice line). Both make claims that are easy
to assert and hard to keep, so the tests here are mostly about the promises:

  * emergency terms score NOTHING while no emergency is declared, because
    "relief fund" and "oxygen" appear in legitimate circulars;
  * declaring an emergency changes the score and the platform says it did;
  * a failed call is never billed;
  * a fresh deployment reports zero revenue, not a seeded figure.
"""

import pytest

from services.intel import metering
from services.intel import pandemic as emergency
from services.intel.db import get_db_connection


@pytest.fixture
def clean_posture():
    """Every test starts from a known posture and leaves none behind."""
    emergency.set_emergency_mode(None)
    yield
    emergency.set_emergency_mode(None)


# ══════════════════════════════════════════════════════════════════════════
# Emergency vocabulary — adaptability
# ══════════════════════════════════════════════════════════════════════════

RELIEF_SCAM = ("Government has approved Rs 5000 covid relief package for you. "
               "Claim your relief fund now, pay processing fee to claim.")
OXYGEN_SCAM = "Oxygen cylinder available urgent, remdesivir injection in stock, DM to book"
WFH_SCAM = "Work from home and earn Rs 3000 daily, part time job registration fee only 500"
LEGITIMATE = ("The district office will publish the relief fund guidelines on "
              "its website next week. No fee is charged for any application.")


class TestEmergencyBankIsInertByDefault:
    def test_nothing_scores_while_no_emergency_is_declared(self, clean_posture):
        """
        The whole reason this bank has a switch: outside an emergency these
        words are ordinary, and scoring them would manufacture false positives
        against legitimate government circulars.
        """
        emergency.set_emergency_mode(False)
        for text in (RELIEF_SCAM, OXYGEN_SCAM, WFH_SCAM):
            score, reasons = emergency.score_emergency(text)
            assert score == 0 and reasons == []

    def test_is_active_reflects_the_switch(self, clean_posture):
        assert emergency.set_emergency_mode(True) is True
        assert emergency.is_active() is True
        assert emergency.set_emergency_mode(False) is False
        assert emergency.is_active() is False

    def test_clearing_the_override_returns_control_to_the_environment(self, clean_posture):
        emergency.set_emergency_mode(True)
        emergency.set_emergency_mode(None)
        assert emergency.is_active() is False   # env default is off


class TestEmergencyBankWhenDeclared:
    def test_relief_fund_scam_is_caught(self, clean_posture):
        emergency.set_emergency_mode(True)
        score, reasons = emergency.score_emergency(RELIEF_SCAM)
        assert score >= 25, (score, reasons)
        assert any("relief" in r.lower() for r in reasons)

    def test_medical_supply_scam_is_caught(self, clean_posture):
        emergency.set_emergency_mode(True)
        score, _ = emergency.score_emergency(OXYGEN_SCAM)
        assert score >= 25

    def test_work_from_home_scam_is_caught(self, clean_posture):
        emergency.set_emergency_mode(True)
        score, _ = emergency.score_emergency(WFH_SCAM)
        assert score >= 20

    def test_a_legitimate_circular_is_not_flagged_hard(self, clean_posture):
        """
        An emergency makes government messaging MORE common, not less. A bank
        that fires on every mention of a relief fund would drown the analyst
        in exactly the period they have least time.
        """
        emergency.set_emergency_mode(True)
        score, _ = emergency.score_emergency(LEGITIMATE)
        assert score <= 20, score

    def test_force_scores_without_declaring(self, clean_posture):
        """The evaluation harness must be able to measure the bank offline."""
        emergency.set_emergency_mode(False)
        score, _ = emergency.score_emergency(RELIEF_SCAM, force=True)
        assert score > 0

    def test_status_reports_the_posture_and_pattern_count(self, clean_posture):
        emergency.set_emergency_mode(True)
        st = emergency.status()
        assert st["active"] is True
        assert st["patterns"] == len(emergency.PANDEMIC_SCAM_KEYWORDS) > 20
        assert st["note"]


class TestEmergencyChangesTheCitizenResult:
    def test_declaring_an_emergency_raises_the_score_and_is_disclosed(
            self, temp_db, clean_posture):
        """
        A citizen comparing two results has to be able to see that the posture,
        not the message, is what changed.
        """
        from blueprints.public_api import init_api_db, run_text_check
        init_api_db()

        emergency.set_emergency_mode(False)
        before = run_text_check(RELIEF_SCAM, "test")

        emergency.set_emergency_mode(True)
        after = run_text_check(RELIEF_SCAM, "test")

        assert after["score"] > before["score"], (before["score"], after["score"])
        assert before["emergency_mode"] is False
        assert after["emergency_mode"] is True


# ══════════════════════════════════════════════════════════════════════════
# Metering — monetisation
# ══════════════════════════════════════════════════════════════════════════

@pytest.fixture
def meter_db(temp_db):
    from blueprints.public_api import init_api_db
    init_api_db()          # creates api_keys + calls init_metering_db()
    return temp_db


def _make_key(label="tenant", plan="standard", org="Test Bank"):
    from blueprints.public_api import create_key
    raw = create_key(label, "api")
    import hashlib
    conn = get_db_connection()
    conn.execute("UPDATE api_keys SET plan = ?, org = ? WHERE key_hash = ?",
                 (plan, org, hashlib.sha256(raw.encode("utf-8")).hexdigest()))
    conn.commit()
    row = conn.execute("SELECT id FROM api_keys WHERE plan = ? AND label = ?",
                       (plan, label)).fetchone()
    conn.close()
    return row["id"], raw


class TestUsageAccounting:
    def test_a_fresh_key_has_consumed_nothing(self, meter_db):
        key_id, _ = _make_key()
        used, by_endpoint = metering.month_to_date(key_id)
        assert used == 0 and by_endpoint == {}

    def test_calls_accumulate_per_endpoint(self, meter_db):
        key_id, _ = _make_key()
        for _ in range(3):
            metering.record_call(key_id, "check")
        metering.record_call(key_id, "usage")

        used, by_endpoint = metering.month_to_date(key_id)
        assert used == 4
        assert by_endpoint == {"check": 3, "usage": 1}

    def test_usage_is_scoped_to_one_tenant(self, meter_db):
        a, _ = _make_key("tenant-a")
        b, _ = _make_key("tenant-b")
        metering.record_call(a, "check")
        metering.record_call(a, "check")
        metering.record_call(b, "check")
        assert metering.month_to_date(a)[0] == 2
        assert metering.month_to_date(b)[0] == 1

    def test_recording_never_raises_on_a_bad_key(self, meter_db):
        """Metering is not allowed to break serving."""
        metering.record_call(None, "check")
        metering.record_call(999999, "check")


class TestInvoicing:
    def test_usage_within_quota_bills_only_the_monthly_fee(self, meter_db):
        key_id, _ = _make_key(plan="standard")
        for _ in range(5):
            metering.record_call(key_id, "check")
        inv = metering.invoice(key_id, "standard")
        assert inv["calls_billable"] == 0
        assert inv["overage_inr"] == 0
        assert inv["total_inr"] == metering.PLANS["standard"]["monthly_fee_inr"]

    def test_overage_is_billed_at_the_published_rate(self, meter_db):
        """
        Arithmetic, checked: the published rate is ₹0.05 per call, so 10 calls
        past quota is ₹0.50 — not a figure anyone has to take on trust.
        """
        key_id, _ = _make_key(plan="standard")
        quota = metering.PLANS["standard"]["monthly_quota"]

        conn = get_db_connection()
        conn.execute("""INSERT INTO api_usage (key_id, day, endpoint, calls, updated_at)
                        VALUES (?, date('now'), 'check', ?, datetime('now'))""",
                     (key_id, quota + 10))
        conn.commit()
        conn.close()

        inv = metering.invoice(key_id, "standard")
        assert inv["calls_billable"] == 10
        assert inv["overage_inr"] == 0.50
        assert inv["total_inr"] == metering.PLANS["standard"]["monthly_fee_inr"] + 0.50

    def test_enterprise_is_unmetered(self, meter_db):
        key_id, _ = _make_key(plan="enterprise")
        for _ in range(50):
            metering.record_call(key_id, "check")
        inv = metering.invoice(key_id, "enterprise")
        assert inv["calls_included"] is None
        assert inv["calls_billable"] == 0
        assert inv["total_inr"] == metering.PLANS["enterprise"]["monthly_fee_inr"]

    def test_a_free_tenant_over_quota_is_never_blocked(self, meter_db):
        """
        A citizen channel cut off mid-emergency is a worse failure than an
        unpaid bill. Over-quota is reported, never enforced.
        """
        key_id, _ = _make_key(plan="free")
        conn = get_db_connection()
        conn.execute("""INSERT INTO api_usage (key_id, day, endpoint, calls, updated_at)
                        VALUES (?, date('now'), 'check', ?, datetime('now'))""",
                     (key_id, metering.PLANS["free"]["monthly_quota"] + 500))
        conn.commit()
        conn.close()

        state = metering.quota_state(key_id, "free")
        assert state["over"] is True
        assert state["blocked"] is False


class TestPlatformSummary:
    def test_a_new_deployment_reports_zero_revenue(self, meter_db):
        """No seeded MRR — the same rule the dashboard counters follow."""
        summary = metering.platform_summary()
        assert summary["total_calls"] == 0
        assert summary["mrr_inr"] == 0
        assert summary["tenant_count"] == 0

    def test_revenue_is_the_sum_of_tenant_invoices(self, meter_db):
        _make_key("bank-a", plan="standard")
        _make_key("state-cell", plan="enterprise")
        _make_key("ngo", plan="free")

        summary = metering.platform_summary()
        expected = (metering.PLANS["standard"]["monthly_fee_inr"]
                    + metering.PLANS["enterprise"]["monthly_fee_inr"]
                    + metering.PLANS["free"]["monthly_fee_inr"])
        assert summary["tenant_count"] == 3
        assert summary["mrr_inr"] == expected


class TestBillingHonesty:
    def test_a_rejected_call_is_not_billed(self, meter_db):
        """
        A customer will notice being charged for a 400. record_call runs only
        after the work succeeded, so an empty-body request costs nothing.
        """
        import os
        os.environ.setdefault("SECRET_KEY", "test-only-key")
        import app as app_module
        from blueprints.public_api import create_key

        raw = create_key("billing-probe", "api")
        conn = get_db_connection()
        key_id = conn.execute("SELECT id FROM api_keys WHERE label = 'billing-probe'"
                              ).fetchone()["id"]
        conn.close()

        app_module.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        app_module.limiter.enabled = False
        client = app_module.app.test_client()

        before = metering.month_to_date(key_id)[0]
        r = client.post("/api/v1/check", json={"text": "   "},
                        headers={"X-API-Key": raw})
        assert r.status_code == 400
        assert metering.month_to_date(key_id)[0] == before

        r = client.post("/api/v1/check", json={"text": "Pay verification fee now"},
                        headers={"X-API-Key": raw})
        assert r.status_code == 200
        assert metering.month_to_date(key_id)[0] == before + 1
