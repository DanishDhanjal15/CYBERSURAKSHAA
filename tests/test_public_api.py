"""
Public API — the surface the Chrome extension and Telegram bot talk to.

This is the only endpoint in the platform a stranger can reach with content of
their choosing, so the tests here are mostly about what it refuses to do:
answer without a key, echo an uncalibrated number as a probability, and let a
submission reach the intelligence graph unreviewed.
"""

import os

import pytest

pytest.importorskip("flask", reason="Flask is not installed")

TEST_KEY = "test-key-for-the-suite-only"

SCAM = (
    "URGENT: Aapka SBI account block ho jayega. Turant KYC update karein "
    "aur OTP share karein. Pay verification fee to scamguy@okhdfcbank or "
    "call 9876543210. Join https://t.me/sbi_kyc_help"
)
BENIGN = (
    "Hi, just confirming our meeting tomorrow at eleven in the north wing "
    "conference room. I have booked it for an hour."
)


# These tests exercise the real application, so they do write to a database --
# a test API key and some quarantined submissions. conftest.py points DB_PATH
# at a scratch file at import time, before `app` is ever imported, so that
# database is never the developer's. This matters more than tidiness: the key
# below has a value published in this repository, and without the isolation it
# was landing in the live database as an active credential.

@pytest.fixture(scope="module")
def api():
    os.environ.setdefault("SECRET_KEY", "test-only-key")
    os.environ["CYBERSURAKSHAA_API_KEY"] = TEST_KEY

    import app as app_module
    from blueprints.public_api import init_api_db

    # The key is seeded at import time; re-seed in case the module was already
    # imported by another test module in the same session.
    init_api_db()

    app_module.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    app_module.limiter.enabled = False
    with app_module.app.test_client() as c:
        yield c


def check(client, text, key=TEST_KEY):
    headers = {"X-API-Key": key} if key else {}
    return client.post("/api/v1/check", json={"text": text}, headers=headers)


class TestDiscovery:
    def test_root_is_self_describing(self, api):
        d = api.get("/api/v1/").get_json()
        assert "endpoints" in d and "limits" in d

    def test_health(self, api):
        assert api.get("/api/v1/health").get_json()["ok"] is True


class TestAuthentication:
    def test_no_key_is_rejected(self, api):
        r = check(api, SCAM, key=None)
        assert r.status_code == 401

    def test_wrong_key_is_rejected(self, api):
        r = check(api, SCAM, key="not-the-key")
        assert r.status_code == 401

    def test_valid_key_is_accepted(self, api):
        assert check(api, SCAM).status_code == 200

    def test_keys_are_not_stored_in_the_clear(self, api):
        """
        A leaked database must not hand the reader working credentials for
        every integration.
        """
        from services.intel.db import get_db_connection
        conn = get_db_connection()
        rows = conn.execute("SELECT key_hash FROM api_keys").fetchall()
        conn.close()
        stored = {r["key_hash"] for r in rows}
        assert TEST_KEY not in stored
        assert all(len(h) == 64 for h in stored)


class TestClassification:
    def test_scam_scores_above_benign(self, api):
        scam = check(api, SCAM).get_json()
        benign = check(api, BENIGN).get_json()
        assert scam["score"] > benign["score"]

    def test_benign_message_is_not_flagged(self, api):
        assert check(api, BENIGN).get_json()["band"] == "SAFE"

    def test_indicators_carry_their_reporting_authority(self, api):
        """
        A citizen who is told "there is a UPI ID in this message" still does
        not know what to do. Naming the authority is the difference between
        information and an action.
        """
        d = check(api, SCAM).get_json()
        upi = [i for i in d["indicators"] if i["kind"] == "upi"]
        assert upi, "the payment address was not extracted"
        assert upi[0]["report_to"]

    def test_advice_is_always_present(self, api):
        for text in (SCAM, BENIGN):
            assert check(api, text).get_json()["advice"]

    def test_clean_result_states_what_it_does_not_cover(self, api):
        """
        "No scam patterns found" must never read as "this message is safe".
        The wording has to say what was not checked.
        """
        advice = " ".join(check(api, BENIGN).get_json()["advice"]).lower()
        assert "wording only" in advice or "not examined" in advice

    def test_uncalibrated_score_says_so(self, api):
        d = check(api, SCAM).get_json()
        if not d["calibrated"]:
            assert "raw" in d["calibration_note"].lower()

    def test_every_response_carries_the_disclaimer(self, api):
        d = check(api, SCAM).get_json()
        assert "1930" in d["disclaimer"]

    def test_empty_text_is_rejected(self, api):
        assert check(api, "   ").status_code == 400

    def test_oversized_text_is_truncated_not_rejected(self, api):
        """
        A forwarded WhatsApp chain can be enormous. Truncating and answering
        beats refusing: the scam wording is almost always near the start.
        """
        assert check(api, SCAM + (" filler" * 5000)).status_code == 200


class TestQuarantine:
    def test_submission_does_not_reach_the_entity_graph(self, api):
        """
        Anything the public can send is attacker-controlled. Auto-ingesting it
        would let one person forge arbitrary links between any two identifiers
        they chose, and the campaign clustering would faithfully report the
        fiction as a finding.
        """
        from services.intel.db import get_db_connection

        conn = get_db_connection()
        before = conn.execute(
            "SELECT COUNT(*) AS n FROM entities WHERE value = ?",
            ("quarantine-probe@okaxis",)).fetchone()["n"]
        conn.close()

        check(api, "Pay me now at quarantine-probe@okaxis or your account "
                   "will be blocked immediately, turant OTP share karo")

        conn = get_db_connection()
        after = conn.execute(
            "SELECT COUNT(*) AS n FROM entities WHERE value = ?",
            ("quarantine-probe@okaxis",)).fetchone()["n"]
        quarantined = conn.execute(
            "SELECT COUNT(*) AS n FROM public_submissions "
            "WHERE text LIKE '%quarantine-probe%' AND promoted = 0").fetchone()["n"]
        conn.close()

        assert after == before, "a public submission entered the entity graph"
        assert quarantined >= 1, "the submission was not quarantined either"

    def test_response_returns_a_submission_id(self, api):
        assert check(api, SCAM).get_json()["submission_id"] is not None


class TestVerifyPassthrough:
    def test_verification_needs_no_key(self, api):
        """
        Deliberate: an endpoint only the operator can call verifies nothing to
        anyone outside the operator.
        """
        r = api.get("/api/v1/verify/" + "a" * 64)
        assert r.status_code == 404
        assert r.get_json()["found"] is False
