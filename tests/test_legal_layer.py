"""
The legal layer: s.63(4) certificates and statutory clocks.

Two things here fail quietly rather than loudly if they are wrong. A working-day
calculation that is off by one tells somebody they have a day left when the
window has closed and their liability has changed. A certificate that fills in
blanks it cannot support gets relied on in court. Both are tested for what they
*refuse* to do as much as for what they produce.
"""

from datetime import datetime, timedelta

import pytest

from services.intel import certificate, clocks, evidence


# ══════════════════════════════════════════════════════════════════════════
# Working days
# ══════════════════════════════════════════════════════════════════════════

class TestWorkingDays:
    def test_sunday_is_not_a_working_day(self):
        assert clocks.is_bank_working_day(datetime(2026, 8, 16)) is False  # Sunday

    def test_ordinary_weekday_is(self):
        assert clocks.is_bank_working_day(datetime(2026, 8, 19)) is True   # Wednesday

    def test_second_and_fourth_saturdays_are_closed(self):
        """
        Indian banks close on the 2nd and 4th Saturday. Treating every Saturday
        as open overstates the window; treating none as open understates it.
        """
        # August 2026: Saturdays fall on 1, 8, 15, 22, 29 → 2nd is the 8th,
        # 4th is the 22nd.
        assert clocks.is_bank_working_day(datetime(2026, 8, 1)) is True    # 1st Sat
        assert clocks.is_bank_working_day(datetime(2026, 8, 8)) is False   # 2nd Sat
        assert clocks.is_bank_working_day(datetime(2026, 8, 15)) is True   # 3rd Sat
        assert clocks.is_bank_working_day(datetime(2026, 8, 22)) is False  # 4th Sat
        assert clocks.is_bank_working_day(datetime(2026, 8, 29)) is True   # 5th Sat

    def test_adding_working_days_skips_closures(self):
        """
        Friday 14 Aug 2026 + 3 working days = Tuesday 18th.

        Saturday the 15th is the *third* Saturday, so banks are open and it
        counts; Sunday the 16th does not. Getting this wrong by one day tells
        somebody their zero-liability window is still open when it has closed.
        """
        friday = datetime(2026, 8, 14)
        assert clocks.add_working_days(friday, 3).date() == datetime(2026, 8, 18).date()

    def test_counting_between_excludes_the_start_day(self):
        mon, thu = datetime(2026, 8, 17), datetime(2026, 8, 20)
        assert clocks.working_days_between(mon, thu) == 3

    def test_backwards_range_is_none_not_negative(self):
        assert clocks.working_days_between(datetime(2026, 8, 20),
                                           datetime(2026, 8, 17)) is None


# ══════════════════════════════════════════════════════════════════════════
# RBI liability — the clock worth money
# ══════════════════════════════════════════════════════════════════════════

class TestRbiLiability:
    def test_reporting_fast_means_zero_liability(self):
        incident = datetime(2026, 8, 17, 10, 0)          # Monday
        result = clocks.rbi_liability(incident, incident + timedelta(days=1))
        assert result["band"] == "ZERO_LIABILITY"
        assert "bears no liability" in result["meaning"]

    def test_the_fourth_to_seventh_day_is_capped_not_zero(self):
        incident = datetime(2026, 8, 17, 10, 0)
        result = clocks.rbi_liability(incident, datetime(2026, 8, 24, 10, 0))
        assert result["band"] == "LIMITED_LIABILITY"

    def test_beyond_the_window_falls_to_bank_policy(self):
        incident = datetime(2026, 8, 3, 10, 0)
        result = clocks.rbi_liability(incident, datetime(2026, 8, 25, 10, 0))
        assert result["band"] == "BANK_POLICY"

    def test_not_yet_reported_is_its_own_band(self):
        """
        Distinct from 'too late'. Somebody who has not told their bank still
        has something to do, and it is the most valuable thing available.
        """
        result = clocks.rbi_liability(datetime.now() - timedelta(hours=2))
        assert result["band"] == "NOT_YET_REPORTED"
        assert "window is closing" in result["meaning"]

    def test_no_incident_time_is_unknown_not_expired(self):
        result = clocks.rbi_liability(None)
        assert result["band"] == clocks.ST_UNKNOWN
        assert result["clocks"] == []

    def test_every_result_carries_the_holiday_caveat(self):
        """
        Gazetted and state holidays are not modelled. A countdown that silently
        ignored Diwali would say two days remain when none do.
        """
        result = clocks.rbi_liability(datetime(2026, 8, 17))
        assert "holidays are not accounted for" in result["caveat"]

    def test_deadline_falls_on_an_open_day(self):
        """A deadline landing on a Sunday would be uncomplyable."""
        for day in range(1, 29):
            incident = datetime(2026, 8, day, 10, 0)
            deadline = clocks.add_working_days(incident, 3)
            assert clocks.is_bank_working_day(deadline)


# ══════════════════════════════════════════════════════════════════════════
# The other clocks
# ══════════════════════════════════════════════════════════════════════════

class TestClockStatus:
    def test_golden_hour_met_when_reported_inside_it(self):
        incident = datetime(2026, 8, 19, 10, 0)
        c = clocks.golden_hour(incident, incident + timedelta(minutes=30))
        assert c["status"] == clocks.ST_MET

    def test_golden_hour_breached_when_reported_late(self):
        incident = datetime(2026, 8, 19, 10, 0)
        c = clocks.golden_hour(incident, incident + timedelta(hours=8))
        assert c["status"] == clocks.ST_BREACHED

    def test_a_running_clock_reports_time_left(self):
        c = clocks.cert_in(datetime.now() - timedelta(hours=1))
        assert c["status"] in (clocks.ST_RUNNING, clocks.ST_DUE_SOON)
        assert c["remaining_seconds"] > 0
        assert "left" in c["remaining_human"]

    def test_an_expired_clock_reads_as_overdue(self):
        c = clocks.cert_in(datetime.now() - timedelta(hours=10))
        assert c["status"] == clocks.ST_BREACHED
        assert "overdue" in c["remaining_human"]

    def test_a_missing_start_event_is_unknown_not_breached(self):
        """
        The takedown notice printed a 36-hour period while never recording
        service. Unstarted must not read as failed.
        """
        c = clocks.intermediary_compliance(None)
        assert c["status"] == clocks.ST_UNKNOWN
        assert "not been recorded as served" in c["note"]

    def test_most_urgent_picks_the_soonest_live_clock(self):
        incident = datetime.now() - timedelta(minutes=50)
        result = clocks.for_victim_report(
            {"incident_at": incident.strftime("%Y-%m-%d %H:%M:%S"),
             "reported_at": None, "bank_reported_at": None})
        assert result["most_urgent"]["name"] == "Golden hour"


# ══════════════════════════════════════════════════════════════════════════
# s.63(4) certificate
# ══════════════════════════════════════════════════════════════════════════

@pytest.fixture
def scan_row(temp_db):
    """A processed artefact with an evidence-chain entry against it."""
    from services.intel.db import get_db_connection
    artefact = "d" * 64

    conn = get_db_connection()
    conn.execute("""
        INSERT INTO scans (user_id, timestamp, module, input_summary, verdict,
                           score, file_hash)
        VALUES (1, '2026-08-19 10:00:00', 'Betting Content', 'poster.png',
                'BETTING', 95, ?)
    """, (artefact,))
    conn.commit()
    scan_id = conn.execute("SELECT id FROM scans").fetchone()["id"]
    conn.close()

    evidence.append_event(evidence.EV_SCAN, actor="officer_kumar",
                          subject_type="scan", subject_id=scan_id,
                          artefact_hash=artefact,
                          payload={"module": "Betting Content"})
    return scan_id, artefact


class TestCertificateContent:
    def test_cites_the_current_statute(self, scan_row):
        """
        s.65B of the Evidence Act was repealed on 1 July 2024. Citing it is
        citing a statute that no longer exists.
        """
        cert = certificate.build_certificate(scan_row[0])
        assert cert["statute"]["act"] == "Bharatiya Sakshya Adhiniyam, 2023"
        assert cert["statute"]["section"] == "63(4)"
        assert "65B" in cert["statute"]["note"]        # explains the change

    def test_requires_two_signatories(self, scan_row):
        """s.63(4) needs the person in charge AND an expert — not one."""
        cert = certificate.build_certificate(scan_row[0])
        assert "expert" in cert["statute"]["signatories_required"].lower()
        assert "One signature alone" in cert["statute"]["signatories_required"]

    def test_states_the_hash_and_its_algorithm(self, scan_row):
        scan_id, artefact = scan_row
        cert = certificate.build_certificate(scan_id)
        assert cert["record"]["hash"] == artefact
        assert cert["record"]["hash_algorithm"] == "SHA-256"

    def test_addresses_all_four_conditions(self, scan_row):
        cert = certificate.build_certificate(scan_row[0])
        assert [c["clause"] for c in cert["conditions"]] == ["a", "b", "c", "d"]
        for condition in cert["conditions"]:
            assert condition["system_evidence"]

    def test_exhibits_the_chain_of_custody(self, scan_row):
        cert = certificate.build_certificate(scan_row[0])
        assert len(cert["custody"]) >= 1
        assert cert["custody"][0]["actor"] == "officer_kumar"

    def test_device_particulars_are_read_from_the_running_host(self, scan_row):
        """
        A certificate describing a device other than the one that produced the
        record would be worse than none.
        """
        cert = certificate.build_certificate(scan_row[0])
        assert cert["device"]["host"]
        assert cert["device"]["runtime"].startswith("Python")

    def test_always_declares_itself_a_draft(self, scan_row):
        cert = certificate.build_certificate(scan_row[0])
        assert any("DRAFT" in limit for limit in cert["limits"])

    def test_states_that_the_chain_is_not_a_signature(self, scan_row):
        cert = certificate.build_certificate(scan_row[0])
        assert any("not a digital signature" in limit for limit in cert["limits"])

    def test_separates_verdict_accuracy_from_record_authenticity(self, scan_row):
        """
        The certificate authenticates the record. It says nothing about whether
        the classifier was right, and it must not be read as though it did.
        """
        cert = certificate.build_certificate(scan_row[0])
        assert any("not a finding of fact" in limit for limit in cert["limits"])

    def test_unknown_scan_returns_none(self, temp_db):
        assert certificate.build_certificate(999999) is None


class TestCertificateRefusal:
    def test_refuses_when_no_hash_was_recorded(self, temp_db):
        """The Schedule requires the hash. Without it the form cannot be met."""
        from services.intel.db import get_db_connection
        conn = get_db_connection()
        conn.execute("""INSERT INTO scans (user_id, timestamp, module,
                        input_summary, verdict, score, file_hash)
                        VALUES (1,'2026-08-19 10:00:00','Voice Scam','call',
                                'VOICE_SCAM', 80, NULL)""")
        conn.commit()
        scan_id = conn.execute("SELECT id FROM scans").fetchone()["id"]
        conn.close()

        ok, reason = certificate.is_certifiable(scan_id)
        assert not ok and "hash" in reason.lower()

    def test_refuses_while_the_chain_is_broken(self, scan_row):
        """
        Integrity of the record store is a precondition. Issuing a certificate
        over a log that does not verify would certify the opposite of the truth.
        """
        from services.intel.db import get_db_connection
        conn = get_db_connection()
        conn.execute("UPDATE evidence_chain SET payload = '{\"tampered\":1}' WHERE seq = 1")
        conn.commit()
        conn.close()

        ok, reason = certificate.is_certifiable(scan_row[0])
        assert not ok and "fails verification" in reason

        cert = certificate.build_certificate(scan_row[0])
        assert cert["chain"]["valid"] is False
        assert "DOES NOT VERIFY" in cert["conditions"][2]["system_evidence"]

    def test_certifiable_when_everything_holds(self, scan_row):
        ok, reason = certificate.is_certifiable(scan_row[0])
        assert ok and reason is None

    def test_missing_artefact_is_reported_not_glossed(self, scan_row):
        """
        Part A states a hash. Restating a recorded value without re-deriving it
        from the bytes now present would certify something nobody checked.
        """
        cert = certificate.build_certificate(scan_row[0], artefact_path=None)
        recheck = cert["record"]["hash_recheck"]
        assert recheck["checked"] is False
        assert "not retained" in recheck["reason"]

    def test_recomputes_the_hash_when_the_artefact_is_present(self, scan_row, tmp_path):
        import hashlib
        blob = tmp_path / "artefact.bin"
        blob.write_bytes(b"the scanned bytes")
        digest = hashlib.sha256(b"the scanned bytes").hexdigest()

        result = certificate.verify_artefact_hash(str(blob), digest)
        assert result["checked"] is True and result["matches"] is True

    def test_a_changed_artefact_fails_the_recheck(self, scan_row, tmp_path):
        blob = tmp_path / "artefact.bin"
        blob.write_bytes(b"different bytes entirely")
        result = certificate.verify_artefact_hash(str(blob), "a" * 64)
        assert result["checked"] is True and result["matches"] is False
