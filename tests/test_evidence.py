"""
Tamper-evident evidence chain.

The chain's only claim is that a silent edit is detectable. A test suite that
only appends and verifies would never exercise that claim, so the important
tests here modify the database behind the module's back and assert that
verification notices.
"""

import sqlite3

from services.intel import evidence


def _raw(temp_db):
    conn = sqlite3.connect(temp_db)
    conn.row_factory = sqlite3.Row
    return conn


class TestAppend:
    def test_first_entry_links_to_genesis(self, temp_db):
        e = evidence.append_event(evidence.EV_SCAN, actor="tester",
                                  payload={"module": "test"})
        assert e["seq"] == 1
        assert e["prev_hash"] == evidence.GENESIS_HASH

    def test_entries_chain(self, temp_db):
        a = evidence.append_event(evidence.EV_SCAN, actor="a")
        b = evidence.append_event(evidence.EV_REPORT, actor="b")
        assert b["prev_hash"] == a["entry_hash"]
        assert b["seq"] == a["seq"] + 1

    def test_append_never_raises_on_unserialisable_payload(self, temp_db):
        """
        Audit logging must not be able to fail a user's request. A payload the
        JSON encoder cannot handle is logged best-effort or dropped; either
        way the exception does not reach the scan that was being recorded.
        """
        class Unserialisable:
            def __repr__(self):
                raise RuntimeError("even repr fails")

        result = evidence.append_event(evidence.EV_SCAN, actor="t",
                                       payload={"bad": Unserialisable()})
        assert result is None or "entry_hash" in result


class TestVerification:
    def test_clean_chain_verifies(self, temp_db):
        for i in range(10):
            evidence.append_event(evidence.EV_SCAN, actor="t", payload={"i": i})
        result = evidence.verify_chain()
        assert result["valid"] is True
        assert result["checked"] == 10

    def test_empty_chain_verifies(self, temp_db):
        assert evidence.verify_chain()["valid"] is True

    def test_edited_payload_is_detected(self, temp_db):
        """The whole point of the module, in one test."""
        for i in range(5):
            evidence.append_event(evidence.EV_SCAN, actor="t", payload={"i": i})

        conn = _raw(temp_db)
        conn.execute(
            "UPDATE evidence_chain SET payload = ? WHERE seq = 3",
            ('{"i": 999}',))
        conn.commit()
        conn.close()

        result = evidence.verify_chain()
        assert result["valid"] is False
        assert result["broken_at"] == 3
        assert "payload" in result["reason"]

    def test_deleted_entry_is_detected(self, temp_db):
        for i in range(5):
            evidence.append_event(evidence.EV_SCAN, actor="t", payload={"i": i})

        conn = _raw(temp_db)
        conn.execute("DELETE FROM evidence_chain WHERE seq = 3")
        conn.commit()
        conn.close()

        result = evidence.verify_chain()
        assert result["valid"] is False
        assert "sequence gap" in result["reason"]

    def test_changed_actor_is_detected(self, temp_db):
        """
        Rewriting who performed an action is exactly the tampering an audit log
        exists to prevent, and the actor is inside the hashed material.
        """
        evidence.append_event(evidence.EV_ADMIN, actor="officer_a")
        evidence.append_event(evidence.EV_ADMIN, actor="officer_b")

        conn = _raw(temp_db)
        conn.execute("UPDATE evidence_chain SET actor = 'someone_else' WHERE seq = 1")
        conn.commit()
        conn.close()

        result = evidence.verify_chain()
        assert result["valid"] is False
        assert result["broken_at"] == 1

    def test_reordered_entries_are_detected(self, temp_db):
        evidence.append_event(evidence.EV_SCAN, actor="t", payload={"i": 1})
        evidence.append_event(evidence.EV_SCAN, actor="t", payload={"i": 2})

        conn = _raw(temp_db)
        conn.execute("UPDATE evidence_chain SET seq = 99 WHERE seq = 2")
        conn.commit()
        conn.close()

        assert evidence.verify_chain()["valid"] is False


class TestHead:
    def test_head_of_empty_chain(self, temp_db):
        h = evidence.head()
        assert h["seq"] == 0
        assert h["entry_hash"] == evidence.GENESIS_HASH

    def test_head_tracks_last_entry(self, temp_db):
        evidence.append_event(evidence.EV_SCAN, actor="t")
        last = evidence.append_event(evidence.EV_SCAN, actor="t")
        assert evidence.head()["entry_hash"] == last["entry_hash"]


class TestPublicLookup:
    def test_unknown_hash_returns_none(self, temp_db):
        assert evidence.lookup_artefact("a" * 64) is None

    def test_partial_hash_is_rejected_not_prefix_matched(self, temp_db):
        """
        A prefix match would turn the public endpoint into an enumeration
        oracle: an attacker could walk the hash space a nibble at a time.
        """
        h = "b" * 64
        evidence.append_event(evidence.EV_SCAN, actor="t", artefact_hash=h)
        assert evidence.lookup_artefact("b" * 10) is None
        assert evidence.lookup_artefact(h) is not None

    def test_lookup_is_case_insensitive(self, temp_db):
        h = "c" * 64
        evidence.append_event(evidence.EV_SCAN, actor="t", artefact_hash=h)
        assert evidence.lookup_artefact(h.upper()) is not None

    def test_lookup_does_not_leak_content(self, temp_db):
        """
        /verify is unauthenticated. It confirms existence and integrity; it
        must not disclose the scanned text, the submitting user, or any
        extracted personal data.
        """
        h = "d" * 64
        evidence.append_event(evidence.EV_SCAN, actor="secret_officer",
                              artefact_hash=h,
                              payload={"text": "victim phone 9876543210"})
        record = evidence.lookup_artefact(h)
        blob = repr(record)
        assert "9876543210" not in blob
        assert "secret_officer" not in blob
        assert "victim" not in blob
