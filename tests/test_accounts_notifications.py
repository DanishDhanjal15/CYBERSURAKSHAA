"""
Account security and notifications.

The properties tested here are mostly about *scope*: a session belongs to one
person and must die when revoked, a notification belongs to one recipient and
must not be readable or clearable by anyone else, and neither may be so noisy
that people stop reading them.
"""

import sqlite3

import pytest

from services.intel import accounts, notifications
from services.intel.db import get_db_connection


@pytest.fixture
def acct_db(temp_db):
    """
    Account tables on top of the shared temp database.

    `users` is created here because services/auth_db.py owns it in production;
    accounts.py only adds columns to it, and creating it in the fixture keeps
    that ownership boundary visible.
    """
    conn = sqlite3.connect(temp_db)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TEXT
        )
    """)
    conn.commit()
    conn.close()

    accounts.init_accounts_db()
    notifications.init_notifications_db()
    return temp_db


def make_user(username="analyst", password="correct-horse-battery", role="user"):
    from werkzeug.security import generate_password_hash
    conn = get_db_connection()
    cur = conn.execute(
        "INSERT INTO users (username, password_hash, role, created_at) VALUES (?,?,?,?)",
        (username, generate_password_hash(password), role, "2026-01-01 00:00:00"))
    conn.commit()
    uid = cur.lastrowid
    conn.close()
    return uid


# ══════════════════════════════════════════════════════════════════════════
# Sessions
# ══════════════════════════════════════════════════════════════════════════

class TestSessions:
    def test_a_new_session_validates(self, acct_db):
        uid = make_user()
        token = accounts.start_session(uid, "analyst", "Mozilla/5.0", "10.0.0.1")
        assert accounts.touch_session(token) is not None

    def test_the_raw_token_is_never_stored(self, acct_db):
        """
        A leaked database must not hand the reader a set of working session
        cookies — the same reasoning as the API keys.
        """
        uid = make_user()
        token = accounts.start_session(uid, "analyst")
        conn = get_db_connection()
        stored = {r["token_hash"] for r in conn.execute("SELECT token_hash FROM user_sessions")}
        conn.close()
        assert token not in stored
        assert all(len(h) == 64 for h in stored)

    def test_revoked_session_stops_validating(self, acct_db):
        """The whole point: a signed cookie alone could never be turned off."""
        uid = make_user()
        token = accounts.start_session(uid, "analyst")
        session_id = accounts.list_sessions(uid)[0]["id"]
        accounts.revoke_session(session_id)
        assert accounts.touch_session(token) is None

    def test_unknown_token_is_rejected(self, acct_db):
        assert accounts.touch_session("not-a-real-token") is None
        assert accounts.touch_session(None) is None
        assert accounts.touch_session("") is None

    def test_idle_session_expires_and_is_recorded(self, acct_db):
        """Expired rather than deleted, so it appears in the list with a reason."""
        uid = make_user()
        token = accounts.start_session(uid, "analyst")
        conn = get_db_connection()
        conn.execute("UPDATE user_sessions SET last_seen = '2020-01-01 00:00:00'")
        conn.commit()
        conn.close()

        assert accounts.touch_session(token) is None
        revoked = accounts.list_sessions(uid, include_revoked=True)
        assert revoked[0]["revoke_reason"] == "idle timeout"

    def test_revoke_all_spares_the_current_session(self, acct_db):
        """
        Logging yourself out as a side effect of securing your account is a
        surprise, and it discourages people from doing it at all.
        """
        uid = make_user()
        here = accounts.start_session(uid, "analyst")
        elsewhere = accounts.start_session(uid, "analyst")

        count = accounts.revoke_all(uid, except_token=here)
        assert count == 1
        assert accounts.touch_session(here) is not None
        assert accounts.touch_session(elsewhere) is None

    def test_revoke_all_without_exception_ends_everything(self, acct_db):
        uid = make_user()
        a = accounts.start_session(uid, "analyst")
        b = accounts.start_session(uid, "analyst")
        assert accounts.revoke_all(uid) == 2
        assert accounts.touch_session(a) is None
        assert accounts.touch_session(b) is None

    def test_sessions_are_scoped_to_their_owner(self, acct_db):
        alice = make_user("alice")
        bob = make_user("bob")
        accounts.start_session(alice, "alice")
        accounts.start_session(bob, "bob")
        assert len(accounts.list_sessions(alice)) == 1
        assert accounts.revoke_all(alice) == 1
        assert len(accounts.list_sessions(bob)) == 1

    def test_description_identifies_the_current_device(self, acct_db):
        uid = make_user()
        token = accounts.start_session(uid, "analyst",
                                       "Mozilla/5.0 (Windows NT 10.0) Chrome/120")
        row = accounts.list_sessions(uid)[0]
        described = accounts.describe_session(row, current_token=token)
        assert described["current"] is True
        assert "Chrome" in described["device"] and "Windows" in described["device"]

    def test_activity_write_is_throttled(self, acct_db):
        """
        Validation reads on every request. Writing the activity stamp that
        often would make session tracking the most expensive thing in a page
        load.
        """
        uid = make_user()
        token = accounts.start_session(uid, "analyst")
        before = accounts.list_sessions(uid)[0]["last_seen"]
        for _ in range(5):
            accounts.touch_session(token)
        assert accounts.list_sessions(uid)[0]["last_seen"] == before


# ══════════════════════════════════════════════════════════════════════════
# Passwords
# ══════════════════════════════════════════════════════════════════════════

class TestPasswordStrength:
    @pytest.mark.parametrize("pw", ["short", "1234567", "aaaaaaaaaa", "admin123"])
    def test_weak_passwords_are_refused(self, pw):
        ok, reason = accounts.check_password_strength(pw)
        assert not ok and reason

    def test_username_in_password_is_refused(self):
        ok, _ = accounts.check_password_strength("analyst-secret-99", username="analyst")
        assert not ok

    def test_a_long_passphrase_is_accepted(self):
        """Length is what resists guessing; a composition rule mostly yields 'Password1!'."""
        ok, reason = accounts.check_password_strength("correct horse battery staple")
        assert ok and reason is None


class TestPasswordChange:
    def test_changes_with_the_correct_current_password(self, acct_db):
        uid = make_user(password="old-password-here")
        ok, reason, _ = accounts.change_password(uid, "old-password-here",
                                                 "a-much-longer-new-one")
        assert ok and reason is None

    def test_wrong_current_password_is_refused(self, acct_db):
        """
        Without this, anyone holding a session cookie could take the account
        permanently by simply setting a new password.
        """
        uid = make_user(password="old-password-here")
        ok, reason, _ = accounts.change_password(uid, "guessing", "a-much-longer-new-one")
        assert not ok and "incorrect" in reason.lower()

    def test_reusing_the_same_password_is_refused(self, acct_db):
        uid = make_user(password="old-password-here")
        ok, reason, _ = accounts.change_password(uid, "old-password-here",
                                                 "old-password-here")
        assert not ok

    def test_changing_ends_other_sessions_by_default(self, acct_db):
        """The usual reason to change a password is thinking somebody else has it."""
        uid = make_user(password="old-password-here")
        here = accounts.start_session(uid, "analyst")
        stolen = accounts.start_session(uid, "analyst")

        ok, _, revoked = accounts.change_password(uid, "old-password-here",
                                                  "a-much-longer-new-one",
                                                  current_token=here)
        assert ok and revoked == 1
        assert accounts.touch_session(stolen) is None
        assert accounts.touch_session(here) is not None

    def test_other_sessions_can_be_kept_deliberately(self, acct_db):
        uid = make_user(password="old-password-here")
        other = accounts.start_session(uid, "analyst")
        ok, _, revoked = accounts.change_password(uid, "old-password-here",
                                                  "a-much-longer-new-one",
                                                  keep_other_sessions=True)
        assert ok and revoked == 0
        assert accounts.touch_session(other) is not None

    def test_admin_reset_forces_a_change_and_kills_every_session(self, acct_db):
        """
        An admin has no session of the user's to spare, and if the account was
        compromised the attacker's session must die with the old credential.
        """
        uid = make_user(password="old-password-here")
        accounts.start_session(uid, "analyst")
        accounts.start_session(uid, "analyst")

        ok, _, revoked = accounts.admin_reset_password(uid, "temporary-issued-value",
                                                       reset_by="admin")
        assert ok and revoked == 2
        assert accounts.must_change_password(uid) is True

    def test_overview_flags_a_never_changed_password(self, acct_db):
        uid = make_user()
        assert accounts.account_overview(uid)["password_never_changed"] is True
        accounts.change_password(uid, "correct-horse-battery", "a-much-longer-new-one")
        assert accounts.account_overview(uid)["password_never_changed"] is False


# ══════════════════════════════════════════════════════════════════════════
# Notifications
# ══════════════════════════════════════════════════════════════════════════

class TestNotifications:
    def test_delivers_to_the_recipient(self, acct_db):
        notifications.notify("analyst", notifications.EV_TARGET_DOWN, "evil.example is gone")
        assert notifications.unread_count("analyst") == 1
        assert notifications.unread_count("someone_else") == 0

    def test_never_notifies_someone_about_their_own_action(self, acct_db):
        """
        Telling people what they just did themselves is the fastest way to
        train them to ignore the bell.
        """
        notifications.notify("analyst", notifications.EV_FEEDBACK_CONFIRMED,
                             "Your correction was confirmed", actor="analyst")
        assert notifications.unread_count("analyst") == 0

    def test_repeats_inside_the_window_collapse(self, acct_db):
        """
        A sweep runs every six hours. A target that is still dead is not news
        again tomorrow.
        """
        for _ in range(4):
            notifications.notify("analyst", notifications.EV_TARGET_DOWN,
                                 "evil.example is gone",
                                 subject_type="target", subject_id=7)
        rows = notifications.for_user("analyst")
        assert len(rows) == 1
        assert rows[0]["repeat_count"] == 4

    def test_different_subjects_do_not_collapse(self, acct_db):
        notifications.notify("analyst", notifications.EV_TARGET_DOWN, "a gone",
                             subject_type="target", subject_id=1)
        notifications.notify("analyst", notifications.EV_TARGET_DOWN, "b gone",
                             subject_type="target", subject_id=2)
        assert len(notifications.for_user("analyst")) == 2

    def test_marking_read_is_scoped_to_the_recipient(self, acct_db):
        """One user must not be able to clear another's queue."""
        nid = notifications.notify("alice", notifications.EV_CASE_ASSIGNED, "Case CS-1")
        assert notifications.mark_read(nid, "bob") is False
        assert notifications.unread_count("alice") == 1
        assert notifications.mark_read(nid, "alice") is True
        assert notifications.unread_count("alice") == 0

    def test_for_user_never_returns_another_users_rows(self, acct_db):
        notifications.notify("alice", notifications.EV_CASE_ASSIGNED, "Alice's case")
        notifications.notify("bob", notifications.EV_CASE_ASSIGNED, "Bob's case")
        titles = {n["title"] for n in notifications.for_user("alice")}
        assert titles == {"Alice's case"}

    def test_mark_all_read_only_affects_the_caller(self, acct_db):
        notifications.notify("alice", notifications.EV_CASE_ASSIGNED, "one")
        notifications.notify("bob", notifications.EV_CASE_ASSIGNED, "two")
        assert notifications.mark_all_read("alice") == 1
        assert notifications.unread_count("bob") == 1

    def test_delivery_failure_never_raises(self, acct_db):
        """
        A notification that cannot be written must not fail the scan, sweep or
        review that triggered it.
        """
        assert notifications.notify(None, "X", "no recipient") is None

        class Unserialisable:
            def __repr__(self):
                raise RuntimeError("nope")

        result = notifications.notify("analyst", "X", "weird payload",
                                      payload={"bad": Unserialisable()})
        assert result is None or isinstance(result, int)

    def test_missing_recipient_is_dropped(self, acct_db):
        assert notifications.notify("", "X", "title") is None


class TestNotificationHooks:
    def test_target_went_dark_reaches_whoever_filed_it(self, acct_db):
        notifications.target_went_dark({
            "id": 1, "kind": "domain", "value": "evil.example",
            "channel": "REGISTRAR", "filed_by": "analyst",
            "filed_at": "2026-08-01 10:00:00",
        })
        rows = notifications.for_user("analyst")
        assert len(rows) == 1
        assert "evil.example" in rows[0]["title"]

    def test_a_target_with_no_filer_notifies_nobody(self, acct_db):
        """Registered outside the platform; there is nobody with standing."""
        assert notifications.target_went_dark(
            {"id": 1, "kind": "domain", "value": "x.example",
             "channel": "REGISTRAR", "filed_by": None}) is None

    def test_rebuild_alert_goes_to_the_people_who_worked_it(self, acct_db):
        notifications.operator_rebuilt(
            {"anchor_value": "kingbet@okaxis", "gap_days": 37,
             "summary": "came back", "anchor_id": 3},
            recipients=["alice", "bob"])
        assert notifications.unread_count("alice") == 1
        assert notifications.unread_count("bob") == 1

    def test_case_assignment_does_not_notify_the_assigner(self, acct_db):
        notifications.case_assigned({"id": 1, "ref": "CS-CASE-00001",
                                     "title": "Operation X", "severity": "HIGH"},
                                    assignee="alice", actor="alice")
        assert notifications.unread_count("alice") == 0

    def test_case_assignment_notifies_a_different_assignee(self, acct_db):
        notifications.case_assigned({"id": 1, "ref": "CS-CASE-00001",
                                     "title": "Operation X", "severity": "HIGH"},
                                    assignee="alice", actor="bob")
        assert notifications.unread_count("alice") == 1
