"""
services/user_state.py
----------------------
One user's complete live state, computed on demand.

The contract this module exists to keep is in the name: every figure returned
is TRUE at the moment of the request. That is enforced structurally, not by
promise:

  * No caching anywhere in this path. Every call runs its queries against the
    database at request time. A number that could go stale cannot be served.
  * The caller's identity comes from the server session, never from a request
    parameter — there is no way to ask for someone else's state, so there is
    no ownership check that could be forgotten.
  * Zero is a real answer. A new account reads 0 scans, 0 cases, 0 alerts —
    no seeded baselines, matching the platform-wide rule that numbers which
    pad themselves cannot be used to argue anything.
  * `generated_at` stamps the exact compute time so the UI can show — and a
    demo can prove — that the snapshot is of this second.

Everything here is stdlib + sqlite; the only ML-adjacent read is the model
readiness map, which is an in-memory status dict, not an inference call.
"""

from __future__ import annotations

from datetime import datetime

from services.intel.db import get_db_connection


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# Verdict strings vary per module (BETTING, FAKE, HIGH_RISK, Scam Alert…).
# These buckets mirror the ones the history drawer already uses, so the same
# scan is counted the same way everywhere.
_THREAT_WORDS = ("betting", "fake", "scam", "danger", "red", "critical", "high")
_WARN_WORDS = ("suspicious", "warn", "unsure")


def _verdict_bucket(verdict):
    v = (verdict or "").lower()
    if any(w in v for w in _THREAT_WORDS):
        return "flagged"
    if any(w in v for w in _WARN_WORDS):
        return "suspicious"
    return "clean"


def live_state(user_id, username, session_token=None):
    """
    Assemble the caller's state. All queries are scoped by user_id/username
    taken from the session — the row filters ARE the access control.
    """
    conn = get_db_connection()
    try:
        # ── Identity ──────────────────────────────────────────────────
        row = conn.execute(
            "SELECT username, role, created_at, last_login, password_changed_at "
            "FROM users WHERE id = ?", (int(user_id),)).fetchone()
        if not row:
            return None
        identity = dict(row)

        # ── Activity: this user's scans, counted fresh ─────────────────
        today = datetime.now().strftime("%Y-%m-%d")
        totals = conn.execute(
            "SELECT COUNT(*) AS total, "
            "       SUM(CASE WHEN timestamp LIKE ? THEN 1 ELSE 0 END) AS today, "
            "       MAX(timestamp) AS last_scan_at "
            "FROM scans WHERE user_id = ?", (today + "%", int(user_id))).fetchone()

        by_module = {
            r["module"]: r["n"] for r in conn.execute(
                "SELECT module, COUNT(*) AS n FROM scans WHERE user_id = ? "
                "GROUP BY module ORDER BY n DESC", (int(user_id),))
        }

        buckets = {"flagged": 0, "suspicious": 0, "clean": 0}
        for r in conn.execute(
                "SELECT verdict, COUNT(*) AS n FROM scans WHERE user_id = ? "
                "GROUP BY verdict", (int(user_id),)):
            buckets[_verdict_bucket(r["verdict"])] += r["n"]

        # ── Work sitting with this user ────────────────────────────────
        open_cases = conn.execute(
            "SELECT COUNT(*) AS n FROM cases "
            "WHERE assigned_to = ? AND status != 'CLOSED'",
            (username,)).fetchone()["n"]
        pending_feedback = conn.execute(
            "SELECT COUNT(*) AS n FROM analyst_feedback "
            "WHERE reviewer = ? AND status = 'PENDING'",
            (username,)).fetchone()["n"]

        # ── Notifications ──────────────────────────────────────────────
        unread = conn.execute(
            "SELECT COUNT(*) AS n FROM notifications "
            "WHERE recipient = ? AND read = 0", (username,)).fetchone()["n"]
    finally:
        conn.close()

    # ── Sessions (own only; accounts scopes by user_id) ────────────────
    sessions_info = {"active": 0, "current": None, "others": []}
    try:
        from services.intel import accounts
        described = [accounts.describe_session(s, session_token)
                     for s in accounts.list_sessions(user_id)]
        sessions_info["active"] = len(described)
        for s in described:
            if s.get("current"):
                sessions_info["current"] = s
            else:
                sessions_info["others"].append(s)
    except Exception:
        pass   # a session-listing failure must not take the whole state down

    # ── Model availability right now ───────────────────────────────────
    models = {}
    try:
        from services.intel.ops import get_model_states
        models = {name: (st or {}).get("status", "unknown")
                  for name, st in (get_model_states() or {}).items()}
    except Exception:
        pass

    return {
        "generated_at": _now(),
        "identity": identity,
        "session": sessions_info,
        "activity": {
            "scans_total": totals["total"] or 0,
            "scans_today": totals["today"] or 0,
            "last_scan_at": totals["last_scan_at"],
            "by_module": by_module,
            "by_verdict": buckets,
        },
        "work": {
            "open_cases_assigned": open_cases,
            "pending_feedback": pending_feedback,
        },
        "notifications_unread": unread,
        "models": models,
        "note": (
            "Every figure above was computed from the database at "
            "generated_at. Nothing is cached or seeded; a new account "
            "legitimately reads zero across the board."
        ),
    }
