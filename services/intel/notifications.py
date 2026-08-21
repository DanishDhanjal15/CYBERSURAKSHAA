"""
services/intel/notifications.py
-------------------------------
Telling people what the platform found out.

Why this is not decoration
==========================
The lifecycle modules changed what the system knows. `takedown.py` learns that
a reported domain went dark. `resurrection.py` learns that an operator rebuilt
on the same payment rail. `feedback.py` learns that a correction was confirmed.

Every one of those was landing in a table nobody was watching. Detection that
nobody is told about is detection that changes no decision — the analyst who
filed the notice three weeks ago has no reason to open that page today, which
is exactly when the thing they care about happened.

So this module exists to close the last gap in the loop: from *the system
learned something* to *the person who can act on it knows*.

Design constraints
==================
**Notify the person with standing, not everyone.** A notification stream
everybody receives is one nobody reads. Events route to whoever filed the
notice, owns the case, or made the correction; admins receive the
system-level ones and nothing else.

**Never notify someone about their own action.** Confirming your own
correction, closing your own case — you were there. Self-notification is the
fastest way to train people to ignore the bell.

**Deduplicate.** A sweep that finds the same target still dead must not
produce a notification every six hours. Events carry a dedupe key, and a
repeat inside the window updates the existing row instead of adding one.

**Failure is silent by design.** `notify()` never raises. A notification that
cannot be written must not fail the scan, sweep or review that triggered it —
the underlying work matters more than the announcement of it.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta

from services.intel.db import get_db_connection

# Event kinds. Each maps to an icon and a colour in the UI.
EV_TARGET_DOWN = "TARGET_WENT_DARK"
EV_TARGET_BACK = "TARGET_RESURFACED"
EV_RESURRECTION = "OPERATOR_REBUILT"
EV_CT_HIT = "LOOKALIKE_ISSUED"
EV_FEEDBACK_CONFIRMED = "FEEDBACK_CONFIRMED"
EV_FEEDBACK_REJECTED = "FEEDBACK_REJECTED"
EV_CASE_ASSIGNED = "CASE_ASSIGNED"
EV_CASE_UPDATED = "CASE_UPDATED"
EV_REVIEW_WAITING = "REVIEW_WAITING"
EV_CHAIN_BROKEN = "EVIDENCE_CHAIN_BROKEN"
EV_FEED_DOWN = "FEED_UNREACHABLE"

# Severity drives ordering and colour, not urgency of delivery.
SEV_INFO = "INFO"
SEV_GOOD = "GOOD"
SEV_WARN = "WARN"
SEV_CRITICAL = "CRITICAL"

# Repeat suppression window. A sweep runs every six hours; a target that is
# still dead is not news again tomorrow either.
DEDUPE_WINDOW_HOURS = 72

# Notifications older than this are pruned. They are a working queue, not a
# record -- the evidence chain is the record.
RETAIN_DAYS = 90


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def init_notifications_db():
    """Create the notification table. Idempotent."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient    TEXT NOT NULL,
            event        TEXT NOT NULL,
            severity     TEXT NOT NULL DEFAULT 'INFO',
            title        TEXT NOT NULL,
            body         TEXT,
            link         TEXT,
            subject_type TEXT,
            subject_id   TEXT,
            dedupe_key   TEXT,
            payload      TEXT,
            read         INTEGER NOT NULL DEFAULT 0,
            created_at   TEXT NOT NULL,
            updated_at   TEXT NOT NULL,
            repeat_count INTEGER NOT NULL DEFAULT 1
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_notif_recipient ON notifications(recipient, read)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_notif_created ON notifications(created_at DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_notif_dedupe ON notifications(dedupe_key)")
    conn.commit()
    conn.close()


# ── Creation ──────────────────────────────────────────────────────────────

def notify(recipient, event, title, body=None, severity=SEV_INFO, link=None,
           subject_type=None, subject_id=None, dedupe_key=None, payload=None,
           actor=None):
    """
    Deliver one notification.

    `actor` is who caused the event. When it matches the recipient the
    notification is dropped — telling somebody what they just did themselves
    is how a notification bell becomes noise people learn to ignore.

    Never raises. A failure here must not fail the work that triggered it.
    """
    try:
        if not recipient:
            return None
        if actor and actor == recipient:
            return None

        key = dedupe_key or "%s:%s:%s" % (event, subject_type or "", subject_id or "")
        cutoff = (datetime.now() - timedelta(hours=DEDUPE_WINDOW_HOURS)
                  ).strftime("%Y-%m-%d %H:%M:%S")

        conn = get_db_connection()
        try:
            existing = conn.execute("""
                SELECT id, repeat_count FROM notifications
                WHERE recipient = ? AND dedupe_key = ? AND created_at >= ?
                ORDER BY id DESC LIMIT 1
            """, (recipient, key, cutoff)).fetchone()

            if existing:
                # Same thing again inside the window: bump the counter and the
                # timestamp rather than stacking identical rows.
                conn.execute("""
                    UPDATE notifications
                    SET repeat_count = repeat_count + 1, updated_at = ?, read = 0
                    WHERE id = ?
                """, (_now(), existing["id"]))
                conn.commit()
                return existing["id"]

            cur = conn.execute("""
                INSERT INTO notifications
                    (recipient, event, severity, title, body, link,
                     subject_type, subject_id, dedupe_key, payload,
                     created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (recipient, event, severity, title, body, link,
                  subject_type, str(subject_id) if subject_id is not None else None,
                  key, json.dumps(payload or {}, default=str), _now(), _now()))
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()
    except Exception as e:
        print("[NOTIFY] could not deliver %r to %r: %s" % (event, recipient, e))
        return None


def notify_admins(event, title, body=None, severity=SEV_WARN, link=None,
                  subject_type=None, subject_id=None, dedupe_key=None,
                  actor=None):
    """
    System-level events, to everyone who can act on them.

    Used sparingly: a broken evidence chain, an unreachable feed. Anything
    case-specific goes to the person with standing instead.
    """
    try:
        # Read through this module's own connection rather than auth_db's, so
        # notification routing cannot end up querying a different database
        # from the one the notifications are written to.
        conn = get_db_connection()
        try:
            admins = [r["username"] for r in conn.execute(
                "SELECT username FROM users WHERE role = 'admin'").fetchall()]
        finally:
            conn.close()
    except Exception as e:
        print("[NOTIFY] could not resolve administrators: %s" % e)
        return []
    return [notify(a, event, title, body=body, severity=severity, link=link,
                   subject_type=subject_type, subject_id=subject_id,
                   dedupe_key=dedupe_key, actor=actor)
            for a in admins]


# ── Reading ───────────────────────────────────────────────────────────────

def for_user(username, unread_only=False, limit=50):
    sql = "SELECT * FROM notifications WHERE recipient = ?"
    params = [username]
    if unread_only:
        sql += " AND read = 0"
    sql += " ORDER BY read ASC, updated_at DESC LIMIT ?"
    params.append(int(limit))

    conn = get_db_connection()
    rows = []
    for r in conn.execute(sql, params).fetchall():
        d = dict(r)
        try:
            d["payload"] = json.loads(d["payload"] or "{}")
        except (ValueError, TypeError):
            d["payload"] = {}
        rows.append(d)
    conn.close()
    return rows


def unread_count(username):
    conn = get_db_connection()
    row = conn.execute(
        "SELECT COUNT(*) AS n FROM notifications WHERE recipient = ? AND read = 0",
        (username,)).fetchone()
    conn.close()
    return row["n"] if row else 0


def mark_read(notification_id, username):
    """Scoped to the recipient, so one user cannot clear another's queue."""
    conn = get_db_connection()
    try:
        cur = conn.execute(
            "UPDATE notifications SET read = 1 WHERE id = ? AND recipient = ?",
            (int(notification_id), username))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def mark_all_read(username):
    conn = get_db_connection()
    try:
        cur = conn.execute(
            "UPDATE notifications SET read = 1 WHERE recipient = ? AND read = 0",
            (username,))
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


def prune(days=RETAIN_DAYS):
    """Drop old notifications. The evidence chain is the record; this is a queue."""
    cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db_connection()
    try:
        cur = conn.execute("DELETE FROM notifications WHERE created_at < ? AND read = 1",
                           (cutoff,))
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


# ── Event hooks ───────────────────────────────────────────────────────────
#
# Called by the modules that learn something. Kept here rather than inline at
# the call sites so the routing rules -- who has standing to hear about what --
# are visible in one place instead of scattered across five modules.

def target_went_dark(target):
    """A reported domain or URL stopped resolving."""
    return notify(
        recipient=target.get("filed_by"),
        event=EV_TARGET_DOWN, severity=SEV_GOOD,
        title="%s is no longer reachable" % target.get("value"),
        body=("The %s you reported to %s on %s has stopped resolving. Worth "
              "confirming before you close the case — a domain can also go "
              "dark because the operator moved on."
              % (target.get("kind"), target.get("channel"),
                 (target.get("filed_at") or "")[:10])),
        link="/watchtower/#pane-td",
        subject_type="enforcement_target", subject_id=target.get("id"),
    )


def target_resurfaced(target):
    """Something previously dead is answering again."""
    return notify(
        recipient=target.get("filed_by"),
        event=EV_TARGET_BACK, severity=SEV_WARN,
        title="%s is back up" % target.get("value"),
        body=("This %s went dark after you reported it and is now resolving "
              "again. Either the suspension was lifted or the name was "
              "re-registered." % target.get("kind")),
        link="/watchtower/#pane-td",
        subject_type="enforcement_target", subject_id=target.get("id"),
    )


def operator_rebuilt(event, recipients):
    """
    A durable anchor went quiet and came back with new infrastructure.

    Routed to whoever worked the original campaign — the people who filed
    against this anchor, or own a case containing it. Falls back to admins
    only when nobody has that standing, because an unrouted alert reaching
    nobody is worse than one reaching a wider group.
    """
    title = "%s resurfaced after %d days" % (event.get("anchor_value"),
                                             round(event.get("gap_days") or 0))
    body = event.get("summary")
    if recipients:
        return [notify(r, EV_RESURRECTION, title, body=body, severity=SEV_CRITICAL,
                       link="/watchtower/#pane-res",
                       subject_type="resurrection_event",
                       subject_id=event.get("anchor_id"))
                for r in recipients]
    return notify_admins(EV_RESURRECTION, title, body=body, severity=SEV_CRITICAL,
                         link="/watchtower/#pane-res",
                         subject_type="resurrection_event",
                         subject_id=event.get("anchor_id"))


def feedback_reviewed(row, status, reviewer):
    """An analyst's correction was adjudicated by somebody else."""
    confirmed = status == "CONFIRMED"
    return notify(
        recipient=row.get("reviewer"), actor=reviewer,
        event=EV_FEEDBACK_CONFIRMED if confirmed else EV_FEEDBACK_REJECTED,
        severity=SEV_GOOD if confirmed else SEV_INFO,
        title=("Your correction was confirmed" if confirmed
               else "Your correction was not upheld"),
        body=("%s reviewed your %s on the %s verdict. %s"
              % (reviewer, (row.get("label") or "").replace("_", " ").lower(),
                 row.get("module"),
                 "It now counts as a training label and enters the confusion matrix."
                 if confirmed else
                 "It stays on record but does not become a label.")),
        link="/intel/feedback",
        subject_type="feedback", subject_id=row.get("id"),
    )


def case_assigned(case, assignee, actor):
    return notify(
        recipient=assignee, actor=actor,
        event=EV_CASE_ASSIGNED, severity=SEV_WARN,
        title="Case %s assigned to you" % (case.get("ref") or case.get("id")),
        body="%s — severity %s. Assigned by %s."
             % (case.get("title"), case.get("severity"), actor or "an administrator"),
        link="/intel/cases",
        subject_type="case", subject_id=case.get("id"),
    )


def review_waiting(feedback_row, actor):
    """
    A correction needs a second opinion.

    Goes to admins because adjudication is admin-only, and never to its
    author — a correction cannot be confirmed by the person who filed it.
    """
    return notify_admins(
        EV_REVIEW_WAITING, "A correction is waiting for review",
        body="%s marked a %s verdict as %s. It needs a second analyst before "
             "it counts as a label."
             % (feedback_row.get("reviewer"), feedback_row.get("module"),
                (feedback_row.get("label") or "").replace("_", " ").lower()),
        severity=SEV_INFO, link="/intel/feedback",
        subject_type="feedback", subject_id=feedback_row.get("id"),
        actor=actor,
    )


def chain_broken(result):
    """The evidence chain failed verification. Nothing outranks this."""
    return notify_admins(
        EV_CHAIN_BROKEN, "Evidence chain verification FAILED",
        body=("The audit chain does not re-walk cleanly. Broken at sequence "
              "%s: %s. Entries recorded after that point cannot be relied on, "
              "and any document derived from them should be treated as "
              "unverified pending investigation."
              % (result.get("broken_at"), result.get("reason"))),
        severity=SEV_CRITICAL, link="/admin/audit",
        subject_type="evidence_chain", subject_id=result.get("broken_at"),
        dedupe_key="chain_broken:%s" % result.get("broken_at"),
    )


def feed_unreachable(source, detail=None):
    """
    An upstream feed is down.

    Notified because the failure is silent by nature: the observation list
    simply stops growing, which looks identical to a quiet day.
    """
    return notify_admins(
        EV_FEED_DOWN, "%s is unreachable" % source,
        body=("Discovery through %s is degraded%s. An empty observation list "
              "right now means the feed is down, not that nothing was issued."
              % (source, " (%s)" % detail if detail else "")),
        severity=SEV_WARN, link="/watchtower/",
        subject_type="feed", subject_id=source,
        dedupe_key="feed_down:%s" % source,
    )
