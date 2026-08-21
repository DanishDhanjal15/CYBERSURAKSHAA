"""
services/intel/evidence.py
--------------------------
Tamper-evident audit log and public evidence verification.

The platform already hashes every artefact it scans. That proves *what* was
scanned but nothing about whether the record of the scan was altered
afterwards -- and an evidence trail that anyone with database access can
silently rewrite is not evidence.

This module maintains an append-only log in which each entry commits to the one
before it:

    entry_hash = SHA256( seq | timestamp | event | actor | payload_hash | prev_hash )

Changing any historical entry changes its hash, which breaks every subsequent
link. Verification is a linear re-walk, so tampering is detectable even though
it is not prevented -- which is the honest guarantee. This is a hash chain, not
a distributed ledger and not a digital signature: it demonstrates internal
consistency, and it does not by itself prove the log was not rewritten wholesale
by someone with write access to the entire table. Where a stronger guarantee is
required, the head hash should be periodically published somewhere the operator
does not control. `head()` exists for exactly that purpose.

The public verification endpoint (/verify/<hash>) lets anyone holding a
generated report confirm that its evidence hash matches a real scan and that
the chain around it is intact, without logging in.
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime

from services.intel.db import get_db_connection

GENESIS_HASH = "0" * 64

# Serialises appends within one process. The chain requires that each entry
# reads the true current head; two threads reading the same head would produce
# two entries claiming the same predecessor and break verification. Cross-
# process safety comes from the IMMEDIATE transaction in _append_locked.
_chain_lock = threading.Lock()

# Event types
EV_SCAN = "SCAN"
EV_REPORT = "REPORT_GENERATED"
EV_TAKEDOWN = "TAKEDOWN_GENERATED"
EV_ACTION_PACK = "ACTION_PACK_GENERATED"
EV_CASE_CREATE = "CASE_CREATED"
EV_CASE_UPDATE = "CASE_UPDATED"
EV_ALERT_BLOCK = "ALERT_BLOCKED"
EV_FEEDBACK = "ANALYST_FEEDBACK"
EV_LOGIN = "LOGIN"
EV_ADMIN = "ADMIN_ACTION"


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def init_evidence_db():
    """Create the evidence chain table. Idempotent."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS evidence_chain (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            seq          INTEGER NOT NULL UNIQUE,
            timestamp    TEXT NOT NULL,
            event        TEXT NOT NULL,
            actor        TEXT,
            subject_type TEXT,
            subject_id   TEXT,
            artefact_hash TEXT,
            payload      TEXT NOT NULL,
            payload_hash TEXT NOT NULL,
            prev_hash    TEXT NOT NULL,
            entry_hash   TEXT NOT NULL
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_chain_seq ON evidence_chain(seq)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_chain_artefact ON evidence_chain(artefact_hash)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_chain_subject ON evidence_chain(subject_type, subject_id)")
    conn.commit()
    conn.close()


def _compute_entry_hash(seq, timestamp, event, actor, payload_hash, prev_hash):
    material = "|".join([
        str(seq), timestamp or "", event or "", actor or "",
        payload_hash or "", prev_hash or "",
    ])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def append_event(event, actor=None, subject_type=None, subject_id=None,
                 artefact_hash=None, payload=None):
    """
    Append one entry to the chain and return it.

    Never raises: audit logging must not be able to fail a user's request. A
    failure is reported on stderr and returns None, which callers treat as
    "unlogged" rather than "failed".
    """
    try:
        with _chain_lock:
            return _append_locked(event, actor, subject_type, subject_id,
                                  artefact_hash, payload)
    except Exception as e:
        print("[EVIDENCE] append failed: %s" % e)
        return None


def _append_locked(event, actor, subject_type, subject_id, artefact_hash, payload):
    payload = payload or {}
    payload_json = json.dumps(payload, sort_keys=True, default=str)
    payload_hash = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
    timestamp = _now()

    conn = get_db_connection()
    try:
        # BEGIN IMMEDIATE takes the write lock up front, so a concurrent
        # appender in another process blocks here rather than reading the same
        # head and forking the chain.
        conn.execute("BEGIN IMMEDIATE")
        cur = conn.cursor()
        cur.execute("SELECT seq, entry_hash FROM evidence_chain ORDER BY seq DESC LIMIT 1")
        row = cur.fetchone()
        seq = (row["seq"] + 1) if row else 1
        prev_hash = row["entry_hash"] if row else GENESIS_HASH

        entry_hash = _compute_entry_hash(seq, timestamp, event, actor, payload_hash, prev_hash)

        cur.execute("""
            INSERT INTO evidence_chain
                (seq, timestamp, event, actor, subject_type, subject_id,
                 artefact_hash, payload, payload_hash, prev_hash, entry_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (seq, timestamp, event, actor, subject_type,
              str(subject_id) if subject_id is not None else None,
              artefact_hash, payload_json, payload_hash, prev_hash, entry_hash))
        conn.commit()
        return {
            "seq": seq, "timestamp": timestamp, "event": event,
            "entry_hash": entry_hash, "prev_hash": prev_hash,
        }
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def verify_chain(limit=None):
    """
    Re-walk the chain and confirm every link.

    Returns a dict with `valid`, the number of entries checked, and -- when a
    break is found -- the sequence number and the reason. Stops at the first
    break: everything after it is untrustworthy anyway, and reporting a
    thousand consequential failures obscures the one that matters.
    """
    conn = get_db_connection()
    cur = conn.cursor()
    if limit:
        cur.execute("SELECT * FROM evidence_chain ORDER BY seq ASC LIMIT ?", (int(limit),))
    else:
        cur.execute("SELECT * FROM evidence_chain ORDER BY seq ASC")
    rows = cur.fetchall()
    conn.close()

    prev_hash = GENESIS_HASH
    expected_seq = 1
    checked = 0

    for row in rows:
        if row["seq"] != expected_seq:
            return {"valid": False, "checked": checked, "broken_at": row["seq"],
                    "reason": "sequence gap: expected %d, found %d" % (expected_seq, row["seq"])}
        if row["prev_hash"] != prev_hash:
            return {"valid": False, "checked": checked, "broken_at": row["seq"],
                    "reason": "predecessor hash mismatch"}

        payload_hash = hashlib.sha256((row["payload"] or "").encode("utf-8")).hexdigest()
        if payload_hash != row["payload_hash"]:
            return {"valid": False, "checked": checked, "broken_at": row["seq"],
                    "reason": "payload was modified after it was recorded"}

        recomputed = _compute_entry_hash(
            row["seq"], row["timestamp"], row["event"], row["actor"],
            row["payload_hash"], row["prev_hash"],
        )
        if recomputed != row["entry_hash"]:
            return {"valid": False, "checked": checked, "broken_at": row["seq"],
                    "reason": "entry hash does not match its contents"}

        prev_hash = row["entry_hash"]
        expected_seq += 1
        checked += 1

    return {"valid": True, "checked": checked, "head": prev_hash}


def head():
    """
    The current chain head.

    Publish this somewhere outside the operator's control (a public repository,
    a timestamping service) to convert the chain's internal-consistency
    guarantee into an external one.
    """
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT seq, entry_hash, timestamp FROM evidence_chain ORDER BY seq DESC LIMIT 1")
    row = cur.fetchone()
    conn.close()
    if not row:
        return {"seq": 0, "entry_hash": GENESIS_HASH, "timestamp": None}
    return {"seq": row["seq"], "entry_hash": row["entry_hash"], "timestamp": row["timestamp"]}


def lookup_artefact(artefact_hash):
    """
    Public verification: does this evidence hash correspond to a real scan?

    Returns a deliberately minimal record. This endpoint is unauthenticated, so
    it confirms existence, integrity and classification without disclosing the
    scanned content, the submitting user, or any extracted personal data.
    """
    if not artefact_hash or len(artefact_hash) != 64:
        return None
    h = artefact_hash.lower().strip()

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, timestamp, module, verdict, score
        FROM scans WHERE LOWER(file_hash) = ? ORDER BY id ASC LIMIT 1
    """, (h,))
    scan = cur.fetchone()

    cur.execute("""
        SELECT seq, timestamp, event, entry_hash
        FROM evidence_chain WHERE LOWER(artefact_hash) = ? ORDER BY seq ASC
    """, (h,))
    entries = [dict(r) for r in cur.fetchall()]
    conn.close()

    if not scan and not entries:
        return None

    chain = verify_chain()
    return {
        "artefact_hash": h,
        "found": True,
        "scan": {
            "id": scan["id"],
            "timestamp": scan["timestamp"],
            "module": scan["module"],
            "verdict": scan["verdict"],
            "score": scan["score"],
        } if scan else None,
        "chain_entries": entries,
        "chain_valid": chain["valid"],
        "chain_length": chain["checked"],
        "chain_head": chain.get("head"),
    }


def recent_entries(limit=50):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT seq, timestamp, event, actor, subject_type, subject_id,
               artefact_hash, entry_hash
        FROM evidence_chain ORDER BY seq DESC LIMIT ?
    """, (int(limit),))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


# -- QR codes --------------------------------------------------------------

def qr_svg(data, size=110):
    """
    Render `data` as an inline SVG QR code.

    Uses ReportLab's barcode widget, which is already a dependency for the PDF
    reports -- no new package, and the same code path works for both the PDF
    and the HTML report. Returns None if ReportLab is unavailable so callers
    can omit the QR rather than fail the report.
    """
    try:
        from reportlab.graphics.barcode import qr
        from reportlab.graphics.shapes import Drawing
        from reportlab.graphics import renderSVG
        import io

        widget = qr.QrCodeWidget(data)
        bounds = widget.getBounds()
        w = bounds[2] - bounds[0]
        h = bounds[3] - bounds[1]
        d = Drawing(size, size, transform=[size / w, 0, 0, size / h, 0, 0])
        d.add(widget)
        buf = io.StringIO()
        renderSVG.drawToFile(d, buf)
        svg = buf.getvalue()
        # Strip the XML prolog and DOCTYPE so the fragment can be inlined
        # directly into an HTML document.
        idx = svg.find("<svg")
        return svg[idx:] if idx != -1 else svg
    except Exception as e:
        print("[EVIDENCE] QR generation unavailable: %s" % e)
        return None


def qr_drawing(data, size=70):
    """ReportLab Drawing for embedding a QR code in a generated PDF."""
    try:
        from reportlab.graphics.barcode import qr
        from reportlab.graphics.shapes import Drawing

        widget = qr.QrCodeWidget(data)
        bounds = widget.getBounds()
        w = bounds[2] - bounds[0]
        h = bounds[3] - bounds[1]
        d = Drawing(size, size, transform=[size / w, 0, 0, size / h, 0, 0])
        d.add(widget)
        return d
    except Exception as e:
        print("[EVIDENCE] QR drawing unavailable: %s" % e)
        return None


def verification_url(base_url, artefact_hash):
    """Canonical public verification URL for an artefact hash."""
    return "%s/verify/%s" % ((base_url or "").rstrip("/"), artefact_hash)
