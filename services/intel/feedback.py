"""
services/intel/feedback.py
--------------------------
Analyst feedback loop.

Every detector in this platform emits a verdict and then forgets about it.
Nothing in the system has ever been able to answer the only question that
matters after deployment -- *how often is it wrong, and wrong in which
direction* -- because no one ever recorded a correction.

This module closes that loop:

    1. An analyst marks a verdict wrong (or right) from the results panel.
    2. The correction lands in a review queue, tied to the scan and to the
       evidence chain, with the reviewer's identity and the timestamp.
    3. `training_export()` turns confirmed corrections into labelled rows.
    4. `metrics()` computes the confusion matrix the modules never had, and
       `calibration_samples()` produces exactly the (score, label) pairs
       services/intel/calibration.py needs to fit a real calibrator.

Step 4 is the point of the whole thing. Until a module has labelled feedback,
`calibration.assess()` reports `calibrated: false` and the UI says the
confidence figure is a raw score. Feedback is what eventually makes that
sentence untrue.

Two deliberate constraints:

* A correction is a claim by one analyst, not ground truth. Rows carry the
  reviewer and are exported at a confidence level the caller chooses; nothing
  here silently promotes one person's opinion into a label.
* Feedback never modifies the original scan row or the evidence chain entry.
  The record of what the system decided at the time must stay exactly as it
  was decided; a correction is an additional fact, appended.
"""

from __future__ import annotations

import json
from datetime import datetime

from services.intel.db import get_db_connection

# What the analyst asserted about the verdict.
LABEL_CORRECT = "CORRECT"          # the verdict was right
LABEL_FALSE_POSITIVE = "FALSE_POSITIVE"   # flagged, but benign
LABEL_FALSE_NEGATIVE = "FALSE_NEGATIVE"   # cleared, but malicious
LABEL_UNSURE = "UNSURE"            # reviewed, could not determine

VALID_LABELS = {
    LABEL_CORRECT, LABEL_FALSE_POSITIVE, LABEL_FALSE_NEGATIVE, LABEL_UNSURE,
}

# Review workflow state.
STATUS_PENDING = "PENDING"     # one analyst's claim, unreviewed
STATUS_CONFIRMED = "CONFIRMED"  # a second analyst agreed -- usable as a label
STATUS_REJECTED = "REJECTED"   # a second analyst disagreed

VALID_STATUSES = {STATUS_PENDING, STATUS_CONFIRMED, STATUS_REJECTED}

# Labels that carry a ground-truth signal. UNSURE is recorded because "an
# analyst looked and could not tell" is itself useful -- it marks the genuinely
# ambiguous cases -- but it is not a label and never reaches training data.
TRAINABLE_LABELS = {LABEL_CORRECT, LABEL_FALSE_POSITIVE, LABEL_FALSE_NEGATIVE}


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def init_feedback_db():
    """Create the feedback table. Idempotent."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS analyst_feedback (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id       INTEGER,
            artefact_hash TEXT,
            module        TEXT NOT NULL,
            system_verdict TEXT,
            system_score  REAL,
            label         TEXT NOT NULL,
            corrected_verdict TEXT,
            note          TEXT,
            reviewer      TEXT,
            reviewer_id   INTEGER,
            status        TEXT NOT NULL DEFAULT 'PENDING',
            confirmed_by  TEXT,
            created_at    TEXT NOT NULL,
            updated_at    TEXT NOT NULL,
            artefact_text TEXT
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_fb_scan ON analyst_feedback(scan_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_fb_module ON analyst_feedback(module)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_fb_status ON analyst_feedback(status)")
    # One analyst gets one opinion per scan. Without this, a page that
    # double-fires its submit handler silently doubles that analyst's weight in
    # every metric computed below.
    # (SQLite treats NULLs as distinct in a unique index, so anonymous
    # submissions -- reviewer_id NULL -- are not deduplicated. Every caller in
    # this codebase is behind @login_required and supplies a reviewer_id.)
    cur.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_fb_unique
        ON analyst_feedback(scan_id, reviewer_id)
    """)
    conn.commit()
    conn.close()


def submit(scan_id, module, label, system_verdict=None, system_score=None,
           corrected_verdict=None, note=None, reviewer=None, reviewer_id=None,
           artefact_hash=None, artefact_text=None):
    """
    Record one analyst's assessment of a verdict.

    Re-submitting for the same (scan, reviewer) updates that analyst's opinion
    rather than adding a second one, and resets the row to PENDING -- a changed
    opinion has not been confirmed by anyone yet.

    Returns the row id, or None with a reason when the input is unusable.
    """
    label = (label or "").upper().strip()
    if label not in VALID_LABELS:
        return None, "unknown label: %s" % label

    now = _now()
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO analyst_feedback
                (scan_id, artefact_hash, module, system_verdict, system_score,
                 label, corrected_verdict, note, reviewer, reviewer_id,
                 status, created_at, updated_at, artefact_text)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(scan_id, reviewer_id) DO UPDATE SET
                label = excluded.label,
                corrected_verdict = excluded.corrected_verdict,
                note = excluded.note,
                status = 'PENDING',
                confirmed_by = NULL,
                updated_at = excluded.updated_at
        """, (scan_id, (artefact_hash or "").lower() or None, module,
              system_verdict, system_score, label, corrected_verdict, note,
              reviewer, reviewer_id, STATUS_PENDING, now, now,
              (artefact_text or "")[:4000] or None))
        conn.commit()
        cur.execute("""
            SELECT id FROM analyst_feedback
            WHERE scan_id IS ? AND reviewer_id IS ?
        """, (scan_id, reviewer_id))
        row = cur.fetchone()
        return (row["id"] if row else cur.lastrowid), None
    finally:
        conn.close()


def review(feedback_id, status, reviewer=None):
    """
    Second-analyst adjudication of a pending correction.

    A correction confirmed by someone other than its author is what turns an
    opinion into a label. The caller enforces that separation; this records it.
    """
    status = (status or "").upper().strip()
    if status not in VALID_STATUSES:
        return False, "unknown status: %s" % status

    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
            UPDATE analyst_feedback
            SET status = ?, confirmed_by = ?, updated_at = ?
            WHERE id = ?
        """, (status, reviewer, _now(), int(feedback_id)))
        conn.commit()
        return cur.rowcount > 0, None
    finally:
        conn.close()


def queue(status=STATUS_PENDING, module=None, limit=100):
    """The review queue: corrections awaiting a second opinion."""
    sql = """
        SELECT id, scan_id, artefact_hash, module, system_verdict, system_score,
               label, corrected_verdict, note, reviewer, reviewer_id, status,
               confirmed_by, created_at, updated_at
        FROM analyst_feedback WHERE 1=1
    """
    params = []
    if status:
        sql += " AND status = ?"
        params.append(status)
    if module:
        sql += " AND module = ?"
        params.append(module)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(int(limit))

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(sql, params)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get(feedback_id):
    """One feedback row by id, or None."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, scan_id, artefact_hash, module, system_verdict, system_score,
               label, corrected_verdict, note, reviewer, reviewer_id, status,
               confirmed_by, created_at, updated_at
        FROM analyst_feedback WHERE id = ?
    """, (int(feedback_id),))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def for_scan(scan_id):
    """Every analyst opinion recorded against one scan."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, label, corrected_verdict, note, reviewer, status, created_at
        FROM analyst_feedback WHERE scan_id = ? ORDER BY id ASC
    """, (int(scan_id),))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def metrics(module=None, confirmed_only=True):
    """
    The confusion matrix the detectors never had.

    Counts are over *reviewed artefacts*, not over all traffic, so these are
    not population error rates -- analysts review the interesting cases, which
    biases the sample toward disagreement. The returned dict says so in
    `caveat`, because a precision figure quoted without that sentence is worse
    than no figure.
    """
    sql = """
        SELECT module, label, system_verdict, COUNT(*) AS n
        FROM analyst_feedback WHERE label != 'UNSURE'
    """
    params = []
    if confirmed_only:
        sql += " AND status = 'CONFIRMED'"
    if module:
        sql += " AND module = ?"
        params.append(module)
    sql += " GROUP BY module, label, system_verdict"

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(sql, params)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()

    per_module = {}
    for r in rows:
        m = per_module.setdefault(r["module"], {
            "module": r["module"], "correct": 0,
            "false_positive": 0, "false_negative": 0, "reviewed": 0,
        })
        n = r["n"]
        m["reviewed"] += n
        if r["label"] == LABEL_CORRECT:
            m["correct"] += n
        elif r["label"] == LABEL_FALSE_POSITIVE:
            m["false_positive"] += n
        elif r["label"] == LABEL_FALSE_NEGATIVE:
            m["false_negative"] += n

    for m in per_module.values():
        reviewed = m["reviewed"]
        m["agreement_rate"] = round(m["correct"] / reviewed, 3) if reviewed else None
        # Reported only once the sample can support it. A "100% accurate"
        # badge off three reviews is the kind of number that gets a system
        # deployed and then discredited.
        m["reportable"] = reviewed >= 30

    return {
        "modules": sorted(per_module.values(), key=lambda x: -x["reviewed"]),
        "total_reviewed": sum(m["reviewed"] for m in per_module.values()),
        "confirmed_only": confirmed_only,
        "caveat": (
            "These rates are over artefacts an analyst chose to review, not "
            "over all traffic. Reviewers look at borderline and disputed "
            "cases, so the disagreement rate here is higher than it would be "
            "across the full stream. Do not quote these as accuracy figures."
        ),
    }


def calibration_samples(module, confirmed_only=True):
    """
    (score, label) pairs for services/intel/calibration.fit_*().

    label is 1 when the artefact was genuinely malicious and 0 when it was
    genuinely benign, reconstructed from the system verdict and the analyst's
    correction:

        verdict THREAT   + CORRECT         -> 1
        verdict THREAT   + FALSE_POSITIVE  -> 0
        verdict BENIGN   + CORRECT         -> 0
        verdict BENIGN   + FALSE_NEGATIVE  -> 1

    Scores are returned on 0..1. Rows with no recorded score are skipped: a
    calibrator fitted on a guessed score is worse than none.
    """
    sql = """
        SELECT system_verdict, system_score, label
        FROM analyst_feedback
        WHERE module = ? AND label IN ('CORRECT','FALSE_POSITIVE','FALSE_NEGATIVE')
          AND system_score IS NOT NULL
    """
    params = [module]
    if confirmed_only:
        sql += " AND status = 'CONFIRMED'"

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(sql, params)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()

    samples = []
    for r in rows:
        score = float(r["system_score"] or 0)
        if score > 1.0:
            score = score / 100.0
        score = max(0.0, min(1.0, score))

        flagged = _verdict_is_threat(r["system_verdict"])
        label = r["label"]
        if label == LABEL_CORRECT:
            truth = 1 if flagged else 0
        elif label == LABEL_FALSE_POSITIVE:
            truth = 0
        elif label == LABEL_FALSE_NEGATIVE:
            truth = 1
        else:
            continue
        samples.append((score, truth))
    return samples


# Verdict vocabulary differs per module (BETTING, SCAM, FAKE, DANGER, ...).
# Rather than a per-module table that silently misclassifies any new verdict
# string, treat anything not explicitly benign as a flag, and keep the benign
# set small and explicit.
_BENIGN_VERDICTS = {
    "SAFE", "REAL", "CLEAN", "BENIGN", "LOW_RISK", "NO_SCRIPT_INDICATORS",
    "LEGITIMATE", "GREEN", "NOT_BETTING", "NO_THREAT",
}


def _verdict_is_threat(verdict):
    return (verdict or "").upper().strip() not in _BENIGN_VERDICTS


def training_export(module=None, confirmed_only=True):
    """
    Confirmed corrections as labelled training rows.

    Only rows that kept the artefact text are exportable -- a label with no
    text trains nothing. Returns a list of dicts ready to append to a module's
    training CSV.
    """
    sql = """
        SELECT module, artefact_text, system_verdict, system_score,
               label, corrected_verdict, reviewer, confirmed_by, updated_at
        FROM analyst_feedback
        WHERE artefact_text IS NOT NULL AND artefact_text != ''
          AND label IN ('CORRECT','FALSE_POSITIVE','FALSE_NEGATIVE')
    """
    params = []
    if confirmed_only:
        sql += " AND status = 'CONFIRMED'"
    if module:
        sql += " AND module = ?"
        params.append(module)
    sql += " ORDER BY id ASC"

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(sql, params)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()

    out = []
    for r in rows:
        flagged = _verdict_is_threat(r["system_verdict"])
        if r["label"] == LABEL_CORRECT:
            truth = 1 if flagged else 0
        elif r["label"] == LABEL_FALSE_POSITIVE:
            truth = 0
        else:
            truth = 1
        out.append({
            "module": r["module"],
            "text": r["artefact_text"],
            "label": truth,
            "source": "analyst_feedback",
            "system_verdict": r["system_verdict"],
            "system_score": r["system_score"],
            "reviewed_by": r["reviewer"],
            "confirmed_by": r["confirmed_by"],
            "labelled_at": r["updated_at"],
        })
    return out


def export_json(module=None):
    return json.dumps(training_export(module), indent=2, ensure_ascii=False)


def summary():
    """Counts for the admin dashboard."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT status, COUNT(*) AS n FROM analyst_feedback GROUP BY status
    """)
    by_status = {r["status"]: r["n"] for r in cur.fetchall()}
    cur.execute("""
        SELECT label, COUNT(*) AS n FROM analyst_feedback GROUP BY label
    """)
    by_label = {r["label"]: r["n"] for r in cur.fetchall()}
    conn.close()
    return {
        "pending": by_status.get(STATUS_PENDING, 0),
        "confirmed": by_status.get(STATUS_CONFIRMED, 0),
        "rejected": by_status.get(STATUS_REJECTED, 0),
        "by_label": by_label,
        "total": sum(by_status.values()),
    }
