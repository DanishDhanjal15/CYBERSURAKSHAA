"""
services/intel/harm.py
----------------------
Quantifying harm in rupees.

Why this is the foundation
==========================
Until now the platform could count things — scans, indicators, campaigns,
cases — but could not answer the only question a national body is actually
judged on: **how much money did this cost people, and how much of it came
back?** There was no concept of an amount anywhere in the codebase.

That absence shaped everything above it. Campaigns were ranked by indicator
count, so thirty cheap posters outranked one operation draining lakhs.
Enforcement was prioritised by how recently something was scanned rather than
by what it was costing. Every "impact" figure described the platform's own
activity rather than its effect.

I4C reports national cyber-fraud losses in the tens of thousands of crores.
Every one of those figures is denominated in rupees. So is every question a
minister, a magistrate or a bank nodal officer will ask.

Four design decisions worth stating
===================================

**Money is stored as integer paise, never as a float.** Binary floating point
cannot represent 0.1 exactly, and summing a few hundred thousand REAL amounts
accumulates visible error — in a system whose whole purpose is reporting
totals. Every amount in this module is an integer number of paise; the
rupee value exists only at the point of display.

**Amounts are reported, not verified.** A victim states what they lost; no
bank has confirmed it. Every aggregate exposes `verified_paise` separately
from `reported_paise`, and no figure silently merges the two. Quoting reported
losses as though they were audited is the fastest way for a national figure to
be discredited.

**Recovery only moves on a human's word.** `amount_recovered_paise` stays zero
until an analyst records a confirmed lien or reversal, exactly as
`takedown.record_outcome()` handles channels that cannot be probed. A system
that inferred recovery would report success it had not observed.

**No victim identity is stored.** Not a name, not a phone number, not an
address. A national database of confirmed fraud victims — people already
demonstrated to be reachable and vulnerable — is among the most attractive
targets imaginable, and holding it is not necessary to compute any figure here.
Reports carry an opaque `reporter_ref` and nothing more.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta

from services.intel.db import get_db_connection

# ── Money ────────────────────────────────────────────────────────────────

PAISE_PER_RUPEE = 100

# Indian numbering. 1 lakh = 10^5, 1 crore = 10^7 — the units every Indian
# figure is actually quoted in, and the grouping (2,2,3) that goes with them.
LAKH = 100_000
CRORE = 10_000_000

# Above this a single reported amount is held for review rather than counted.
# Not a rejection: a ₹50 crore individual loss is possible but rare enough that
# a typo is the likelier explanation, and one mistyped figure can dominate a
# national total.
IMPLAUSIBLE_AMOUNT_PAISE = 50 * CRORE * PAISE_PER_RUPEE


def to_paise(rupees):
    """
    Rupees (str/int/float/Decimal) to integer paise.

    Rounds half-up at the paisa, which is what a person entering "1234.567"
    means and what every financial system does.
    """
    if rupees is None:
        return None
    if isinstance(rupees, str):
        cleaned = re.sub(r"[₹,\s]", "", rupees.strip())
        if not cleaned:
            return None
        rupees = float(cleaned)
    return int(round(float(rupees) * PAISE_PER_RUPEE))


def format_inr(paise, short=True):
    """
    Integer paise to a string an Indian reader expects.

    `short=True` gives "₹47.2 lakh" / "₹1.24 crore" — how these figures are
    spoken and reported. `short=False` gives "₹47,25,000.00" with Indian
    digit grouping (2,2,3), which is what belongs on a document.
    """
    if paise is None:
        return "—"
    rupees = paise / PAISE_PER_RUPEE

    if short:
        if rupees >= CRORE:
            return "₹%.2f crore" % (rupees / CRORE)
        if rupees >= LAKH:
            return "₹%.2f lakh" % (rupees / LAKH)
        if rupees >= 1000:
            return "₹%.1fk" % (rupees / 1000)
        return "₹%.0f" % rupees

    whole = int(rupees)
    fraction = paise % PAISE_PER_RUPEE
    digits = str(whole)
    if len(digits) > 3:
        # Indian grouping: last three digits, then pairs.
        head, tail = digits[:-3], digits[-3:]
        parts = []
        while len(head) > 2:
            parts.insert(0, head[-2:])
            head = head[:-2]
        if head:
            parts.insert(0, head)
        grouped = ",".join(parts + [tail])
    else:
        grouped = digits
    return "₹%s.%02d" % (grouped, fraction)


# ── Taxonomy ─────────────────────────────────────────────────────────────
#
# The platform's only crime taxonomy today is a five-branch substring match on
# the module name in actions._ncrp_category(). This is the real one, following
# NCRP's own category structure, so a report can be filed under what actually
# happened rather than under which detector happened to see it.

CATEGORIES = {
    "financial.upi": "Online Financial Fraud > UPI fraud",
    "financial.netbanking": "Online Financial Fraud > Internet banking fraud",
    "financial.card": "Online Financial Fraud > Debit/credit card fraud",
    "financial.wallet": "Online Financial Fraud > E-wallet fraud",
    "financial.vishing": "Online Financial Fraud > Fraud call / vishing",
    "financial.aeps": "Online Financial Fraud > AePS / biometric fraud",
    "financial.bec": "Online Financial Fraud > Business email compromise",
    "financial.demat": "Online Financial Fraud > Demat / depository fraud",
    "investment": "Online Financial Fraud > Investment / trading scam",
    "digital_arrest": "Online Financial Fraud > Digital arrest / fake agency",
    "task_scam": "Online Financial Fraud > Task-based / part-time job scam",
    "loan_app": "Online Financial Fraud > Predatory lending app",
    "social.impersonation": "Online and Social Media Crime > Cheating by impersonation",
    "social.job": "Online and Social Media Crime > Online job fraud",
    "social.romance": "Online and Social Media Crime > Matrimonial / romance fraud",
    "social.sextortion": "Online and Social Media Crime > Sextortion",
    "crypto": "Cryptocurrency Crime",
    "gambling": "Online Gambling / Betting",
    "ransomware": "Ransomware",
    "other": "Any Other Cyber Crime",
}

# How each detector's verdict maps onto that taxonomy, replacing the substring
# matching in actions._ncrp_category(). Unmapped modules fall to "other"
# explicitly rather than by accident.
MODULE_CATEGORY = {
    "Investment Scam": "investment",
    "Betting Content": "gambling",
    "Customer Care": "financial.vishing",
    "Voice Scam": "digital_arrest",
    "Deepfake Face": "social.impersonation",
    "Betting App (APK)": "gambling",
}

PAYMENT_MODES = ("upi", "imps", "neft", "rtgs", "card", "wallet",
                 "netbanking", "cash", "crypto", "other")

# Beneficiary kinds that exist in the entity graph, so a victim report links to
# the same node the detectors create.
BENEFICIARY_KINDS = ("upi", "bank_account", "crypto_wallet", "phone", "other")

ST_REPORTED = "REPORTED"
ST_LIEN_MARKED = "LIEN_MARKED"
ST_RECOVERED = "RECOVERED"
ST_LOST = "LOST"
VALID_STATUSES = {ST_REPORTED, ST_LIEN_MARKED, ST_RECOVERED, ST_LOST}

# Time-to-report bands. The first is the "golden hour" — I4C's own guidance is
# that a lien placed inside it is the single largest determinant of recovery,
# a claim services/intel/actions.py already makes in prose without ever
# measuring it.
GOLDEN_HOUR_MINUTES = 60
REPORT_BANDS = [
    ("within_1h", 0, 60),
    ("1h_to_6h", 60, 360),
    ("6h_to_24h", 360, 1440),
    ("1d_to_3d", 1440, 4320),
    ("over_3d", 4320, None),
]


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _parse(ts):
    if not ts:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(str(ts)[:19], fmt)
        except ValueError:
            continue
    return None


# ── Schema ───────────────────────────────────────────────────────────────

def init_harm_db():
    """Create the victim-report tables. Idempotent."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS victim_reports (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            reporter_ref      TEXT,
            channel           TEXT NOT NULL DEFAULT 'web',
            category          TEXT NOT NULL DEFAULT 'other',
            incident_at       TEXT,
            reported_at       TEXT NOT NULL,
            bank_reported_at  TEXT,
            amount_paise           INTEGER NOT NULL DEFAULT 0,
            amount_recovered_paise INTEGER NOT NULL DEFAULT 0,
            verified          INTEGER NOT NULL DEFAULT 0,
            plausible         INTEGER NOT NULL DEFAULT 1,
            payment_mode      TEXT,
            transaction_ref   TEXT,
            beneficiary_kind  TEXT,
            beneficiary_value TEXT,
            entity_id         INTEGER,
            state_code        TEXT,
            scan_id           INTEGER,
            case_id           INTEGER,
            status            TEXT NOT NULL DEFAULT 'REPORTED',
            recorded_by       TEXT,
            outcome_by        TEXT,
            outcome_note      TEXT,
            note              TEXT,
            created_at        TEXT NOT NULL,
            updated_at        TEXT NOT NULL
        )
    """)
    for stmt in (
        "CREATE INDEX IF NOT EXISTS idx_vr_entity ON victim_reports(entity_id)",
        "CREATE INDEX IF NOT EXISTS idx_vr_category ON victim_reports(category)",
        "CREATE INDEX IF NOT EXISTS idx_vr_state ON victim_reports(state_code)",
        "CREATE INDEX IF NOT EXISTS idx_vr_reported ON victim_reports(reported_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_vr_status ON victim_reports(status)",
        "CREATE INDEX IF NOT EXISTS idx_vr_beneficiary ON victim_reports(beneficiary_kind, beneficiary_value)",
    ):
        cur.execute(stmt)
    conn.commit()
    conn.close()


# ── Recording ────────────────────────────────────────────────────────────

def record_report(amount_rupees, category="other", payment_mode=None,
                  beneficiary_kind=None, beneficiary_value=None,
                  incident_at=None, reported_at=None, transaction_ref=None,
                  state_code=None, scan_id=None, case_id=None, channel="web",
                  reporter_ref=None, note=None, recorded_by=None,
                  link_to_graph=True):
    """
    Record one victim report, and link its beneficiary into the entity graph.

    That link is the point: a UPI ID a victim says they paid is the *same node*
    the betting detector creates when it reads that ID off a poster. Once both
    exist, the platform can say what a campaign is actually costing rather than
    how many artefacts it has produced.

    Returns (report_id, None) or (None, reason).
    """
    amount_paise = to_paise(amount_rupees)
    if amount_paise is None or amount_paise < 0:
        return None, "a non-negative amount is required"

    category = (category or "other").strip()
    if category not in CATEGORIES:
        return None, "unknown category: %s" % category

    if payment_mode and payment_mode.lower() not in PAYMENT_MODES:
        return None, "unknown payment mode: %s" % payment_mode

    if beneficiary_kind and beneficiary_kind.lower() not in BENEFICIARY_KINDS:
        return None, "unknown beneficiary kind: %s" % beneficiary_kind

    # A single mistyped figure can dominate a national total, so an implausible
    # amount is recorded and flagged rather than accepted silently or thrown
    # away. Aggregates exclude it until somebody looks.
    plausible = 1 if amount_paise <= IMPLAUSIBLE_AMOUNT_PAISE else 0

    reported = reported_at or _now()
    entity_id = None

    if link_to_graph and beneficiary_kind and beneficiary_value:
        entity_id = _link_beneficiary(beneficiary_kind.lower(), beneficiary_value,
                                      category, amount_paise, scan_id)

    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO victim_reports
                (reporter_ref, channel, category, incident_at, reported_at,
                 amount_paise, plausible, payment_mode, transaction_ref,
                 beneficiary_kind, beneficiary_value, entity_id, state_code,
                 scan_id, case_id, status, recorded_by, note,
                 created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (reporter_ref, channel, category, incident_at, reported,
              amount_paise, plausible,
              (payment_mode or "").lower() or None, transaction_ref,
              (beneficiary_kind or "").lower() or None, beneficiary_value,
              entity_id, (state_code or "").upper() or None,
              scan_id, case_id, ST_REPORTED, recorded_by, note,
              _now(), _now()))
        conn.commit()
        return cur.lastrowid, None
    finally:
        conn.close()


def _link_beneficiary(kind, value, category, amount_paise, scan_id):
    """
    Put the beneficiary into the entity graph and record the sighting.

    Never raises: a graph write failing must not lose the victim's report,
    which is the part that matters.
    """
    try:
        from services.intel import graph
        conn = graph.get_db_connection()
        try:
            eid = graph.upsert_entity(
                conn, kind, value,
                # Risk here reflects that money demonstrably moved to this
                # account, which is stronger evidence than appearing on a
                # poster. Capped so one report cannot saturate the scale.
                risk=min(100, 60 + int(amount_paise / (LAKH * PAISE_PER_RUPEE)) * 5),
                confidence=0.95,
                meta={"source": "victim_report", "category": category},
            )
            graph.record_sighting(
                conn, eid, scan_id=scan_id, module="Victim Report",
                verdict="FUNDS_RECEIVED", score=90,
                context="Beneficiary of a reported loss of %s" % format_inr(amount_paise),
                source="harm",
            )
            conn.commit()
            return eid
        finally:
            conn.close()
    except Exception as e:
        print("[HARM] could not link beneficiary %s=%s: %s" % (kind, value, e))
        return None


def confirm_recovery(report_id, recovered_rupees, status=ST_RECOVERED,
                     confirmed_by=None, note=None):
    """
    Record that money was actually held or returned.

    The only route by which `amount_recovered_paise` ever becomes non-zero.
    Nothing infers recovery from a takedown, a freeze request or the passage of
    time — the platform cannot see a bank ledger, and reporting recoveries it
    has not observed is how an impact figure becomes a fiction.
    """
    status = (status or "").upper().strip()
    if status not in VALID_STATUSES:
        return False, "status must be one of: %s" % ", ".join(sorted(VALID_STATUSES))

    recovered = to_paise(recovered_rupees)
    if recovered is None or recovered < 0:
        return False, "a non-negative recovered amount is required"

    conn = get_db_connection()
    try:
        row = conn.execute("SELECT amount_paise FROM victim_reports WHERE id = ?",
                           (int(report_id),)).fetchone()
        if not row:
            return False, "report not found"
        if recovered > row["amount_paise"]:
            return False, "recovered amount exceeds the amount reported lost"

        conn.execute("""
            UPDATE victim_reports
            SET amount_recovered_paise = ?, status = ?, verified = 1,
                outcome_by = ?, outcome_note = ?, updated_at = ?
            WHERE id = ?
        """, (recovered, status, confirmed_by, note, _now(), int(report_id)))
        conn.commit()
        return True, None
    finally:
        conn.close()


def mark_bank_reported(report_id, when=None):
    """
    Record when the victim told their bank.

    Distinct from when they told us: RBI's limited-liability windows run from
    the customer's report to the *bank*, and that is the clock that decides
    whether they bear the loss.
    """
    conn = get_db_connection()
    try:
        cur = conn.execute(
            "UPDATE victim_reports SET bank_reported_at = ?, updated_at = ? WHERE id = ?",
            (when or _now(), _now(), int(report_id)))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


# ── Reading ──────────────────────────────────────────────────────────────

def get_report(report_id):
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM victim_reports WHERE id = ?",
                       (int(report_id),)).fetchone()
    conn.close()
    return _decorate(dict(row)) if row else None


def list_reports(category=None, state=None, status=None, limit=100):
    sql = "SELECT * FROM victim_reports WHERE 1=1"
    params = []
    for column, value in (("category", category), ("state_code", state),
                          ("status", status)):
        if value:
            sql += " AND %s = ?" % column
            params.append(value)
    sql += " ORDER BY reported_at DESC, id DESC LIMIT ?"
    params.append(int(limit))

    conn = get_db_connection()
    rows = [_decorate(dict(r)) for r in conn.execute(sql, params).fetchall()]
    conn.close()
    return rows


def _decorate(row):
    """Add the display and derived fields the UI needs."""
    row["amount_display"] = format_inr(row.get("amount_paise"))
    row["amount_exact"] = format_inr(row.get("amount_paise"), short=False)
    row["recovered_display"] = format_inr(row.get("amount_recovered_paise"))
    row["category_label"] = CATEGORIES.get(row.get("category"), row.get("category"))
    row["minutes_to_report"] = _minutes_to_report(row)
    row["report_band"] = _band(row["minutes_to_report"])
    row["golden_hour"] = (row["minutes_to_report"] is not None
                          and row["minutes_to_report"] <= GOLDEN_HOUR_MINUTES)
    return row


def _minutes_to_report(row):
    incident = _parse(row.get("incident_at"))
    reported = _parse(row.get("reported_at"))
    if not incident or not reported or reported < incident:
        return None
    return round((reported - incident).total_seconds() / 60.0, 1)


def _band(minutes):
    if minutes is None:
        return None
    for name, low, high in REPORT_BANDS:
        if minutes >= low and (high is None or minutes < high):
            return name
    return "over_3d"


# ── Exposure ─────────────────────────────────────────────────────────────

def entity_exposure(entity_id):
    """How much money is reported to have reached one indicator."""
    conn = get_db_connection()
    row = conn.execute("""
        SELECT COUNT(*) AS reports,
               COALESCE(SUM(amount_paise), 0) AS total,
               COALESCE(SUM(amount_recovered_paise), 0) AS recovered
        FROM victim_reports WHERE entity_id = ? AND plausible = 1
    """, (int(entity_id),)).fetchone()
    conn.close()
    return {
        "entity_id": entity_id,
        "reports": row["reports"],
        "total_paise": row["total"],
        "recovered_paise": row["recovered"],
        "total_display": format_inr(row["total"]),
        "recovered_display": format_inr(row["recovered"]),
    }


def campaign_exposure(campaign_id):
    """
    How much money is reported against every indicator in a campaign.

    Counts each *report* once even where several of a campaign's indicators
    appear in it — otherwise a campaign that shares two beneficiaries with one
    victim would double its own apparent harm, and the biggest number would
    belong to the best-connected campaign rather than the most costly one.
    """
    conn = get_db_connection()
    row = conn.execute("""
        SELECT COUNT(DISTINCT vr.id) AS reports,
               COALESCE(SUM(vr.amount_paise), 0) AS total,
               COALESCE(SUM(vr.amount_recovered_paise), 0) AS recovered
        FROM (
            SELECT DISTINCT vr2.id, vr2.amount_paise, vr2.amount_recovered_paise
            FROM campaign_entities ce
            JOIN victim_reports vr2 ON vr2.entity_id = ce.entity_id
            WHERE ce.campaign_id = ? AND vr2.plausible = 1
        ) vr
    """, (int(campaign_id),)).fetchone()
    conn.close()
    return {
        "campaign_id": campaign_id,
        "reports": row["reports"],
        "total_paise": row["total"],
        "recovered_paise": row["recovered"],
        "total_display": format_inr(row["total"]),
        "recovered_display": format_inr(row["recovered"]),
    }


def top_beneficiaries(limit=20):
    """
    The accounts money actually went to, ranked by amount.

    This is the enforcement priority list. An account receiving from thirty
    victims is a mule worth freezing; a domain seen thirty times may just be a
    popular link.
    """
    conn = get_db_connection()
    rows = [dict(r) for r in conn.execute("""
        SELECT beneficiary_kind, beneficiary_value, entity_id,
               COUNT(*) AS reports,
               SUM(amount_paise) AS total,
               SUM(amount_recovered_paise) AS recovered
        FROM victim_reports
        WHERE beneficiary_value IS NOT NULL AND plausible = 1
        GROUP BY beneficiary_kind, beneficiary_value
        ORDER BY total DESC LIMIT ?
    """, (int(limit),)).fetchall()]
    conn.close()
    for r in rows:
        r["total_display"] = format_inr(r["total"])
        r["recovered_display"] = format_inr(r["recovered"])
    return rows


# ── National figures ─────────────────────────────────────────────────────

def national_totals(days=None, state=None, category=None):
    """
    The headline figures, with reported and verified kept apart.

    `recovery_rate` is deliberately computed against *verified* losses only.
    Dividing confirmed recoveries by self-reported losses would understate it
    whenever a report is exaggerated and overstate it whenever one is missing —
    a ratio between two differently-sourced numbers is not a rate.
    """
    where = ["plausible = 1"]
    params = []
    if days:
        cutoff = (datetime.now() - timedelta(days=int(days))
                  ).strftime("%Y-%m-%d %H:%M:%S")
        where.append("reported_at >= ?")
        params.append(cutoff)
    if state:
        where.append("state_code = ?")
        params.append(state.upper())
    if category:
        where.append("category = ?")
        params.append(category)
    clause = " AND ".join(where)

    conn = get_db_connection()
    row = conn.execute("""
        SELECT COUNT(*) AS reports,
               COALESCE(SUM(amount_paise), 0) AS reported,
               COALESCE(SUM(CASE WHEN verified = 1 THEN amount_paise ELSE 0 END), 0) AS verified,
               COALESCE(SUM(amount_recovered_paise), 0) AS recovered,
               COALESCE(SUM(CASE WHEN status = 'LIEN_MARKED' THEN amount_paise ELSE 0 END), 0) AS lien
        FROM victim_reports WHERE %s
    """ % clause, params).fetchone()

    excluded = conn.execute(
        "SELECT COUNT(*) AS n FROM victim_reports WHERE plausible = 0").fetchone()["n"]
    conn.close()

    verified_paise = row["verified"]
    return {
        "reports": row["reports"],
        "reported_paise": row["reported"],
        "reported_display": format_inr(row["reported"]),
        "verified_paise": verified_paise,
        "verified_display": format_inr(verified_paise),
        "recovered_paise": row["recovered"],
        "recovered_display": format_inr(row["recovered"]),
        "lien_marked_paise": row["lien"],
        "lien_marked_display": format_inr(row["lien"]),
        "recovery_rate": (round(row["recovered"] / verified_paise, 4)
                          if verified_paise else None),
        "held_for_review": excluded,
        "caveat": (
            "Reported amounts are what victims stated they lost; no bank has "
            "confirmed them. Only figures marked verified have been checked, "
            "and the recovery rate is computed against those alone. %s"
            % ("%d report(s) with an implausibly large amount are excluded "
               "pending review." % excluded if excluded else "")
        ).strip(),
    }


def by_category(days=None):
    return _group("category", days, label_map=CATEGORIES)


def by_state(days=None):
    return _group("state_code", days)


def by_payment_mode(days=None):
    return _group("payment_mode", days)


def _group(column, days=None, label_map=None):
    where = ["plausible = 1", "%s IS NOT NULL" % column]
    params = []
    if days:
        cutoff = (datetime.now() - timedelta(days=int(days))
                  ).strftime("%Y-%m-%d %H:%M:%S")
        where.append("reported_at >= ?")
        params.append(cutoff)

    conn = get_db_connection()
    rows = [dict(r) for r in conn.execute("""
        SELECT %s AS key, COUNT(*) AS reports,
               SUM(amount_paise) AS total,
               SUM(amount_recovered_paise) AS recovered
        FROM victim_reports WHERE %s
        GROUP BY %s ORDER BY total DESC
    """ % (column, " AND ".join(where), column), params).fetchall()]
    conn.close()

    for r in rows:
        r["label"] = (label_map or {}).get(r["key"], r["key"])
        r["total_display"] = format_inr(r["total"])
        r["recovered_display"] = format_inr(r["recovered"])
    return rows


def golden_hour_stats():
    """
    Time-to-report, and what it appears to be worth.

    `actions.py` already tells analysts the golden hour is "the single largest
    determinant of recovery" — as prose, never measured. This measures it.

    The recovery rate per band is observational: victims who report fast may
    differ from those who do not in ways that have nothing to do with the
    speed. It is a strong operational signal and not a causal claim, and the
    returned `caveat` says so.
    """
    conn = get_db_connection()
    # No `incident_at IS NOT NULL` filter. Excluding those rows in SQL made
    # the `no_incident_time` counter below structurally unreachable — it could
    # only ever report zero, which would have read as "every report is timed"
    # rather than "we never checked".
    rows = [dict(r) for r in conn.execute("""
        SELECT incident_at, reported_at, amount_paise, amount_recovered_paise, verified
        FROM victim_reports WHERE plausible = 1
    """).fetchall()]
    conn.close()

    bands = {name: {"band": name, "reports": 0, "total": 0, "recovered": 0,
                    "verified_total": 0}
             for name, _, _ in REPORT_BANDS}
    untimed = 0

    for r in rows:
        minutes = _minutes_to_report(r)
        if minutes is None:
            untimed += 1
            continue
        b = bands[_band(minutes)]
        b["reports"] += 1
        b["total"] += r["amount_paise"]
        b["recovered"] += r["amount_recovered_paise"]
        if r["verified"]:
            b["verified_total"] += r["amount_paise"]

    for b in bands.values():
        b["total_display"] = format_inr(b["total"])
        b["recovered_display"] = format_inr(b["recovered"])
        b["recovery_rate"] = (round(b["recovered"] / b["verified_total"], 4)
                              if b["verified_total"] else None)

    within = bands["within_1h"]["reports"]
    timed = sum(b["reports"] for b in bands.values())

    return {
        "bands": [bands[name] for name, _, _ in REPORT_BANDS],
        "golden_hour_reports": within,
        "timed_reports": timed,
        "golden_hour_rate": round(within / timed, 4) if timed else None,
        "no_incident_time": untimed,
        "caveat": (
            "Recovery rates per band are observational. People who report "
            "within the hour may differ from those who do not in ways "
            "unrelated to speed, and no control exists here. Treat this as an "
            "operational signal, not a causal claim."
        ),
    }


def summary():
    """Compact figures for the dashboard tiles."""
    totals = national_totals()
    return {
        "reports": totals["reports"],
        "reported_display": totals["reported_display"],
        "recovered_display": totals["recovered_display"],
        "recovery_rate": totals["recovery_rate"],
        "golden_hour_rate": golden_hour_stats()["golden_hour_rate"],
        "top_category": (by_category() or [{}])[0].get("label"),
    }
