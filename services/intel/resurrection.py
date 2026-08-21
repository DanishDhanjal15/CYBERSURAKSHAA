"""
services/intel/resurrection.py
------------------------------
Temporal intelligence — detecting when a taken-down operation comes back.

The observation this is built on
================================
Operators do not stop when you take them down. They rebuild. And when they
rebuild, what they replace and what they keep is not arbitrary — it is dictated
by cost:

  Cheap to replace, replaced every time
      Domains (₹500 and ten minutes), hosting, SIM cards, Telegram channels,
      social accounts, the creative artwork.

  Expensive to replace, kept as long as possible
      The UPI address and the mule bank account behind it, because a new one
      needs a new mule with a new set of KYC documents.
      The APK signing certificate, because changing it means every existing
      install has to be replaced rather than updated.
      The cryptocurrency wallet, because moving accumulated funds is visible.

So the signature of a resurrection is precise and checkable: **new disposable
infrastructure attached to a durable anchor that has been seen before.**

Why it matters more than another detection
==========================================
A classifier tells you an artefact is a scam. This tells an investigator that
the operation they filed a notice against three weeks ago is running again —
which is the difference between processing incidents and pursuing an operator.
It is also the evidence that makes an escalation stick: a first offence is a
takedown, a documented pattern of rebuilding after enforcement is something
else entirely.

Everything here runs on data the graph already collects: `entity_sightings`
timestamps and `entities.first_seen`. Nothing new needed to be recorded.

What it cannot tell you
=======================
Shared infrastructure produces the same signature without a shared operator.
Bulletproof hosting resold to many customers, a payment aggregator handle used
by several merchants, a stolen wallet address reused by whoever obtained it —
all look like one operator rebuilding. The `confidence` on every alert reflects
how exclusive the anchor is, and no alert here is an attribution. It is a lead
that says: look at these two clusters together.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta

from services.intel.db import get_db_connection
from services.intel.indicators import (
    KIND_UPI, KIND_CRYPTO, KIND_BANK_ACCT, KIND_APK_CERT, KIND_IFSC,
    KIND_PHONE, KIND_TELEGRAM, KIND_WHATSAPP, KIND_DOMAIN, KIND_URL,
    KIND_IP, KIND_LABELS,
)

# Anchors an operator cannot cheaply abandon. Weighted by how much friction
# replacing one actually involves -- a new mule account needs a new person, a
# new signing certificate orphans every existing install.
DURABLE_ANCHORS = {
    KIND_BANK_ACCT: 1.00,   # needs a new mule with fresh KYC
    KIND_APK_CERT: 0.95,    # rotating it breaks every installed copy
    KIND_UPI: 0.90,         # tied to a bank account, same problem
    KIND_CRYPTO: 0.85,      # moving accumulated funds is visible on-chain
    KIND_IFSC: 0.40,        # identifies a branch, shared by many accounts
}

# Infrastructure replaced between campaigns as a matter of routine.
DISPOSABLE_KINDS = {
    KIND_DOMAIN, KIND_URL, KIND_IP, KIND_TELEGRAM, KIND_WHATSAPP, KIND_PHONE,
}

# An anchor this widely shared says nothing about a single operator. A payment
# aggregator handle appearing across dozens of unrelated artefacts is
# infrastructure, not identity.
ANCHOR_SHARING_LIMIT = 25

# Silence long enough to count as "we thought this was finished".
DORMANCY_DAYS = 7

# Activity after dormancy only counts as a resurrection if it is genuinely new
# infrastructure, not a straggling sighting of what was already known.
MIN_NEW_INFRASTRUCTURE = 1

# How far back to consider. Beyond this an anchor reappearing is more likely
# coincidence or resale than the same operation continuing.
MAX_GAP_DAYS = 180


def _now():
    return datetime.now()


def _stamp(dt=None):
    return (dt or datetime.now()).strftime("%Y-%m-%d %H:%M:%S")


def _parse(ts):
    if not ts:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(str(ts)[:19], fmt)
        except ValueError:
            continue
    return None


# ── Schema ────────────────────────────────────────────────────────────────

def init_resurrection_db():
    """Table for recorded resurrection events. Idempotent."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS resurrection_events (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            anchor_id       INTEGER NOT NULL,
            anchor_kind     TEXT NOT NULL,
            anchor_value    TEXT NOT NULL,
            dormant_from    TEXT,
            dormant_until   TEXT,
            gap_days        REAL,
            new_entities    TEXT,
            new_count       INTEGER NOT NULL DEFAULT 0,
            confidence      REAL NOT NULL DEFAULT 0,
            detected_at     TEXT NOT NULL,
            acknowledged    INTEGER NOT NULL DEFAULT 0,
            note            TEXT,
            UNIQUE(anchor_id, dormant_until)
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_res_detected ON resurrection_events(detected_at DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_res_ack ON resurrection_events(acknowledged)")
    conn.commit()
    conn.close()


# ── Activity timelines ────────────────────────────────────────────────────

def entity_timeline(entity_id):
    """Every sighting of one entity, oldest first."""
    conn = get_db_connection()
    rows = [dict(r) for r in conn.execute("""
        SELECT timestamp, module, verdict, score, source, scan_id, alert_id
        FROM entity_sightings WHERE entity_id = ?
        ORDER BY timestamp ASC
    """, (int(entity_id),)).fetchall()]
    conn.close()
    return rows


def activity_gaps(timestamps, min_gap_days=DORMANCY_DAYS):
    """
    Periods of silence between consecutive sightings.

    Returns [{"from", "until", "days"}] for every gap longer than the
    threshold. These are the windows in which an operation looked finished.
    """
    parsed = sorted(t for t in (_parse(x) for x in timestamps) if t)
    gaps = []
    for earlier, later in zip(parsed, parsed[1:]):
        days = (later - earlier).total_seconds() / 86400.0
        if days >= min_gap_days:
            gaps.append({"from": _stamp(earlier), "until": _stamp(later),
                         "days": round(days, 2)})
    return gaps


def campaign_timeline(campaign_id):
    """
    Activity for a whole campaign, bucketed by day.

    The shape is the point: a campaign with a solid block of activity, a gap,
    then another block is behaving differently from one with a steady trickle.
    """
    conn = get_db_connection()
    rows = conn.execute("""
        SELECT s.timestamp, e.kind, e.value, e.first_seen
        FROM campaign_entities ce
        JOIN entities e ON e.id = ce.entity_id
        LEFT JOIN entity_sightings s ON s.entity_id = e.id
        WHERE ce.campaign_id = ?
    """, (int(campaign_id),)).fetchall()
    conn.close()

    by_day = {}
    stamps = []
    for r in rows:
        ts = _parse(r["timestamp"] or r["first_seen"])
        if not ts:
            continue
        stamps.append(ts)
        day = ts.strftime("%Y-%m-%d")
        by_day[day] = by_day.get(day, 0) + 1

    if not stamps:
        return {"days": [], "gaps": [], "first": None, "last": None, "dormant": False}

    first, last = min(stamps), max(stamps)
    dormant_days = (datetime.now() - last).total_seconds() / 86400.0

    return {
        "days": [{"date": d, "sightings": n} for d, n in sorted(by_day.items())],
        "gaps": activity_gaps([_stamp(s) for s in stamps]),
        "first": _stamp(first),
        "last": _stamp(last),
        "dormant": dormant_days >= DORMANCY_DAYS,
        "dormant_days": round(dormant_days, 1),
    }


# ── Detection ─────────────────────────────────────────────────────────────

def _anchor_degree(conn, entity_id):
    """How many distinct artefacts this anchor has been seen in."""
    row = conn.execute("""
        SELECT COUNT(DISTINCT COALESCE(scan_id, -alert_id)) AS n
        FROM entity_sightings WHERE entity_id = ?
    """, (int(entity_id),)).fetchone()
    return row["n"] if row else 0


def detect(dormancy_days=DORMANCY_DAYS, max_gap_days=MAX_GAP_DAYS, record=True):
    """
    Find durable anchors that went quiet and then reappeared with new
    infrastructure attached.

    The algorithm, stated plainly:

      1. Take every entity of a durable anchor kind.
      2. Look at its sighting timeline for a gap of at least `dormancy_days`.
      3. For the most recent such gap, find neighbours whose `first_seen` falls
         *after* the gap ended — infrastructure that did not exist while the
         operation was dormant.
      4. Require at least one of those to be a disposable kind. An anchor
         reappearing beside only other durable anchors is a bookkeeping
         artefact, not a rebuild.
      5. Score confidence from anchor durability and exclusivity.
    """
    conn = get_db_connection()
    try:
        # Counting `entity_sightings` rows rather than filtering on
        # `entities.sightings`. That column is a denormalized counter
        # maintained only by upsert_entity(), so any path that records a
        # sighting without going through it -- the crawler, a backfill, a
        # direct insert -- leaves the counter behind the truth. Trusting it
        # made the detector silently skip exactly the anchors with the most
        # interesting history.
        anchors = [dict(r) for r in conn.execute("""
            SELECT e.id, e.kind, e.value, e.first_seen, e.last_seen,
                   COUNT(s.id) AS observed
            FROM entities e
            JOIN entity_sightings s ON s.entity_id = e.id
            WHERE e.kind IN (%s)
            GROUP BY e.id
            HAVING COUNT(s.id) >= 2
        """ % ",".join("?" * len(DURABLE_ANCHORS)),
            tuple(DURABLE_ANCHORS.keys())).fetchall()]

        events = []
        for anchor in anchors:
            timeline = [r["timestamp"] for r in conn.execute(
                "SELECT timestamp FROM entity_sightings WHERE entity_id = ? ORDER BY timestamp",
                (anchor["id"],)).fetchall()]
            gaps = [g for g in activity_gaps(timeline, dormancy_days)
                    if g["days"] <= max_gap_days]
            if not gaps:
                continue

            gap = gaps[-1]     # the most recent dormancy
            resumed = _parse(gap["until"])
            if not resumed:
                continue

            # Neighbours of this anchor that appeared only after it resumed.
            neighbours = [dict(r) for r in conn.execute("""
                SELECT e.id, e.kind, e.value, e.first_seen
                FROM entity_edges ed
                JOIN entities e ON e.id = CASE
                    WHEN ed.src_id = ? THEN ed.dst_id ELSE ed.src_id END
                WHERE ed.src_id = ? OR ed.dst_id = ?
            """, (anchor["id"], anchor["id"], anchor["id"])).fetchall()]

            fresh = []
            for n in neighbours:
                seen = _parse(n["first_seen"])
                if seen and seen >= resumed - timedelta(hours=12):
                    fresh.append(n)

            disposable = [n for n in fresh if n["kind"] in DISPOSABLE_KINDS]
            if len(disposable) < MIN_NEW_INFRASTRUCTURE:
                continue

            degree = _anchor_degree(conn, anchor["id"])
            if degree > ANCHOR_SHARING_LIMIT:
                # Too widely shared to point at one operator.
                continue

            durability = DURABLE_ANCHORS.get(anchor["kind"], 0.5)
            # Exclusivity: an anchor seen in a handful of artefacts is far
            # more identifying than one seen in twenty.
            exclusivity = max(0.0, 1.0 - (degree / float(ANCHOR_SHARING_LIMIT)))
            volume = min(1.0, len(disposable) / 4.0)
            confidence = round(
                0.55 * durability + 0.30 * exclusivity + 0.15 * volume, 3)

            events.append({
                "anchor_id": anchor["id"],
                "anchor_kind": anchor["kind"],
                "anchor_label": KIND_LABELS.get(anchor["kind"], anchor["kind"]),
                "anchor_value": anchor["value"],
                "dormant_from": gap["from"],
                "dormant_until": gap["until"],
                "gap_days": gap["days"],
                "new_entities": fresh,
                "new_infrastructure": disposable,
                "new_count": len(fresh),
                "anchor_degree": degree,
                "confidence": confidence,
                "summary": _summarise(anchor, gap, disposable),
            })
    finally:
        conn.close()

    events.sort(key=lambda e: (-e["confidence"], -e["new_count"]))
    if record:
        new_events = _record_events(events)
        for e in new_events:
            _announce(e)
    return events


def _interested_parties(anchor_id, anchor_value):
    """
    Who worked this anchor before.

    Anyone who filed an enforcement notice against it, or owns a case
    containing it. These are the people for whom "it came back" changes
    something; everyone else would just be receiving mail.
    """
    people = set()
    conn = get_db_connection()
    try:
        for r in conn.execute("""
            SELECT DISTINCT filed_by FROM enforcement_targets
            WHERE value = ? AND filed_by IS NOT NULL
        """, (anchor_value,)).fetchall():
            people.add(r["filed_by"])

        for r in conn.execute("""
            SELECT DISTINCT c.assigned_to, c.created_by_name
            FROM case_entities ce JOIN cases c ON c.id = ce.case_id
            WHERE ce.entity_id = ?
        """, (int(anchor_id),)).fetchall():
            people.update(x for x in (r["assigned_to"], r["created_by_name"]) if x)
    except Exception as e:
        # The enforcement or case tables may not exist in a minimal
        # deployment. An empty set falls back to notifying administrators,
        # which is the right failure direction.
        print("[RESURRECTION] could not resolve interested parties: %s" % e)
    finally:
        conn.close()
    return sorted(people)


def _announce(event):
    """Never lets a delivery failure abort detection."""
    try:
        from services.intel import notifications
        recipients = _interested_parties(event["anchor_id"], event["anchor_value"])
        notifications.operator_rebuilt(event, recipients)
    except Exception as e:
        print("[RESURRECTION] could not announce %s: %s" % (event.get("anchor_value"), e))


def _summarise(anchor, gap, disposable):
    kinds = {}
    for n in disposable:
        kinds[n["kind"]] = kinds.get(n["kind"], 0) + 1
    described = ", ".join("%d new %s%s" % (n, KIND_LABELS.get(k, k).lower(),
                                           "s" if n > 1 else "")
                          for k, n in sorted(kinds.items(), key=lambda kv: -kv[1]))
    return (
        "%s %s was quiet for %.0f days, then reappeared alongside %s. "
        "The infrastructure is new; the payment rail is not — which is the "
        "pattern of an operator rebuilding rather than a new operation."
        % (KIND_LABELS.get(anchor["kind"], anchor["kind"]), anchor["value"],
           gap["days"], described or "new infrastructure")
    )


def _record_events(events):
    """
    Persist events, returning only those not already recorded.

    The return value is what stops every detect() run re-announcing the same
    rebuild -- detection is idempotent by design, so without this the
    notification would fire on each pass.
    """
    if not events:
        return []
    fresh = []
    conn = get_db_connection()
    try:
        for e in events:
            seen = conn.execute("""
                SELECT 1 FROM resurrection_events
                WHERE anchor_id = ? AND dormant_until = ?
            """, (e["anchor_id"], e["dormant_until"])).fetchone()
            if not seen:
                fresh.append(e)
            conn.execute("""
                INSERT INTO resurrection_events
                    (anchor_id, anchor_kind, anchor_value, dormant_from,
                     dormant_until, gap_days, new_entities, new_count,
                     confidence, detected_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(anchor_id, dormant_until) DO UPDATE SET
                    new_count  = excluded.new_count,
                    confidence = excluded.confidence,
                    new_entities = excluded.new_entities
            """, (e["anchor_id"], e["anchor_kind"], e["anchor_value"],
                  e["dormant_from"], e["dormant_until"], e["gap_days"],
                  json.dumps([{"kind": n["kind"], "value": n["value"]}
                              for n in e["new_entities"]]),
                  e["new_count"], e["confidence"], _stamp()))
        conn.commit()
    finally:
        conn.close()
    return fresh


# ── Churn analysis ────────────────────────────────────────────────────────

def churn_profile(campaign_id=None, anchor_id=None):
    """
    How fast an operation replaces each kind of infrastructure.

    A campaign burning through a domain a week but holding one UPI address for
    three months has a rate limit, and that rate limit is the payment rail.
    Naming it tells an investigator exactly where pressure would actually cost
    the operator something.
    """
    conn = get_db_connection()
    if campaign_id:
        rows = [dict(r) for r in conn.execute("""
            SELECT e.kind, e.value, e.first_seen, e.last_seen
            FROM campaign_entities ce JOIN entities e ON e.id = ce.entity_id
            WHERE ce.campaign_id = ?
        """, (int(campaign_id),)).fetchall()]
    elif anchor_id:
        # UNION the anchor itself in. The comparison this function exists to
        # make is anchor-lifespan against disposable-lifespan, and omitting
        # the anchor left the one row that carries the answer out of the table.
        rows = [dict(r) for r in conn.execute("""
            SELECT e.kind, e.value, e.first_seen, e.last_seen
            FROM entity_edges ed
            JOIN entities e ON e.id = CASE
                WHEN ed.src_id = ? THEN ed.dst_id ELSE ed.src_id END
            WHERE ed.src_id = ? OR ed.dst_id = ?
            UNION
            SELECT kind, value, first_seen, last_seen FROM entities WHERE id = ?
        """, (int(anchor_id),) * 4).fetchall()]
    else:
        conn.close()
        return {"error": "campaign_id or anchor_id is required"}
    conn.close()

    by_kind = {}
    for r in rows:
        first, last = _parse(r["first_seen"]), _parse(r["last_seen"])
        lifespan = ((last - first).total_seconds() / 86400.0) if first and last else 0.0
        k = by_kind.setdefault(r["kind"], {"kind": r["kind"],
                                           "label": KIND_LABELS.get(r["kind"], r["kind"]),
                                           "count": 0, "lifespans": []})
        k["count"] += 1
        k["lifespans"].append(lifespan)

    profile = []
    for k in by_kind.values():
        spans = sorted(k["lifespans"])
        median = (spans[len(spans) // 2] if len(spans) % 2
                  else (spans[len(spans) // 2 - 1] + spans[len(spans) // 2]) / 2.0) if spans else 0
        profile.append({
            "kind": k["kind"],
            "label": k["label"],
            "count": k["count"],
            "median_lifespan_days": round(median, 1),
            "durable": k["kind"] in DURABLE_ANCHORS,
        })
    profile.sort(key=lambda p: -p["median_lifespan_days"])

    longest = profile[0] if profile else None
    return {
        "profile": profile,
        "bottleneck": longest,
        "interpretation": (
            "The longest-lived indicator is the %s — held for a median of "
            "%.0f days while other infrastructure was replaced. That is where "
            "this operation is least able to absorb enforcement pressure."
            % (longest["label"].lower(), longest["median_lifespan_days"])
            if longest and longest["durable"] else
            "No durable anchor stands out. Either this operation replaces "
            "everything at a similar rate, or there is not yet enough history "
            "to tell."
        ),
    }


# ── Queries ───────────────────────────────────────────────────────────────

def recent_events(limit=50, unacknowledged_only=False, min_confidence=0.0):
    sql = "SELECT * FROM resurrection_events WHERE confidence >= ?"
    params = [float(min_confidence)]
    if unacknowledged_only:
        sql += " AND acknowledged = 0"
    sql += " ORDER BY detected_at DESC, confidence DESC LIMIT ?"
    params.append(int(limit))

    conn = get_db_connection()
    rows = []
    for r in conn.execute(sql, params).fetchall():
        d = dict(r)
        try:
            d["new_entities"] = json.loads(d["new_entities"] or "[]")
        except (ValueError, TypeError):
            d["new_entities"] = []
        rows.append(d)
    conn.close()
    return rows


def acknowledge(event_id, note=None):
    conn = get_db_connection()
    try:
        cur = conn.execute("""
            UPDATE resurrection_events SET acknowledged = 1, note = ? WHERE id = ?
        """, (note, int(event_id)))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def dormant_campaigns(days=DORMANCY_DAYS):
    """
    Campaigns with no activity recently.

    These are the ones a resurrection would be *about*. Listing them makes the
    detector's output legible: an alert naming a campaign already on this list
    reads very differently from one out of nowhere.
    """
    conn = get_db_connection()
    rows = [dict(r) for r in conn.execute("""
        SELECT id, label, size, risk, first_seen, last_seen FROM campaigns
        ORDER BY last_seen DESC
    """).fetchall()]
    conn.close()

    out = []
    for c in rows:
        last = _parse(c["last_seen"])
        if not last:
            continue
        quiet = (datetime.now() - last).total_seconds() / 86400.0
        if quiet >= days:
            c["dormant_days"] = round(quiet, 1)
            out.append(c)
    return sorted(out, key=lambda c: -c["dormant_days"])


def stats():
    conn = get_db_connection()
    cur = conn.cursor()
    total = cur.execute("SELECT COUNT(*) AS n FROM resurrection_events").fetchone()["n"]
    unack = cur.execute(
        "SELECT COUNT(*) AS n FROM resurrection_events WHERE acknowledged = 0").fetchone()["n"]
    strong = cur.execute(
        "SELECT COUNT(*) AS n FROM resurrection_events WHERE confidence >= 0.7").fetchone()["n"]
    gap = cur.execute("SELECT AVG(gap_days) AS g FROM resurrection_events").fetchone()["g"]
    conn.close()
    return {
        "events": total,
        "unacknowledged": unack,
        "high_confidence": strong,
        "mean_gap_days": round(gap, 1) if gap else None,
        "dormancy_threshold_days": DORMANCY_DAYS,
        "caveat": (
            "A shared anchor produces this signature without a shared "
            "operator — resold bulletproof hosting, an aggregator payment "
            "handle, a stolen wallet address. Confidence reflects how "
            "exclusive the anchor is. None of these is an attribution; each is "
            "a reason to examine two clusters together."
        ),
    }
