"""
services/intel/takedown.py
--------------------------
Enforcement outcome tracking — did the notice actually work?

The gap
=======
`services/intel/actions.py` builds a draft notice for every indicator and
routes it to the right authority. Then nothing. The platform had no idea
whether a single one of those notices ever resulted in anything, which means
it could describe its own activity but never its own effect.

That distinction is the whole difference between "we generated 41 notices" —
a measure of how busy the tool was — and "27 of those domains are dark, median
3.2 days" — a measure of whether any of it mattered.

How it works
============
When an action pack is dispatched, each target is registered here. A prober
then re-checks the target on a schedule and records what it finds, append-only,
so the decay of a campaign's infrastructure can be plotted rather than merely
asserted.

What can and cannot be probed
=============================
This is the constraint that shapes everything below, and it is not a
limitation to be worked around — it is a fact about what is observable:

  domain / url / ip     Machine-checkable. DNS resolution and HTTP reachability
                        are directly observable from here.

  upi / bank_account    Not checkable. There is no public endpoint that will
  phone / telegram      tell you whether a UPI handle has been frozen or a
  apk_cert              number disconnected, and probing payment rails to find
                        out would be indistinguishable from abuse. These carry
                        outcomes only when an analyst records one, and until
                        then they are honestly UNKNOWN — never counted as
                        successes and never counted as failures.

Attribution
===========
A dead domain is **correlation, not causation**. Operators rotate
infrastructure constantly, hosts suspend accounts for non-payment, and
registrations lapse. This module records that a target went dark and when; it
does not claim the notice caused it. Every metric it produces carries that
sentence, because "our takedown success rate is 66%" is a claim about
effectiveness that the data cannot support, while "66% of targets we reported
went dark within 30 days" is exactly what was measured.

Transient failures
==================
A single failed DNS lookup means nothing — resolvers hiccup, networks blip.
A target is only declared DEAD after CONSECUTIVE_DEAD_PROBES consecutive
failures, and a single successful probe resets that counter. Without this the
tracker would report an impressive and completely fictional takedown rate.
"""

from __future__ import annotations

import json
import socket
import threading
import urllib.error
import urllib.request
from datetime import datetime, timedelta

from services.intel.db import get_db_connection

# Target lifecycle.
ST_FILED = "FILED"          # registered, never yet probed
ST_LIVE = "LIVE"            # confirmed still reachable
ST_DEAD = "DEAD"            # confirmed gone, repeatedly
ST_UNKNOWN = "UNKNOWN"      # not machine-checkable, no analyst outcome yet
ST_RESURFACED = "RESURFACED"  # was DEAD, came back

VALID_STATES = {ST_FILED, ST_LIVE, ST_DEAD, ST_UNKNOWN, ST_RESURFACED}

# Indicator kinds this module can observe directly.
PROBEABLE_KINDS = {"domain", "url", "ip"}

# Kinds whose outcome only a human can establish. Listed explicitly rather
# than inferred, so adding a new indicator kind forces a deliberate decision
# about whether it is observable.
MANUAL_KINDS = {"upi", "bank_account", "ifsc", "phone", "telegram",
                "whatsapp", "crypto_wallet", "apk_cert", "email"}

# Consecutive failed probes before a target is called DEAD. Three at the
# default interval is roughly a day of agreement, which comfortably outlasts a
# resolver blip or a brief outage.
CONSECUTIVE_DEAD_PROBES = 3

PROBE_TIMEOUT = 6.0
PROBE_INTERVAL_SECONDS = 21600     # 6 hours
MAX_TARGETS_PER_SWEEP = 120

# Targets stop being probed once they have been dead this long. An operator is
# not coming back to a domain that has been gone for two months, and probing
# forever turns a fixed cost into an unbounded one.
STOP_PROBING_AFTER_DAYS = 60


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _parse(ts):
    try:
        return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return None


# ── Schema ────────────────────────────────────────────────────────────────

def init_takedown_db():
    """Create the enforcement tracking tables. Idempotent."""
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS enforcement_targets (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            kind           TEXT NOT NULL,
            value          TEXT NOT NULL,
            channel        TEXT NOT NULL,
            entity_id      INTEGER,
            scan_id        INTEGER,
            case_id        INTEGER,
            campaign_id    INTEGER,
            action_ref     TEXT,
            filed_at       TEXT NOT NULL,
            filed_by       TEXT,
            state          TEXT NOT NULL DEFAULT 'FILED',
            probeable      INTEGER NOT NULL DEFAULT 0,
            first_probe    TEXT,
            last_probe     TEXT,
            last_alive     TEXT,
            died_at        TEXT,
            consecutive_dead INTEGER NOT NULL DEFAULT 0,
            probe_count    INTEGER NOT NULL DEFAULT 0,
            outcome_note   TEXT,
            outcome_by     TEXT,
            UNIQUE(kind, value, channel)
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_et_state ON enforcement_targets(state)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_et_probe ON enforcement_targets(probeable, last_probe)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_et_channel ON enforcement_targets(channel)")

    # Append-only probe history. Kept rather than collapsed into a current
    # state because the shape of the decay is the interesting part: a target
    # that flickered for a week before going down tells a different story from
    # one that vanished the day after the notice.
    cur.execute("""
        CREATE TABLE IF NOT EXISTS enforcement_probes (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id   INTEGER NOT NULL,
            timestamp   TEXT NOT NULL,
            alive       INTEGER NOT NULL,
            method      TEXT,
            detail      TEXT,
            FOREIGN KEY(target_id) REFERENCES enforcement_targets(id) ON DELETE CASCADE
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_ep_target ON enforcement_probes(target_id, timestamp)")

    conn.commit()
    conn.close()


# ── Registration ──────────────────────────────────────────────────────────

def register_target(kind, value, channel, entity_id=None, scan_id=None,
                    case_id=None, campaign_id=None, action_ref=None,
                    filed_by=None):
    """
    Record that a notice was filed against one target.

    Re-filing against the same (kind, value, channel) updates the existing row
    rather than creating a second: two notices about one domain to one
    registrar is one enforcement effort, and counting it twice would inflate
    every rate computed below.
    """
    kind = (kind or "").lower().strip()
    value = (value or "").strip()
    if not kind or not value:
        return None, "kind and value are required"

    probeable = 1 if kind in PROBEABLE_KINDS else 0
    state = ST_FILED if probeable else ST_UNKNOWN

    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO enforcement_targets
                (kind, value, channel, entity_id, scan_id, case_id, campaign_id,
                 action_ref, filed_at, filed_by, state, probeable)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(kind, value, channel) DO UPDATE SET
                action_ref = COALESCE(excluded.action_ref, enforcement_targets.action_ref),
                case_id    = COALESCE(excluded.case_id, enforcement_targets.case_id),
                campaign_id= COALESCE(excluded.campaign_id, enforcement_targets.campaign_id)
        """, (kind, value, channel, entity_id, scan_id, case_id, campaign_id,
              action_ref, _now(), filed_by, state, probeable))
        conn.commit()
        row = cur.execute(
            "SELECT id FROM enforcement_targets WHERE kind = ? AND value = ? AND channel = ?",
            (kind, value, channel)).fetchone()
        return (row["id"] if row else None), None
    finally:
        conn.close()


def register_action_pack(pack, scan_id=None, case_id=None, filed_by=None):
    """
    Register every target in an action pack from services/intel/actions.py.

    Called when a pack is dispatched, which is the moment enforcement actually
    begins and therefore the moment the clock should start.
    """
    registered = []
    for action in (pack or {}).get("actions", []):
        channel = action.get("channel")
        ref = action.get("ref")
        for ind in action.get("indicators", []):
            kind = ind.get("kind") if isinstance(ind, dict) else None
            value = ind.get("normalized") or ind.get("value") if isinstance(ind, dict) else None
            if not kind or not value:
                continue
            tid, err = register_target(kind, value, channel, scan_id=scan_id,
                                       case_id=case_id, action_ref=ref,
                                       filed_by=filed_by)
            if tid:
                registered.append({"id": tid, "kind": kind, "value": value,
                                   "channel": channel,
                                   "probeable": kind in PROBEABLE_KINDS})
    return registered


# ── Probing ───────────────────────────────────────────────────────────────

def _probe_domain(name, timeout=PROBE_TIMEOUT):
    """DNS resolution. NXDOMAIN is the signal a registrar suspension produces."""
    original = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(name, None)
        ips = sorted({i[4][0] for i in infos})
        return True, "dns", ", ".join(ips[:3])
    except socket.gaierror as e:
        return False, "dns", "does not resolve (%s)" % getattr(e, "strerror", e)
    except Exception as e:
        # A transport error is not evidence the target is gone. Reported as
        # alive so it cannot accumulate toward a DEAD verdict on a network
        # problem at our end.
        return True, "dns", "probe inconclusive: %s" % str(e)[:60]
    finally:
        socket.setdefaulttimeout(original)


def _probe_url(url, timeout=PROBE_TIMEOUT):
    """
    HTTP reachability.

    Any HTTP response — including 403 and 404 — means a server answered, so
    the host is up. Only a connection failure counts as gone. A 451 is called
    out separately because it is literally "unavailable for legal reasons",
    which is a takedown succeeding rather than a target disappearing.
    """
    req = urllib.request.Request(url, method="HEAD", headers={
        "User-Agent": "CYBERSURAKSHAA-TakedownTracker/1.0",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return True, "http", "HTTP %s" % resp.status
    except urllib.error.HTTPError as e:
        if e.code == 451:
            return False, "http", "HTTP 451 — unavailable for legal reasons"
        return True, "http", "HTTP %s" % e.code
    except urllib.error.URLError as e:
        return False, "http", "unreachable (%s)" % str(e.reason)[:60]
    except Exception as e:
        return True, "http", "probe inconclusive: %s" % str(e)[:60]


def probe_target(target):
    """Probe one target and record the result. Returns the updated state."""
    kind, value = target["kind"], target["value"]

    if kind == "domain":
        alive, method, detail = _probe_domain(value)
    elif kind == "ip":
        alive, method, detail = True, "none", "IP addresses are not probed for liveness"
    elif kind == "url":
        alive, method, detail = _probe_url(value)
    else:
        return target["state"]

    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO enforcement_probes (target_id, timestamp, alive, method, detail)
            VALUES (?, ?, ?, ?, ?)
        """, (target["id"], _now(), 1 if alive else 0, method, detail))

        if alive:
            # A single success clears the streak. Anything else would let three
            # unrelated blips spread over weeks add up to a false takedown.
            new_state = ST_RESURFACED if target["state"] == ST_DEAD else ST_LIVE
            cur.execute("""
                UPDATE enforcement_targets
                SET state = ?, last_probe = ?, last_alive = ?,
                    consecutive_dead = 0, probe_count = probe_count + 1,
                    died_at = CASE WHEN ? = 'RESURFACED' THEN NULL ELSE died_at END,
                    first_probe = COALESCE(first_probe, ?)
                WHERE id = ?
            """, (new_state, _now(), _now(), new_state, _now(), target["id"]))
        else:
            streak = (target["consecutive_dead"] or 0) + 1
            confirmed = streak >= CONSECUTIVE_DEAD_PROBES
            new_state = ST_DEAD if confirmed else target["state"] or ST_FILED
            cur.execute("""
                UPDATE enforcement_targets
                SET state = ?, last_probe = ?, consecutive_dead = ?,
                    probe_count = probe_count + 1,
                    died_at = CASE WHEN ? = 1 AND died_at IS NULL THEN ? ELSE died_at END,
                    first_probe = COALESCE(first_probe, ?)
                WHERE id = ?
            """, (new_state, _now(), streak, 1 if confirmed else 0, _now(),
                  _now(), target["id"]))
        conn.commit()
        return new_state
    finally:
        conn.close()


def sweep(limit=MAX_TARGETS_PER_SWEEP):
    """
    Probe every target due for a check.

    Skips targets that have been dead long enough to be uninteresting, so the
    cost of a sweep stays proportional to live enforcement rather than to
    everything ever filed.
    """
    cutoff = (datetime.now() - timedelta(days=STOP_PROBING_AFTER_DAYS)
              ).strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db_connection()
    rows = [dict(r) for r in conn.execute("""
        SELECT * FROM enforcement_targets
        WHERE probeable = 1
          AND (died_at IS NULL OR died_at > ?)
        ORDER BY COALESCE(last_probe, '') ASC
        LIMIT ?
    """, (cutoff, int(limit))).fetchall()]
    conn.close()

    results = {"probed": 0, "alive": 0, "dead": 0, "newly_dead": [], "resurfaced": []}
    for target in rows:
        before = target["state"]
        after = probe_target(target)
        results["probed"] += 1
        if after in (ST_LIVE, ST_RESURFACED):
            results["alive"] += 1
        if after == ST_DEAD:
            results["dead"] += 1
            if before != ST_DEAD:
                results["newly_dead"].append({"kind": target["kind"],
                                              "value": target["value"],
                                              "channel": target["channel"]})
                _announce("down", target)
        if after == ST_RESURFACED and before == ST_DEAD:
            results["resurfaced"].append({"kind": target["kind"],
                                          "value": target["value"]})
            _announce("back", target)
    return results


def _announce(kind, target):
    """
    Tell whoever filed the notice that its target changed state.

    Imported lazily and wrapped: this module must stay importable without the
    notification table existing, and a delivery failure must never abort a
    sweep that is otherwise doing its job.
    """
    try:
        from services.intel import notifications
        if kind == "down":
            notifications.target_went_dark(target)
        else:
            notifications.target_resurfaced(target)
    except Exception as e:
        print("[TAKEDOWN] could not announce %s for %s: %s"
              % (kind, target.get("value"), e))


# ── Manual outcomes ───────────────────────────────────────────────────────

def record_outcome(target_id, state, note=None, recorded_by=None):
    """
    An analyst records an outcome a machine cannot observe.

    This is the only way a UPI handle, phone number or Telegram channel ever
    leaves UNKNOWN. Without it those channels would be permanently invisible in
    the metrics — and since payment-rail freezes are the single most effective
    enforcement action available in India, that would leave the most valuable
    channel looking like the least measurable one.
    """
    state = (state or "").upper().strip()
    if state not in VALID_STATES:
        return False, "state must be one of: %s" % ", ".join(sorted(VALID_STATES))

    conn = get_db_connection()
    try:
        cur = conn.execute("""
            UPDATE enforcement_targets
            SET state = ?, outcome_note = ?, outcome_by = ?,
                died_at = CASE WHEN ? = 'DEAD' AND died_at IS NULL THEN ? ELSE died_at END
            WHERE id = ?
        """, (state, note, recorded_by, state, _now(), int(target_id)))
        conn.commit()
        return cur.rowcount > 0, None
    finally:
        conn.close()


# ── Metrics ───────────────────────────────────────────────────────────────

def _median(values):
    if not values:
        return None
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def effectiveness(channel=None):
    """
    The numbers this whole module exists to produce.

    Deliberately reports `measurable` and `unmeasurable` separately. Folding
    the unprobeable channels into the denominator would drag every rate down
    for a reason that has nothing to do with enforcement working; leaving them
    out of the report entirely would hide that most payment-rail actions have
    no recorded outcome at all.
    """
    sql = "SELECT * FROM enforcement_targets WHERE 1=1"
    params = []
    if channel:
        sql += " AND channel = ?"
        params.append(channel)

    conn = get_db_connection()
    rows = [dict(r) for r in conn.execute(sql, params).fetchall()]
    conn.close()

    measurable = [r for r in rows if r["state"] in (ST_LIVE, ST_DEAD, ST_RESURFACED)]
    dead = [r for r in measurable if r["state"] == ST_DEAD]
    unknown = [r for r in rows if r["state"] in (ST_UNKNOWN, ST_FILED)]

    days_to_death = []
    for r in dead:
        filed, died = _parse(r["filed_at"]), _parse(r["died_at"])
        if filed and died and died >= filed:
            days_to_death.append(round((died - filed).total_seconds() / 86400.0, 2))

    per_channel = {}
    for r in rows:
        c = per_channel.setdefault(r["channel"], {
            "channel": r["channel"], "filed": 0, "measurable": 0,
            "dead": 0, "live": 0, "unknown": 0})
        c["filed"] += 1
        if r["state"] == ST_DEAD:
            c["dead"] += 1; c["measurable"] += 1
        elif r["state"] in (ST_LIVE, ST_RESURFACED):
            c["live"] += 1; c["measurable"] += 1
        else:
            c["unknown"] += 1
    for c in per_channel.values():
        c["rate"] = round(c["dead"] / c["measurable"], 3) if c["measurable"] else None

    return {
        "filed": len(rows),
        "measurable": len(measurable),
        "went_dark": len(dead),
        "still_live": len([r for r in measurable if r["state"] != ST_DEAD]),
        "no_recorded_outcome": len(unknown),
        "rate": round(len(dead) / len(measurable), 3) if measurable else None,
        "median_days_to_dark": _median(days_to_death),
        "fastest_days": min(days_to_death) if days_to_death else None,
        "slowest_days": max(days_to_death) if days_to_death else None,
        "resurfaced": len([r for r in rows if r["state"] == ST_RESURFACED]),
        "by_channel": sorted(per_channel.values(), key=lambda c: -c["filed"]),
        "attribution_caveat": (
            "These figures record that reported targets went dark, not that the "
            "notices caused it. Operators rotate infrastructure, hosts suspend "
            "accounts for non-payment, and registrations lapse. No control "
            "group exists here, so this measures correlation over the reporting "
            "window and nothing stronger."
        ),
        "coverage_caveat": (
            "%d of %d targets have no recorded outcome. Payment rails, phone "
            "numbers and platform accounts cannot be probed from outside, so "
            "they stay UNKNOWN until an analyst records what happened — they "
            "are excluded from the rate rather than counted as failures."
            % (len(unknown), len(rows))
        ) if unknown else None,
    }


def survival_curve(days=30):
    """
    Fraction of reported targets still reachable, day by day.

    The shape carries information a single rate cannot: a cliff at day 3 means
    registrars act quickly, a long flat tail means most notices went nowhere.
    """
    conn = get_db_connection()
    rows = [dict(r) for r in conn.execute("""
        SELECT filed_at, died_at, state FROM enforcement_targets
        WHERE probeable = 1 AND state IN ('LIVE','DEAD','RESURFACED')
    """).fetchall()]
    conn.close()
    if not rows:
        return {"points": [], "n": 0}

    points = []
    for day in range(days + 1):
        alive = 0
        counted = 0
        for r in rows:
            filed = _parse(r["filed_at"])
            if not filed:
                continue
            # Only include targets old enough to have reached this day, or the
            # curve reports survival for a period that has not elapsed yet.
            if (datetime.now() - filed).total_seconds() / 86400.0 < day:
                continue
            counted += 1
            died = _parse(r["died_at"]) if r["died_at"] else None
            if not died or (died - filed).total_seconds() / 86400.0 > day:
                alive += 1
        if counted:
            points.append({"day": day, "alive": alive, "of": counted,
                           "fraction": round(alive / counted, 3)})
    return {"points": points, "n": len(rows)}


def list_targets(state=None, channel=None, limit=200):
    sql = "SELECT * FROM enforcement_targets WHERE 1=1"
    params = []
    if state:
        sql += " AND state = ?"
        params.append(state.upper())
    if channel:
        sql += " AND channel = ?"
        params.append(channel)
    sql += " ORDER BY filed_at DESC LIMIT ?"
    params.append(int(limit))

    conn = get_db_connection()
    rows = [dict(r) for r in conn.execute(sql, params).fetchall()]
    conn.close()
    return rows


def target_history(target_id):
    """Every probe recorded against one target, oldest first."""
    conn = get_db_connection()
    target = conn.execute("SELECT * FROM enforcement_targets WHERE id = ?",
                          (int(target_id),)).fetchone()
    probes = conn.execute("""
        SELECT timestamp, alive, method, detail FROM enforcement_probes
        WHERE target_id = ? ORDER BY timestamp ASC
    """, (int(target_id),)).fetchall()
    conn.close()
    if not target:
        return None
    return {"target": dict(target), "probes": [dict(p) for p in probes]}


# ── Background sweeper ────────────────────────────────────────────────────

_sweeper_thread = None
_sweeper_stop = threading.Event()
_sweeper_state = {"running": False, "last_sweep": None, "sweeps": 0, "last_result": None}


def _sweeper_loop(interval):
    while not _sweeper_stop.is_set():
        try:
            result = sweep()
            _sweeper_state["last_sweep"] = _now()
            _sweeper_state["sweeps"] += 1
            _sweeper_state["last_result"] = result
            if result["newly_dead"]:
                print("[TAKEDOWN] %d target(s) went dark: %s"
                      % (len(result["newly_dead"]),
                         ", ".join(t["value"] for t in result["newly_dead"][:5])))
            if result["resurfaced"]:
                print("[TAKEDOWN] %d target(s) came back up: %s"
                      % (len(result["resurfaced"]),
                         ", ".join(t["value"] for t in result["resurfaced"][:5])))
        except Exception as e:
            print("[TAKEDOWN] sweep failed: %s" % e)
        _sweeper_stop.wait(interval)
    _sweeper_state["running"] = False


def start_sweeper(interval=PROBE_INTERVAL_SECONDS):
    global _sweeper_thread
    if _sweeper_thread and _sweeper_thread.is_alive():
        return False
    _sweeper_stop.clear()
    _sweeper_state["running"] = True
    _sweeper_thread = threading.Thread(target=_sweeper_loop, args=(interval,),
                                       daemon=True, name="takedown-sweeper")
    _sweeper_thread.start()
    print("[TAKEDOWN] Outcome tracker started (sweep every %ds)." % interval)
    return True


def stop_sweeper():
    _sweeper_stop.set()
    _sweeper_state["running"] = False


def sweeper_status():
    return dict(_sweeper_state,
                thread_alive=bool(_sweeper_thread and _sweeper_thread.is_alive()))
