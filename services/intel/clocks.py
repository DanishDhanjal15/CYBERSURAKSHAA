"""
services/intel/clocks.py
------------------------
Statutory and operational deadlines, computed rather than described.

The gap this closes
===================
The platform has always talked about deadlines and never tracked one.
`services/intel/actions.py` tells analysts the golden hour is "the single
largest determinant of recovery". `services/takedown_generator.py` prints a
thirty-six hour compliance period on every notice. Neither is a date. Nothing
computes when the window closes, nothing reports that it has, and the takedown
notice does not even record when it was served — so the clock it prints starts
from a moment the system never observed.

Four clocks matter here, and three of them have a legal basis rather than an
operational one.

The one that matters most to a victim
=====================================
**The RBI limited-liability window.** Under the Reserve Bank's directions on
customer liability in unauthorised electronic banking transactions, a
customer's exposure depends almost entirely on how quickly they tell their
*bank*:

  * reported within **3 working days** — **zero liability**, the bank bears it;
  * reported within **4 to 7 working days** — liability limited to a capped
    amount that varies with the account type;
  * beyond 7 working days — governed by the bank's own board-approved policy.

That is the difference between a person losing nothing and losing everything,
and it turns on a countdown nobody was showing them. It runs from the
customer's report *to the bank* — a different event from telling this platform,
which is why `harm.mark_bank_reported()` records it separately.

Working days, honestly
======================
"Working days" is not "days". Indian banks are closed on Sundays and on the
second and fourth Saturday of each month, and additionally on gazetted and
state-specific holidays that vary by state and by year. This module handles
Sundays and the Saturday rule, which is deterministic; it does **not** hold a
holiday calendar, and every result says so. A countdown that silently ignored
Diwali would tell somebody they had two days left when they had none.
"""

from __future__ import annotations

from datetime import datetime, timedelta

# ── Bases ────────────────────────────────────────────────────────────────

GOLDEN_HOUR_MINUTES = 60

# RBI customer-liability directions.
RBI_ZERO_LIABILITY_DAYS = 3
RBI_LIMITED_LIABILITY_DAYS = 7

# CERT-In Directions of 28 April 2022 under s.70B(6), IT Act 2000.
CERT_IN_HOURS = 6

# IT Act s.79(3)(b) read with the Intermediary Guidelines Rules.
INTERMEDIARY_HOURS = 36

# Status vocabulary shared by every clock.
ST_RUNNING = "RUNNING"
ST_DUE_SOON = "DUE_SOON"
ST_BREACHED = "BREACHED"
ST_MET = "MET"
ST_UNKNOWN = "UNKNOWN"

# Fraction of a window remaining below which it is called due soon.
DUE_SOON_FRACTION = 0.25


def _parse(ts):
    if not ts:
        return None
    if isinstance(ts, datetime):
        return ts
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(str(ts)[:19], fmt)
        except ValueError:
            continue
    return None


def _stamp(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S") if dt else None


# ── Working days ─────────────────────────────────────────────────────────

def is_bank_working_day(day):
    """
    Whether Indian banks are open, on the rules that are deterministic.

    Closed on Sundays, and on the second and fourth Saturday of the month.
    Gazetted and state holidays are **not** covered — see the module docstring.
    """
    if day.weekday() == 6:            # Sunday
        return False
    if day.weekday() == 5:            # Saturday: which one of the month?
        return ((day.day - 1) // 7) + 1 not in (2, 4)
    return True


def add_working_days(start, days):
    """The date `days` bank working days after `start`."""
    current = start
    remaining = int(days)
    while remaining > 0:
        current += timedelta(days=1)
        if is_bank_working_day(current):
            remaining -= 1
    return current


def working_days_between(start, end):
    """Working days elapsed from `start` to `end`, not counting the start day."""
    if not start or not end or end < start:
        return None
    count = 0
    current = start.date()
    last = end.date()
    while current < last:
        current += timedelta(days=1)
        if is_bank_working_day(datetime.combine(current, datetime.min.time())):
            count += 1
    return count


# ── Clock construction ───────────────────────────────────────────────────

def _clock(name, basis, started_at, deadline_at, satisfied_at=None,
           note=None, unit="hours", caveat=None):
    """One clock, with everything a caller needs to render or act on it."""
    now = datetime.now()
    started = _parse(started_at)
    deadline = _parse(deadline_at)
    satisfied = _parse(satisfied_at)

    if not started or not deadline:
        return {"name": name, "basis": basis, "status": ST_UNKNOWN,
                "started_at": _stamp(started), "deadline_at": _stamp(deadline),
                "note": note or "Cannot be computed: the starting event was "
                                "never recorded.",
                "caveat": caveat}

    if satisfied:
        status = ST_MET if satisfied <= deadline else ST_BREACHED
        remaining = None
    else:
        total = (deadline - started).total_seconds()
        left = (deadline - now).total_seconds()
        remaining = left
        if left <= 0:
            status = ST_BREACHED
        elif total > 0 and (left / total) <= DUE_SOON_FRACTION:
            status = ST_DUE_SOON
        else:
            status = ST_RUNNING

    return {
        "name": name,
        "basis": basis,
        "status": status,
        "started_at": _stamp(started),
        "deadline_at": _stamp(deadline),
        "satisfied_at": _stamp(satisfied),
        "remaining_seconds": int(remaining) if remaining is not None else None,
        "remaining_human": _humanise(remaining),
        "unit": unit,
        "note": note,
        "caveat": caveat,
    }


def _humanise(seconds):
    if seconds is None:
        return None
    overdue = seconds < 0
    seconds = abs(seconds)
    days, rem = divmod(int(seconds), 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60

    if days:
        text = "%dd %dh" % (days, hours)
    elif hours:
        text = "%dh %dm" % (hours, minutes)
    else:
        text = "%dm" % minutes
    return ("%s overdue" % text) if overdue else ("%s left" % text)


# ── The clocks ───────────────────────────────────────────────────────────

def golden_hour(incident_at, reported_at=None):
    """
    The window in which a lien on the beneficiary account is most likely.

    Operational guidance rather than statute, and labelled as such. Reporting
    to 1930 or cybercrime.gov.in inside the first hour is what the National
    Cyber Crime Reporting system is built around.
    """
    incident = _parse(incident_at)
    if not incident:
        return _clock("Golden hour", "I4C / 1930 operational guidance",
                      None, None, unit="minutes")
    return _clock(
        "Golden hour",
        "I4C / 1930 operational guidance (not a statutory limit)",
        incident,
        incident + timedelta(minutes=GOLDEN_HOUR_MINUTES),
        satisfied_at=reported_at,
        unit="minutes",
        note=("Report to 1930 or cybercrime.gov.in. A lien placed inside this "
              "window is the strongest predictor of the money being held."),
    )


def rbi_liability(incident_at, bank_reported_at=None):
    """
    The customer's liability band under the RBI directions.

    Returns both clocks — zero-liability and limited-liability — plus the band
    the customer currently falls in and what it means for them in money.
    """
    incident = _parse(incident_at)
    reported = _parse(bank_reported_at)

    caveat = ("Working days here exclude Sundays and the second and fourth "
              "Saturday of each month. Gazetted and state holidays are not "
              "accounted for, so treat these dates as the latest possible and "
              "act earlier. Liability caps vary by account type — confirm with "
              "the bank.")

    if not incident:
        return {"band": ST_UNKNOWN,
                "meaning": "The time the money moved was not recorded, so the "
                           "liability window cannot be computed.",
                "clocks": [], "caveat": caveat}

    zero_deadline = add_working_days(incident, RBI_ZERO_LIABILITY_DAYS)
    limited_deadline = add_working_days(incident, RBI_LIMITED_LIABILITY_DAYS)

    clocks = [
        _clock("Zero liability",
               "RBI directions on customer liability in unauthorised "
               "electronic banking transactions",
               incident, zero_deadline, satisfied_at=bank_reported_at,
               unit="working days",
               note="Report to the BANK within %d working days and the customer "
                    "bears no loss." % RBI_ZERO_LIABILITY_DAYS,
               caveat=caveat),
        _clock("Limited liability",
               "RBI directions on customer liability",
               incident, limited_deadline, satisfied_at=bank_reported_at,
               unit="working days",
               note="Between %d and %d working days the customer's liability is "
                    "capped by account type."
                    % (RBI_ZERO_LIABILITY_DAYS + 1, RBI_LIMITED_LIABILITY_DAYS),
               caveat=caveat),
    ]

    if reported:
        elapsed = working_days_between(incident, reported)
        if elapsed is None:
            band, meaning = ST_UNKNOWN, "The bank report predates the incident."
        elif elapsed <= RBI_ZERO_LIABILITY_DAYS:
            band = "ZERO_LIABILITY"
            meaning = ("Reported to the bank %d working day(s) after the "
                       "transaction. On the RBI directions the customer bears "
                       "no liability." % elapsed)
        elif elapsed <= RBI_LIMITED_LIABILITY_DAYS:
            band = "LIMITED_LIABILITY"
            meaning = ("Reported %d working day(s) after the transaction. "
                       "Liability is capped by account type rather than "
                       "unlimited." % elapsed)
        else:
            band = "BANK_POLICY"
            meaning = ("Reported %d working day(s) after the transaction, "
                       "beyond the directions' windows. Liability is governed "
                       "by the bank's own board-approved policy." % elapsed)
    else:
        band = "NOT_YET_REPORTED"
        meaning = ("The customer has not yet reported to their bank. This is "
                   "the single most valuable thing they can do, and the window "
                   "is closing.")

    return {"band": band, "meaning": meaning, "clocks": clocks, "caveat": caveat,
            "working_days_elapsed": working_days_between(incident, reported or datetime.now())}


def cert_in(noticed_at, reported_at=None):
    """
    CERT-In's six-hour incident reporting obligation.

    Directions of 28 April 2022 under s.70B(6) of the IT Act. Runs from when
    the incident was *noticed*, not when it occurred, and applies to the
    categories the Directions specify rather than to everything.
    """
    noticed = _parse(noticed_at)
    if not noticed:
        return _clock("CERT-In reporting", "IT Act s.70B(6) Directions, 28 April 2022",
                      None, None)
    return _clock(
        "CERT-In reporting",
        "IT Act s.70B(6) Directions, 28 April 2022",
        noticed, noticed + timedelta(hours=CERT_IN_HOURS),
        satisfied_at=reported_at,
        note=("Specified incident categories must be reported to CERT-In within "
              "six hours of being noticed."),
        caveat=("The obligation applies to the incident types listed in the "
                "Directions. Confirm the incident falls within them before "
                "treating this clock as binding."),
    )


def intermediary_compliance(served_at, complied_at=None):
    """
    The thirty-six hours an intermediary has after a s.79(3)(b) notice.

    Runs from **service** of the notice, not from the scan. The takedown
    generator has printed this period on every notice it produced while never
    recording when the notice was served, which made the clock uncomputable.
    """
    served = _parse(served_at)
    if not served:
        return _clock("Intermediary compliance",
                      "IT Act s.79(3)(b) and the Intermediary Guidelines Rules",
                      None, None,
                      note="The notice has not been recorded as served, so the "
                           "thirty-six hour period has not started.")
    return _clock(
        "Intermediary compliance",
        "IT Act s.79(3)(b) and the Intermediary Guidelines Rules",
        served, served + timedelta(hours=INTERMEDIARY_HOURS),
        satisfied_at=complied_at,
        note=("Failure to disable access within thirty-six hours of receipt "
              "removes the safe harbour under s.79(1)."),
    )


# ── Aggregation ──────────────────────────────────────────────────────────

def for_victim_report(report):
    """
    Every clock relevant to one recorded loss.

    `report` is a row from services/intel/harm.get_report().
    """
    clocks = [golden_hour(report.get("incident_at"), report.get("reported_at"))]
    liability = rbi_liability(report.get("incident_at"), report.get("bank_reported_at"))
    clocks.extend(liability["clocks"])
    return {
        "clocks": clocks,
        "liability": {k: v for k, v in liability.items() if k != "clocks"},
        "most_urgent": _most_urgent(clocks),
    }


def _most_urgent(clocks):
    """The clock a person should act on first."""
    live = [c for c in clocks
            if c["status"] in (ST_RUNNING, ST_DUE_SOON)
            and c.get("remaining_seconds") is not None]
    if live:
        return min(live, key=lambda c: c["remaining_seconds"])
    breached = [c for c in clocks if c["status"] == ST_BREACHED]
    return breached[0] if breached else None


def summary():
    """
    Live compliance position across every recorded loss.

    Counts rather than lists: this drives an admin tile, and the detail lives
    on the report it belongs to.
    """
    try:
        from services.intel import harm
        reports = harm.list_reports(limit=1000)
    except Exception as e:
        return {"error": "loss reports unavailable: %s" % e, "reports": 0}

    counts = {"zero_liability_open": 0, "limited_liability_open": 0,
              "windows_closed": 0, "not_reported_to_bank": 0,
              "golden_hour_met": 0, "no_incident_time": 0}

    for r in reports:
        if not r.get("incident_at"):
            counts["no_incident_time"] += 1
            continue
        if r.get("golden_hour"):
            counts["golden_hour_met"] += 1
        if not r.get("bank_reported_at"):
            counts["not_reported_to_bank"] += 1

        liability = rbi_liability(r.get("incident_at"), r.get("bank_reported_at"))
        statuses = {c["name"]: c["status"] for c in liability["clocks"]}
        if statuses.get("Zero liability") in (ST_RUNNING, ST_DUE_SOON):
            counts["zero_liability_open"] += 1
        elif statuses.get("Limited liability") in (ST_RUNNING, ST_DUE_SOON):
            counts["limited_liability_open"] += 1
        elif statuses.get("Limited liability") == ST_BREACHED:
            counts["windows_closed"] += 1

    counts["reports"] = len(reports)
    counts["caveat"] = (
        "Working-day arithmetic excludes Sundays and the second and fourth "
        "Saturday only. Gazetted and state holidays are not modelled, so a "
        "window may close earlier than shown."
    )
    return counts
