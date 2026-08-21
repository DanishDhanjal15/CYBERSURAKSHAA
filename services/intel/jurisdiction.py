"""
services/intel/jurisdiction.py
------------------------------
Which police force actually investigates this, and where the victim can file.

The gap
=======
"Police" is not one organisation in India. Public order and police are State
subjects under the Seventh Schedule, so cybercrime is investigated by 36
separate forces — 28 States and 8 Union Territories, each with its own cyber
cell. The national bodies coordinate; they do not investigate a UPI fraud in
Nashik.

The platform knew none of this. `blueprints/geo_intel.py` maps a phone prefix
to a telecom circle for the purpose of drawing a dot on a map; the state is
never persisted, never aggregated, and never used to route anything. Every
enforcement channel in `services/intel/actions.py` points at a national entry
point. So a case could be fully worked up and still leave an officer with no
answer to "who do I send this to".

Two things this gets right on purpose
=====================================

**It does not invent contact details.** A wrong phone number for a state cyber
cell sends a victim to a dead line during the hours that decide whether their
money is recoverable. This module names the jurisdiction with confidence and
marks the contact as requiring verification, exactly as
`services/intel/actions.py` does with its `PLACEHOLDER`. The national entry
points — cybercrime.gov.in and 1930 — are pre-filled because they are stable
and universal.

**It states how strong each signal is.** A state derived from a mobile prefix
is a weak inference: numbers port between circles, people roam, and VoIP has
no circle at all. A state the complainant stated is strong. Routing shows
which rule fired and how much weight it carries, so nobody mistakes a guess
for a determination.

Zero FIR
========
The most useful thing to tell somebody being turned away at the wrong police
station: under the proviso to section 173 of the **Bharatiya Nagarik Suraksha
Sanhita 2023** (which replaced the CrPC on 1 July 2024), information about a
cognizable offence may be recorded **irrespective of the area where the
offence was committed**. The FIR is registered with number zero and
transferred to the station with territorial jurisdiction. Refusing to record
it is not lawful, and a victim who knows this is much harder to turn away.
"""

from __future__ import annotations

from datetime import datetime

# ── The 36 jurisdictions ─────────────────────────────────────────────────
#
# Every State and Union Territory. `cyber_cell` deliberately holds no phone
# number or address: see the module docstring. What is recorded is the name of
# the body with jurisdiction, which is stable, and a flag saying the contact
# must be confirmed before use.

CONTACT_PLACEHOLDER = "[RESOLVE: confirm the current cyber cell contact before dispatch]"

NORTH, SOUTH, EAST, WEST, CENTRAL, NORTHEAST = (
    "North", "South", "East", "West", "Central", "North East")

STATES = {
    # ── States ──────────────────────────────────────────────────────────
    "AP": ("Andhra Pradesh", SOUTH, "state"),
    "AR": ("Arunachal Pradesh", NORTHEAST, "state"),
    "AS": ("Assam", NORTHEAST, "state"),
    "BR": ("Bihar", EAST, "state"),
    "CG": ("Chhattisgarh", CENTRAL, "state"),
    "GA": ("Goa", WEST, "state"),
    "GJ": ("Gujarat", WEST, "state"),
    "HR": ("Haryana", NORTH, "state"),
    "HP": ("Himachal Pradesh", NORTH, "state"),
    "JH": ("Jharkhand", EAST, "state"),
    "KA": ("Karnataka", SOUTH, "state"),
    "KL": ("Kerala", SOUTH, "state"),
    "MP": ("Madhya Pradesh", CENTRAL, "state"),
    "MH": ("Maharashtra", WEST, "state"),
    "MN": ("Manipur", NORTHEAST, "state"),
    "ML": ("Meghalaya", NORTHEAST, "state"),
    "MZ": ("Mizoram", NORTHEAST, "state"),
    "NL": ("Nagaland", NORTHEAST, "state"),
    "OD": ("Odisha", EAST, "state"),
    "PB": ("Punjab", NORTH, "state"),
    "RJ": ("Rajasthan", NORTH, "state"),
    "SK": ("Sikkim", NORTHEAST, "state"),
    "TN": ("Tamil Nadu", SOUTH, "state"),
    "TS": ("Telangana", SOUTH, "state"),
    "TR": ("Tripura", NORTHEAST, "state"),
    "UP": ("Uttar Pradesh", NORTH, "state"),
    "UK": ("Uttarakhand", NORTH, "state"),
    "WB": ("West Bengal", EAST, "state"),
    # ── Union Territories ───────────────────────────────────────────────
    "AN": ("Andaman and Nicobar Islands", EAST, "ut"),
    "CH": ("Chandigarh", NORTH, "ut"),
    "DH": ("Dadra and Nagar Haveli and Daman and Diu", WEST, "ut"),
    "DL": ("Delhi (NCT)", NORTH, "ut"),
    "JK": ("Jammu and Kashmir", NORTH, "ut"),
    "LA": ("Ladakh", NORTH, "ut"),
    "LD": ("Lakshadweep", SOUTH, "ut"),
    "PY": ("Puducherry", SOUTH, "ut"),
}

# Codes and names that arrive from other systems or from people typing.
ALIASES = {
    "TG": "TS",                 # Telangana adopted TG alongside the older TS
    "UT": "UK", "UA": "UK",     # Uttarakhand has used several codes
    "OR": "OD",                 # Odisha, formerly Orissa
    "CT": "CG",
    "DD": "DH", "DN": "DH",     # merged into one UT in 2020
    "ND": "DL", "DELHI": "DL", "NEW DELHI": "DL",
    "PONDICHERRY": "PY", "PUDUCHERRY": "PY",
    "J&K": "JK", "JAMMU AND KASHMIR": "JK",
    "MUMBAI": "MH", "PUNE": "MH", "NAGPUR": "MH", "NASHIK": "MH",
    "BENGALURU": "KA", "BANGALORE": "KA",
    "CHENNAI": "TN", "HYDERABAD": "TS", "KOLKATA": "WB",
    "AHMEDABAD": "GJ", "SURAT": "GJ", "JAIPUR": "RJ", "LUCKNOW": "UP",
    "PATNA": "BR", "BHOPAL": "MP", "KOCHI": "KL", "DELHI NCR": "DL",
}

# Confidence in a routing signal. Named rather than numeric because the
# distinction that matters is categorical: a stated state is a fact, a state
# inferred from a phone prefix is a guess.
STRONG, MODERATE, WEAK = "strong", "moderate", "weak"

# National entry points. These are stable and universal, so unlike the state
# contacts they are pre-filled.
NATIONAL = {
    "portal": "https://cybercrime.gov.in",
    "helpline": "1930",
    "authority": "Indian Cyber Crime Coordination Centre (I4C), Ministry of Home Affairs",
}


def normalise(code_or_name):
    """
    Resolve a code, alias or city to a State/UT code. None if unrecognised.

    Accepts what other parts of the platform actually produce — `geo_intel`
    emits names like "Delhi NCR" and "Maharashtra", people type "Mumbai".
    """
    if not code_or_name:
        return None
    key = str(code_or_name).strip().upper()
    if key in STATES:
        return key
    if key in ALIASES:
        return ALIASES[key]
    for code, (name, _region, _kind) in STATES.items():
        if key == name.upper():
            return code
    # Last resort: a unique prefix match on the full name, so "MAHARASHTRA "
    # or "TAMIL NADU" with odd spacing still resolves.
    matches = [c for c, (n, _, _) in STATES.items() if n.upper().startswith(key)]
    return matches[0] if len(matches) == 1 else None


def get(code_or_name):
    """The jurisdiction record for one State/UT."""
    code = normalise(code_or_name)
    if not code:
        return None
    name, region, kind = STATES[code]
    return {
        "code": code,
        "name": name,
        "region": region,
        "type": kind,
        "cyber_cell": "%s Police — Cyber Crime Unit" % name,
        "contact": CONTACT_PLACEHOLDER,
        "contact_verified": False,
        "national": dict(NATIONAL),
    }


def all_jurisdictions():
    return [get(code) for code in sorted(STATES)]


def by_region():
    grouped = {}
    for code in sorted(STATES):
        record = get(code)
        grouped.setdefault(record["region"], []).append(record)
    return grouped


# ── Routing ──────────────────────────────────────────────────────────────

def route(stated_state=None, phone=None, beneficiary_state=None,
          infrastructure_state=None):
    """
    Decide which jurisdiction to route to, and show the reasoning.

    Rules are evaluated strongest first and every candidate is returned, not
    just the winner — a case where the victim is in Bihar and the mule account
    is in Maharashtra involves both forces, and hiding that behind a single
    answer would be worse than useless.

    Returns a dict with `primary`, `candidates`, `rule`, `confidence` and the
    Zero FIR guidance. `primary` is None when nothing could be determined,
    which is reported rather than guessed at.
    """
    candidates = []

    if stated_state:
        record = get(stated_state)
        if record:
            candidates.append({
                "jurisdiction": record, "confidence": STRONG,
                "rule": "complainant_state",
                "reason": ("The complainant stated they are in %s. Under BNSS "
                           "the complaint is ordinarily registered where the "
                           "victim is, and the loss was suffered there."
                           % record["name"]),
            })

    if beneficiary_state:
        record = get(beneficiary_state)
        if record:
            candidates.append({
                "jurisdiction": record, "confidence": MODERATE,
                "rule": "beneficiary_state",
                "reason": ("The receiving account is held in %s. That force "
                           "will need to act on the account itself, and the "
                           "money trail is investigated there."
                           % record["name"]),
            })

    if phone:
        record, note = _from_phone(phone)
        if record:
            candidates.append({
                "jurisdiction": record, "confidence": WEAK,
                "rule": "telecom_circle",
                "reason": note,
            })

    if infrastructure_state:
        record = get(infrastructure_state)
        if record:
            candidates.append({
                "jurisdiction": record, "confidence": WEAK,
                "rule": "infrastructure_state",
                "reason": ("Hosting infrastructure resolves to %s. This locates "
                           "a server, not a person, and CDNs and proxies make "
                           "it frequently misleading." % record["name"]),
            })

    order = {STRONG: 0, MODERATE: 1, WEAK: 2}
    candidates.sort(key=lambda c: order[c["confidence"]])

    primary = candidates[0] if candidates else None
    distinct = {c["jurisdiction"]["code"] for c in candidates}

    return {
        "primary": primary["jurisdiction"] if primary else None,
        "rule": primary["rule"] if primary else None,
        "confidence": primary["confidence"] if primary else None,
        "reason": primary["reason"] if primary else (
            "No jurisdiction could be determined from the information "
            "available. Route through the national portal, and ask the "
            "complainant which State or Union Territory they are in — it is "
            "the single most useful field and the only strong signal."),
        "candidates": candidates,
        "multi_jurisdiction": len(distinct) > 1,
        "multi_jurisdiction_note": (
            "This case touches %d jurisdictions. Cybercrime routinely does: "
            "the victim, the mule account and the infrastructure are commonly "
            "in three different States. Each force acts on what is within its "
            "territory, coordinated through I4C." % len(distinct)
            if len(distinct) > 1 else None),
        "national": dict(NATIONAL),
        "zero_fir": zero_fir_guidance(),
    }


def _from_phone(phone):
    """
    Infer a State from an Indian mobile number's telecom circle.

    Reuses the prefix tables in `blueprints/geo_intel.py` rather than
    duplicating them, and carries forward that module's honesty about what a
    circle actually means.
    """
    digits = "".join(ch for ch in str(phone) if ch.isdigit())
    if len(digits) > 10:
        digits = digits[-10:]
    if len(digits) != 10:
        return None, None

    try:
        from blueprints.geo_intel import PHONE_PREFIX_MAP, TELECOM_CIRCLES
    except Exception:
        return None, None

    info = PHONE_PREFIX_MAP.get(digits[:4])
    if info:
        record = get(info["state"])
        if record:
            return record, (
                "The number's four-digit prefix is issued in the %s circle. "
                "Portability, roaming and VoIP all break this, so treat it as "
                "a lead rather than a location." % record["name"])

    circles = TELECOM_CIRCLES.get(digits[:2])
    if circles:
        # A two-digit prefix genuinely maps to several circles; geo_intel picks
        # deterministically from the remaining digits so a number always
        # resolves the same way. The weakness is inherent, not a defect.
        try:
            selector = int(digits[2:6])
        except ValueError:
            selector = 0
        chosen = circles[selector % len(circles)]
        record = get(chosen["state"])
        if record:
            return record, (
                "A two-digit prefix is shared across %d circles and does not "
                "identify one. %s is the deterministic choice so the same "
                "number always resolves alike — it is close to no evidence at "
                "all." % (len(circles), record["name"]))
    return None, None


# ── Zero FIR ─────────────────────────────────────────────────────────────

def zero_fir_guidance():
    """
    What to tell someone being turned away at the wrong police station.

    This is the highest-value paragraph in the module. A victim in the golden
    hour who is sent away to find "the right station" loses the window in
    which their money could have been held.
    """
    return {
        "title": "You may file at any police station",
        "basis": ("Proviso to section 173, Bharatiya Nagarik Suraksha Sanhita "
                  "2023 (in force from 1 July 2024, replacing the Code of "
                  "Criminal Procedure 1973)"),
        "summary": ("Information about a cognizable offence must be recorded "
                    "irrespective of the area where the offence was committed. "
                    "It is registered as a Zero FIR and transferred to the "
                    "station with territorial jurisdiction for investigation."),
        "points": [
            "You do not have to travel to the place where the fraud happened, "
            "or to where the accused is.",
            "The station cannot lawfully refuse to record it on the ground "
            "that the offence occurred elsewhere.",
            "Ask for it to be registered as a Zero FIR. Get the FIR number and "
            "a copy before you leave — you are entitled to one free of charge.",
            "Do this in parallel with reporting on cybercrime.gov.in or by "
            "calling 1930, not instead of it. The portal is what triggers the "
            "request to hold the money; the FIR is what makes it a case.",
            "If a station still refuses, the complaint can be sent in writing "
            "to the Superintendent of Police.",
        ],
        "urgency": ("Do not let a jurisdiction argument consume the first "
                    "hours. Call 1930 first — a lien on the receiving account "
                    "is time-critical and does not wait on the FIR."),
    }


# ── Aggregation ──────────────────────────────────────────────────────────

def loss_by_jurisdiction(days=None):
    """
    Reported losses grouped by State/UT.

    Builds on `services/intel/harm.by_state()`, resolving raw codes into named
    jurisdictions and reporting how much could not be attributed at all —
    which is the figure that says how much to trust the rest.
    """
    try:
        from services.intel import harm
    except Exception as e:
        return {"error": "loss data unavailable: %s" % e, "rows": []}

    rows = []
    unattributed = {"reports": 0, "total": 0}

    for entry in harm.by_state(days=days):
        record = get(entry["key"])
        if not record:
            unattributed["reports"] += entry["reports"]
            unattributed["total"] += entry["total"] or 0
            continue
        rows.append({
            "code": record["code"],
            "name": record["name"],
            "region": record["region"],
            "reports": entry["reports"],
            "total": entry["total"],
            "total_display": entry["total_display"],
        })

    rows.sort(key=lambda r: -(r["total"] or 0))
    return {
        "rows": rows,
        "jurisdictions_with_losses": len(rows),
        "unattributed": unattributed,
        "note": (
            "%d report(s) carry no recognisable State or Union Territory and "
            "are excluded from this breakdown. State is the strongest routing "
            "signal available and is worth capturing at intake."
            % unattributed["reports"]) if unattributed["reports"] else None,
        "caveat": (
            "Grouped by the State the complainant reported from. The receiving "
            "account and the infrastructure are frequently elsewhere, so this "
            "shows where harm was suffered rather than where an operation is "
            "based."),
    }


def summary():
    return {
        "jurisdictions": len(STATES),
        "states": sum(1 for _, (_, _, k) in STATES.items() if k == "state"),
        "union_territories": sum(1 for _, (_, _, k) in STATES.items() if k == "ut"),
        "contacts_verified": 0,
        "contact_note": (
            "No state cyber cell contact is pre-filled. A wrong number sends a "
            "victim to a dead line during the hours that decide whether their "
            "money is recoverable, so each is marked for verification before "
            "dispatch. The national channels — cybercrime.gov.in and 1930 — "
            "are stable and are filled in."),
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
