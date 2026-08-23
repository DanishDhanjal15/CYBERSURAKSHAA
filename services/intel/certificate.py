"""
services/intel/certificate.py
-----------------------------
Certificate under section 63(4), Bharatiya Sakshya Adhiniyam 2023.

Why this exists
===============
The platform has produced a tamper-evident record of every scan since the
evidence chain was built. That record is technically sound and legally inert:
in an Indian court an electronic record is not admissible on its own merits.
It becomes admissible when it is accompanied by a certificate.

Until 1 July 2024 that certificate lived in section 65B of the Indian Evidence
Act 1872. From that date the Evidence Act was replaced by the **Bharatiya
Sakshya Adhiniyam 2023**, and the equivalent provision is **section 63**. Any
material citing 65B today is citing a repealed statute.

So this module is the bridge between what the platform already knows — the
SHA-256 of the artefact, when it was processed, by which module, under what
chain entry — and the form in which a magistrate can receive it.

What section 63 requires
========================
s.63(2) sets four conditions the computer output must satisfy:

  (a) it was produced during a period in which the device was **used regularly**
      to store or process information for activities regularly carried on by
      the person having lawful control of it;
  (b) information of that kind was **regularly fed in** in the ordinary course
      of those activities;
  (c) the device was **operating properly** throughout the material part of
      that period, or any malfunction did not affect the accuracy of the record;
  (d) the information **reproduces or is derived from** information fed in in
      the ordinary course.

s.63(4) then requires a certificate that identifies the record, describes how
it was produced, gives the particulars of the device, and addresses the s.63(2)
conditions. The Schedule to the Act sets the form: **Part A** completed by the
party producing the record, **Part B** by an expert, with the **hash of the
record** stated and the algorithm named.

Note the change from the old law: s.63(4) requires the signature of the person
in charge of the device **and** of an expert. A single signatory is no longer
sufficient.

What this module will and will not do
=====================================
It fills in every fact the platform actually knows, and **nothing else**.

It does not sign. It cannot: signature under s.63(4) is an attestation by a
named human who is in charge of the system or who has examined it as an
expert, and a program asserting either would be producing exactly the kind of
unverifiable document the section exists to exclude. Both signature blocks are
left blank, the document says on its face that it is a draft, and the
statements in Part A are framed as facts recorded by the system for a
certifying person to adopt or correct — not as assertions the software is
making on anybody's behalf.
"""

from __future__ import annotations

import hashlib
import os
import platform
import sys
from datetime import datetime

from services.intel import evidence
from services.intel.db import get_db_connection

# Named in the Schedule to the Act. SHA-256 is what the platform computes for
# every artefact, which is why it is the default here.
HASH_ALGORITHM = "SHA-256"

# The four conditions of s.63(2), quoted so a certifying officer can see
# exactly what they are being asked to adopt rather than a paraphrase.
S63_2_CONDITIONS = [
    ("a", "Regular use",
     "The computer output containing the information was produced by the "
     "computer or communication device during the period over which it was "
     "used regularly to create, store or process information for the purposes "
     "of activities regularly carried on over that period by the person having "
     "lawful control over the use of that device."),
    ("b", "Ordinary course of activity",
     "During the said period, information of the kind contained in the "
     "electronic record was regularly fed into the computer or communication "
     "device in the ordinary course of the said activities."),
    ("c", "Proper operation",
     "Throughout the material part of the said period the computer or "
     "communication device was operating properly; or, if not, any respect in "
     "which it was not operating properly or was out of operation during that "
     "part of the period was not such as to affect the electronic record or "
     "the accuracy of its contents."),
    ("d", "Derivation",
     "The information contained in the electronic record reproduces or is "
     "derived from such information fed into the computer or communication "
     "device in the ordinary course of the said activities."),
]


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _get_scan(scan_id):
    """
    Read the scan through this module's own connection.

    Deliberately not `services.auth_db.get_scan`. That module resolves its
    database path independently, so reading the scan through it while reading
    the evidence chain through `services.intel.db` means two connection
    policies over what is meant to be one database. In production both land on
    the same file and it works by coincidence; anywhere they diverge the scan
    silently reads as missing and no certificate can be produced for a record
    that plainly exists. `services/intel/accounts.py` carries the same note for
    the same reason.
    """
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (int(scan_id),)).fetchone()
        return dict(row) if row else None
    except Exception:
        return None
    finally:
        conn.close()


# ── Facts the platform can actually state ────────────────────────────────

def device_particulars():
    """
    Particulars of the device that produced the record, per s.63(4)(b).

    For a server-side platform "the device" is the host the application runs
    on. These are the identifying facts an expert examining the system would
    check against, and every one is read from the running environment rather
    than configured — a certificate describing a device other than the one
    that produced the record would be worse than none.
    """
    return {
        "host": platform.node() or "unknown",
        "operating_system": "%s %s" % (platform.system(), platform.release()),
        "architecture": platform.machine(),
        "runtime": "Python %s" % sys.version.split()[0],
        "application": "CYBERSURAKSHAA National Threat Detection Suite",
        "database": os.environ.get("DB_PATH", "cybersurakshaa.db"),
        "timezone": datetime.now().astimezone().tzname() or "system local time",
    }


def _regular_use_window():
    """
    The period over which the system has been in regular use, evidenced.

    s.63(2)(a) turns on regular use over a period. The evidence chain is the
    system's own record of that: its first and last entries bound the period,
    and the count shows the activity was continuous rather than got up for the
    occasion.
    """
    conn = get_db_connection()
    try:
        row = conn.execute("""
            SELECT MIN(timestamp) AS first_entry,
                   MAX(timestamp) AS last_entry,
                   COUNT(*)       AS entries
            FROM evidence_chain
        """).fetchone()
        scans = conn.execute("SELECT COUNT(*) AS n FROM scans").fetchone()["n"]
    except Exception:
        return {"first_entry": None, "last_entry": None, "entries": 0, "scans": 0}
    finally:
        conn.close()

    return {
        "first_entry": row["first_entry"],
        "last_entry": row["last_entry"],
        "entries": row["entries"],
        "scans": scans,
    }


def chain_of_custody(artefact_hash):
    """
    Every recorded handling of one artefact, oldest first.

    Drawn from the evidence chain rather than assembled for the certificate,
    which is the point: the custody record existed before anybody asked for it.
    """
    if not artefact_hash:
        return []
    conn = get_db_connection()
    rows = [dict(r) for r in conn.execute("""
        SELECT seq, timestamp, event, actor, subject_type, subject_id, entry_hash
        FROM evidence_chain
        WHERE LOWER(artefact_hash) = ?
        ORDER BY seq ASC
    """, (artefact_hash.lower(),)).fetchall()]
    conn.close()
    return rows


def verify_artefact_hash(file_path, expected_hash):
    """
    Recompute the hash of a stored artefact and compare.

    Part A of the Schedule states a hash. Stating one that was recorded months
    ago without re-deriving it from the bytes now present would certify a claim
    nobody had checked. Where the artefact is no longer held, that is reported
    honestly rather than passed over.
    """
    if not file_path or not os.path.exists(file_path):
        return {"checked": False,
                "reason": "The artefact is not retained by this system, so its "
                          "hash could not be recomputed at the time of this "
                          "certificate."}
    try:
        digest = hashlib.sha256()
        with open(file_path, "rb") as fh:
            for block in iter(lambda: fh.read(65536), b""):
                digest.update(block)
        actual = digest.hexdigest()
        return {"checked": True, "matches": actual == (expected_hash or "").lower(),
                "recomputed": actual}
    except Exception as e:
        return {"checked": False, "reason": "Could not read the stored artefact: %s" % e}


# ── Assembly ─────────────────────────────────────────────────────────────

def build_certificate(scan_id, base_url=None, artefact_path=None):
    """
    Assemble the certificate content for one scan.

    Returns a dict, not a document — the PDF and HTML renderers both consume
    this, and so can a test. `None` when the scan does not exist.
    """
    scan = _get_scan(scan_id)
    if not scan:
        return None

    artefact_hash = (scan.get("file_hash") or "").lower() or None
    from services.public_url import public_base_url
    base_url = public_base_url(base_url)

    custody = chain_of_custody(artefact_hash)
    chain_state = evidence.verify_chain()
    window = _regular_use_window()

    return {
        "reference": "CS-BSA63-DRAFT/%d/%04d" % (datetime.now().year, scan_id),
        "generated_at": _now(),
        "statute": {
            "act": "Bharatiya Sakshya Adhiniyam, 2023",
            "section": "63(4)",
            "note": ("Section 63 replaced section 65B of the Indian Evidence "
                     "Act 1872 with effect from 1 July 2024. A certificate "
                     "citing section 65B relies on a repealed provision."),
            "signatories_required": (
                "Section 63(4) requires this certificate to be signed by the "
                "person in charge of the computer or communication device, or "
                "of the management of the relevant activities, AND by an "
                "expert. One signature alone does not satisfy the section."),
        },

        # ── Part A: the electronic record ────────────────────────────────
        "record": {
            "scan_id": scan_id,
            "produced_at": scan.get("timestamp"),
            "module": scan.get("module"),
            "verdict": scan.get("verdict"),
            "score": scan.get("score"),
            "description": scan.get("input_summary"),
            "submitted_by": scan.get("username"),
            "hash_algorithm": HASH_ALGORITHM,
            "hash": artefact_hash,
            "hash_recheck": verify_artefact_hash(artefact_path, artefact_hash),
            "manner_of_production": (
                "The artefact was submitted to the CYBERSURAKSHAA platform "
                "through its web interface or authenticated API and processed "
                "by the %s detection module. The SHA-256 digest recorded above "
                "was computed over the submitted bytes at the time of "
                "processing, before any analysis was performed. The verdict "
                "and score were produced by that module and written to the "
                "platform database in the ordinary course of its operation."
                % (scan.get("module") or "relevant")),
        },

        "device": device_particulars(),

        # ── s.63(2) conditions, with the evidence for each ───────────────
        "conditions": [
            {"clause": clause, "heading": heading, "text": text,
             "system_evidence": _condition_evidence(clause, window, chain_state)}
            for clause, heading, text in S63_2_CONDITIONS
        ],

        # ── Custody and integrity ────────────────────────────────────────
        "custody": custody,
        "chain": {
            "valid": chain_state.get("valid"),
            "entries_verified": chain_state.get("checked"),
            "head": chain_state.get("head") or evidence.head().get("entry_hash"),
            "broken_at": chain_state.get("broken_at"),
            "reason": chain_state.get("reason"),
        },
        "verification_url": (evidence.verification_url(base_url, artefact_hash)
                             if artefact_hash else None),

        "limits": _limits(chain_state, artefact_hash, custody),
    }


def _condition_evidence(clause, window, chain_state):
    """
    What the system can actually show for each s.63(2) condition.

    Deliberately evidence rather than assertion. The certifying person adopts
    the statement; the platform's job is to put in front of them what it
    observed, including where it observed nothing.
    """
    if clause == "a":
        if not window["entries"]:
            return ("No audit history is present, so regular use over a period "
                    "cannot be evidenced from this system's own records.")
        return ("The platform's append-only audit log holds %d entries spanning "
                "%s to %s, and the database holds %d processed artefacts, "
                "evidencing continuous operational use over that period."
                % (window["entries"], window["first_entry"] or "—",
                   window["last_entry"] or "—", window["scans"]))

    if clause == "b":
        return ("Artefacts of this kind are submitted and processed as the "
                "platform's ordinary and only function. This record was created "
                "by that routine process and not by any separate or special "
                "operation undertaken for the purposes of this certificate.")

    if clause == "c":
        if chain_state.get("valid"):
            return ("The audit chain re-walks cleanly across all %d entries: "
                    "each entry's stored hash matches a recomputation over its "
                    "own contents and its predecessor's hash. No interruption "
                    "affecting the integrity of stored records is evidenced."
                    % chain_state.get("checked", 0))
        return ("THE AUDIT CHAIN DOES NOT VERIFY. Verification failed at "
                "sequence %s (%s). This condition cannot be certified on the "
                "present state of the system and the discrepancy must be "
                "investigated before this record is relied upon."
                % (chain_state.get("broken_at"), chain_state.get("reason")))

    return ("The values stated in this certificate are read directly from the "
            "platform database records created when the artefact was processed. "
            "They are reproductions of information fed in in the ordinary "
            "course, not derived or recalculated for this document.")


def _limits(chain_state, artefact_hash, custody):
    """
    What this certificate does not establish.

    Included in the document itself. A certificate that overstates is worse
    than one that is refused, because it is relied upon.
    """
    limits = [
        "This document is a DRAFT prepared by an automated system. It has no "
        "effect until completed and signed by the persons section 63(4) "
        "requires — the person in charge of the device or of the management of "
        "the relevant activities, and an expert.",
        "The audit chain demonstrates that stored records are internally "
        "consistent and have not been altered in place. It is a hash chain, "
        "not a digital signature, and it cannot by itself exclude the "
        "possibility that the entire log was rewritten by a person with write "
        "access to the whole database.",
        "The detection verdict recorded in this certificate is the output of "
        "an automated classifier. It is an investigative finding, not a "
        "finding of fact, and its accuracy is a separate question from the "
        "authenticity of the record.",
    ]
    if not artefact_hash:
        limits.append(
            "No hash was recorded for this artefact, so the record cannot be "
            "tied to specific bytes and the requirements of the Schedule "
            "cannot be met.")
    if not custody:
        limits.append(
            "No audit-chain entries reference this artefact, so no chain of "
            "custody can be exhibited for it.")
    if not chain_state.get("valid"):
        limits.append(
            "The audit chain currently fails verification. Until that is "
            "resolved this certificate should not be issued.")
    return limits


def is_certifiable(scan_id):
    """
    Whether a certificate could honestly be issued for this scan.

    Called before offering the document, so an officer is told why not rather
    than handed a certificate full of blanks.
    """
    cert = build_certificate(scan_id)
    if not cert:
        return False, "No such scan."
    if not cert["record"]["hash"]:
        return False, ("No hash was recorded for this artefact. The Schedule to "
                       "the Act requires the hash of the electronic record.")
    if not cert["chain"]["valid"]:
        return False, ("The audit chain fails verification (%s). A certificate "
                       "must not be issued while the integrity of the record "
                       "store is in doubt." % cert["chain"]["reason"])
    return True, None
