"""
blueprints/public_api.py
------------------------
Machine-to-machine API for the citizen-facing channels.

The web console is built for analysts. The people who actually receive these
scams are on WhatsApp and Telegram, or looking at a page in a browser — and
they will never open an analyst console. This blueprint is the surface those
channels talk to: the Chrome extension (`integrations/chrome-extension/`) and
the Telegram bot (`integrations/telegram_bot.py`).

Three design decisions worth stating plainly:

1. **It is key-authenticated, not open.** An unauthenticated text-classification
   endpoint is a free oracle: an operator can tune a creative against it until
   it scores clean, then send the tuned version. Keys are per-integration, so
   one can be revoked without touching the others.

2. **It does not write to the entity graph by default.** Anything a stranger
   pastes into a bot would otherwise become an "indicator sighting" with the
   same standing as an analyst's scan, and the graph would be trivial to
   poison. Submissions land in a separate quarantine table; an analyst
   promotes them.

3. **It returns a band, not a bare percentage.** A citizen asking "is this a
   scam" needs SAFE / UNSURE / LIKELY SCAM and what to do next, not a
   confidence figure from an uncalibrated model.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from datetime import datetime
from functools import wraps

from flask import Blueprint, request, jsonify

from extensions import limiter
from services.intel import calibration, evidence, multilingual
from services.intel.db import get_db_connection
from services.intel.indicators import extract_all, KIND_LABELS, KIND_AUTHORITY

bp = Blueprint('public_api', __name__, url_prefix='/api/v1')

# Tighter than the console's allowance: these keys are held by automated
# clients, and a bot loop that runs away should be throttled, not amplified.
API_RATE_LIMIT = "60 per hour;600 per day"

# Upper bound on submitted text. Long enough for a forwarded WhatsApp chain,
# short enough that the extractor's regex passes stay cheap.
MAX_TEXT_LENGTH = 8000


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# -- Key management --------------------------------------------------------

def init_api_db():
    """Create the API key and quarantine tables. Idempotent."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            label       TEXT NOT NULL,
            key_hash    TEXT NOT NULL UNIQUE,
            channel     TEXT NOT NULL,
            active      INTEGER NOT NULL DEFAULT 1,
            created_at  TEXT NOT NULL,
            last_used   TEXT,
            call_count  INTEGER NOT NULL DEFAULT 0
        )
    """)
    # Citizen submissions, quarantined. Never joined into the entity graph
    # until an analyst promotes the row -- see the module docstring.
    cur.execute("""
        CREATE TABLE IF NOT EXISTS public_submissions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            channel     TEXT NOT NULL,
            text        TEXT NOT NULL,
            text_hash   TEXT NOT NULL,
            verdict     TEXT,
            score       REAL,
            indicators  TEXT,
            promoted    INTEGER NOT NULL DEFAULT 0,
            created_at  TEXT NOT NULL
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_sub_hash ON public_submissions(text_hash)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_sub_promoted ON public_submissions(promoted)")
    conn.commit()
    conn.close()

    _seed_key_from_environment()


def _hash_key(raw):
    """
    Keys are stored hashed.

    A leaked database should not hand the reader working credentials for every
    integration. SHA-256 without a work factor is appropriate here and not for
    passwords: the key is 32 bytes of `secrets.token_urlsafe` entropy, so there
    is no dictionary to run against it.
    """
    return hashlib.sha256((raw or "").encode("utf-8")).hexdigest()


def create_key(label, channel):
    """Mint a key. The raw value is returned once and never stored."""
    raw = secrets.token_urlsafe(32)
    conn = get_db_connection()
    try:
        conn.execute("""
            INSERT INTO api_keys (label, key_hash, channel, active, created_at)
            VALUES (?, ?, ?, 1, ?)
        """, (label, _hash_key(raw), channel, _now()))
        conn.commit()
    finally:
        conn.close()
    return raw


def _seed_key_from_environment():
    """
    Register a key supplied via CYBERSURAKSHAA_API_KEY, if present.

    This exists so a deployment can provision the bot's key through its normal
    secret mechanism instead of a manual database step. Absence is the normal
    case and is not an error -- it just means the public API has no valid keys
    and will reject every caller, which is the correct default.
    """
    raw = os.environ.get("CYBERSURAKSHAA_API_KEY")
    if not raw:
        return
    conn = get_db_connection()
    try:
        conn.execute("""
            INSERT INTO api_keys (label, key_hash, channel, active, created_at)
            VALUES (?, ?, ?, 1, ?)
            ON CONFLICT(key_hash) DO NOTHING
        """, ("environment", _hash_key(raw), "env", _now()))
        conn.commit()
    except Exception as e:
        print("[API] could not seed environment key: %s" % e)
    finally:
        conn.close()


def _lookup_key(raw):
    if not raw:
        return None
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, label, channel, active FROM api_keys WHERE key_hash = ?
    """, (_hash_key(raw),))
    row = cur.fetchone()
    if row and row["active"]:
        conn.execute("""
            UPDATE api_keys SET last_used = ?, call_count = call_count + 1
            WHERE id = ?
        """, (_now(), row["id"]))
        conn.commit()
        result = dict(row)
    else:
        result = None
    conn.close()
    return result


def require_api_key(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        raw = (request.headers.get("X-API-Key")
               or request.args.get("key")
               or (request.get_json(silent=True) or {}).get("key"))
        key = _lookup_key(raw)
        if not key:
            return jsonify({
                "error": "A valid X-API-Key header is required.",
                "docs": "/api/v1/",
            }), 401
        request.api_key = key
        return fn(*args, **kwargs)
    return wrapper


# -- Endpoints -------------------------------------------------------------

@bp.route('/')
def api_index():
    """Self-describing root, so an integrator does not need separate docs."""
    return jsonify({
        "service": "CYBERSURAKSHAA public API",
        "version": "1",
        "authentication": "X-API-Key header",
        "endpoints": {
            "POST /api/v1/check": "Classify a message and extract indicators",
            "GET  /api/v1/verify/<sha256>": "Verify an evidence hash (no key required)",
            "GET  /api/v1/health": "Liveness",
        },
        "limits": {"rate": API_RATE_LIMIT, "max_text_length": MAX_TEXT_LENGTH},
        "notes": [
            "Submissions are quarantined and are not joined into the "
            "intelligence graph until an analyst promotes them.",
            "Verdict bands are SAFE, UNSURE and LIKELY_SCAM. The numeric score "
            "is included for completeness but is not a calibrated probability "
            "unless `calibrated` is true.",
        ],
    })


@bp.route('/health')
def api_health():
    return jsonify({"ok": True, "time": _now()})


@bp.route('/check', methods=['POST'])
@limiter.limit(API_RATE_LIMIT)
@require_api_key
def api_check():
    """
    Classify one message.

    This is the endpoint behind the Chrome extension's in-page warning and the
    Telegram bot's reply. It runs the text-side signals only -- the keyword
    banks, the Hinglish normalisation and the indicator extractor -- because
    the vision and audio models are far too slow for an interactive check and
    the text signal is what carries on a forwarded message anyway.
    """
    data = request.get_json(silent=True) or {}
    text = (data.get("text") or "").strip()

    if not text:
        return jsonify({"error": "text is required"}), 400
    if len(text) > MAX_TEXT_LENGTH:
        text = text[:MAX_TEXT_LENGTH]

    hinglish_score, hinglish_reasons = multilingual.score_hinglish(text)
    indicators = extract_all(text)

    # Indicator presence is corroborating, not decisive: a legitimate bank SMS
    # also contains a phone number. Only the identity-bearing payment rails
    # move the score, and only a little.
    payment_kinds = {"upi", "bank_account", "crypto_wallet"}
    payment_hits = [i for i in indicators if i.kind in payment_kinds]
    contact_hits = [i for i in indicators if i.kind in ("telegram", "whatsapp")]

    score = hinglish_score
    reasons = list(hinglish_reasons)
    if payment_hits and hinglish_score > 0:
        score = min(100, score + 10)
        reasons.append(
            "A payment destination is included alongside urgency language — "
            "the combination that makes a message actionable rather than merely "
            "alarming.")
    if contact_hits and hinglish_score > 0:
        score = min(100, score + 5)
        reasons.append(
            "The message moves the conversation to a channel outside the "
            "institution it claims to represent.")

    assessment = calibration.assess(score, module="public_check")

    band_map = {
        calibration.BAND_SAFE: "SAFE",
        calibration.BAND_ABSTAIN: "UNSURE",
        calibration.BAND_THREAT: "LIKELY_SCAM",
    }
    band = band_map.get(assessment["band"], "UNSURE")

    submission_id = _quarantine(request.api_key["channel"], text, band, score,
                                indicators)

    return jsonify({
        "band": band,
        "score": score,
        "calibrated": assessment["calibrated"],
        "calibration_note": assessment["note"],
        "reasons": reasons,
        "indicators": [
            {
                "kind": i.kind,
                "label": KIND_LABELS.get(i.kind, i.kind),
                "value": i.normalized,
                "report_to": KIND_AUTHORITY.get(i.kind),
            }
            for i in indicators
        ],
        "advice": _advice(band, bool(payment_hits)),
        "submission_id": submission_id,
        "disclaimer": (
            "This is an automated assessment of the text alone. It is not "
            "legal advice and not a determination by any authority. If money "
            "has already been sent, call 1930 immediately — the first few "
            "hours are when a transfer can still be held."
        ),
    })


def _advice(band, has_payment_destination):
    if band == "LIKELY_SCAM":
        steps = [
            "Do not pay, and do not share any OTP. No bank, telecom operator "
            "or government department will ever ask for one.",
            "Do not use the phone number in the message. Look the institution "
            "up independently and call the number on its official site.",
            "Report it at cybercrime.gov.in, or call 1930.",
        ]
        if has_payment_destination:
            steps.insert(1, "Report the payment address at cybercrime.gov.in — "
                            "a UPI ID or account number is what actually gets "
                            "the operator's collection frozen.")
        return steps
    if band == "UNSURE":
        return [
            "There is not enough in this message to call it either way.",
            "Verify independently: find the institution's number yourself "
            "rather than using one supplied in the message.",
            "If it asks for an OTP, a payment or remote access to your device, "
            "treat it as a scam regardless of this result.",
        ]
    return [
        "No scam patterns were detected in this text.",
        "This checks wording only. A message can be clean and still come from "
        "a spoofed sender, and an attachment or link was not examined.",
    ]


def _quarantine(channel, text, verdict, score, indicators):
    """
    Store the submission without touching the entity graph.

    Anything the public can send is attacker-controllable. Writing it straight
    into the graph would let one person create arbitrary "sightings" linking
    any two identifiers they chose -- and the campaign clustering would then
    faithfully report the fiction. Promotion is a deliberate analyst action.
    """
    import json
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO public_submissions
                (channel, text, text_hash, verdict, score, indicators,
                 promoted, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 0, ?)
        """, (channel, text[:MAX_TEXT_LENGTH],
              hashlib.sha256(text.encode("utf-8")).hexdigest(),
              verdict, score,
              json.dumps([{"kind": i.kind, "value": i.normalized}
                          for i in indicators]),
              _now()))
        conn.commit()
        sub_id = cur.lastrowid
        conn.close()
        return sub_id
    except Exception as e:
        # A failed quarantine write must not fail the citizen's check.
        print("[API] quarantine write failed: %s" % e)
        return None


@bp.route('/verify/<artefact_hash>')
@limiter.limit("120 per hour")
def api_verify(artefact_hash):
    """
    Evidence verification, unauthenticated by design.

    Deliberately needs no key: a verification endpoint that only the operator
    can call verifies nothing to anybody outside the operator.
    """
    record = evidence.lookup_artefact(artefact_hash)
    if not record:
        return jsonify({"found": False, "artefact_hash": artefact_hash.lower()}), 404
    return jsonify(record)
