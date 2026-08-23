"""
services/intel/pandemic.py
--------------------------
Emergency / pandemic scam vocabulary — the adaptability proof.

WHY THIS MODULE EXISTS
----------------------
The round-2 scenario is a declared global emergency with no public gatherings
for ninety days. Every past lockdown produced the same pattern: the *delivery
mechanism* of fraud did not change (a message, a poster, a QR sticker), but the
*pretext* changed completely and within days — relief funds, oxygen cylinders,
vaccine slots, e-passes, work-from-home income.

A detection platform that needs retraining to follow that shift is useless in
the window that matters. This module is the demonstration that ours does not:
a new threat class is a new keyword bank in the shape the scorers already
consume, shipped without touching a model, a schema, or a route.

DESIGN
------
* Same (pattern, weight, label) triple as nlp_analyzer.SCAM_KEYWORDS and
  multilingual.HINGLISH_SCAM_KEYWORDS, so every existing scorer can consume it
  by concatenation.
* English AND Hinglish/Devanagari-transliterated forms in one bank, because the
  messages that actually circulate are mixed-script.
* Deliberately *pretext* patterns, not generic urgency: urgency is already
  scored by the base banks, and double-counting it would inflate every score
  during an emergency rather than distinguishing emergency-themed fraud.
* Written to generalise beyond one disease. "vaccine" and "oxygen" are COVID
  artefacts; "relief fund", "e-pass", "quarantine fine" and "emergency aid"
  recur in every emergency, including floods and cyclones.

ACTIVATION
----------
The bank is inert until enabled, because outside an emergency these words are
ordinary: "relief fund" appears in legitimate government circulars and
"oxygen" in medical supply invoices. Scoring them permanently would
manufacture false positives in normal times.

    EMERGENCY_MODE=1        environment variable, or
    set_emergency_mode(True) at runtime (admin toggle)

is_active() is what callers check. That single switch is the whole adaptation
surface — see docs/ROUND2_IMPLEMENTATION.md.
"""

from __future__ import annotations

import os
import re

# -- Bank ------------------------------------------------------------------
# (pattern, weight, label). Weights follow the existing convention: 25 for a
# claim that is fraudulent on its face, 15-20 for a strong pretext, 8-12 for a
# supporting signal that needs corroboration.

PANDEMIC_SCAM_KEYWORDS = [
    # -- Relief / aid disbursement --------------------------------------
    # The single largest emergency fraud category: a payment the citizen is
    # told they are owed, gated behind a fee or an OTP.
    (r"(?:relief|aid|assistance)\s+fund.{0,30}(?:claim|apply|register|receive)", 25,
     "Emergency: relief-fund disbursement lure"),
    (r"(?:covid|corona|pandemic|lockdown|emergency)\s+(?:relief|package|allowance|grant)", 20,
     "Emergency: relief-package claim"),
    (r"(?:rahat|sahayata)\s+(?:kosh|rashi|paisa)|sarkari\s+madad", 20,
     "Emergency (Hinglish): government-relief lure"),
    (r"government\s+(?:has\s+)?(?:approved|sanctioned).{0,25}(?:rs\.?|₹|inr)\s*[\d,]+", 25,
     "Emergency: fabricated government sanction"),
    (r"(?:free|muft)\s+ration\s+(?:card|kit).{0,30}(?:register|apply|link)", 15,
     "Emergency: free-ration registration lure"),
    (r"unemployment\s+(?:allowance|benefit).{0,30}(?:claim|apply)", 15,
     "Emergency: unemployment-benefit lure"),

    # -- Medical supply / treatment -------------------------------------
    # Scarcity pricing is the tell: a supplier who can only be reached on a
    # messaging app and only takes advance payment.
    (r"(?:oxygen|cylinder|concentrator).{0,40}(?:available|supply|urgent|book)", 20,
     "Emergency: scarce medical-supply offer"),
    (r"(?:remdesivir|tocilizumab|injection|life\s*saving\s+drug).{0,30}(?:available|stock|sell)", 25,
     "Emergency: restricted-medicine offer"),
    (r"(?:vaccine|vaccination|booster)\s+(?:slot|dose|certificate).{0,30}(?:book|register|fee|paid)", 20,
     "Emergency: paid vaccine-slot claim"),
    (r"(?:hospital\s+bed|icu\s+bed|ventilator).{0,30}(?:arrange|book|available|advance)", 20,
     "Emergency: hospital-bed brokering"),
    (r"(?:covid|corona|rt-?pcr)\s+(?:test|report|negative)\s+(?:certificate|result).{0,25}"
     r"(?:without|instant|guaranteed|home)", 25,
     "Emergency: forged test-certificate offer"),
    (r"(?:oxygen|dawai|injection)\s+(?:milega|available\s+hai|chahiye\s+to)", 20,
     "Emergency (Hinglish): scarce-supply offer"),

    # -- Movement / compliance documents --------------------------------
    (r"e-?pass.{0,30}(?:apply|issue|urgent|fee|approved)", 20,
     "Emergency: movement e-pass lure"),
    (r"(?:quarantine|isolation|lockdown)\s+(?:fine|penalty|challan|violation)", 25,
     "Emergency: quarantine-fine extortion"),
    (r"(?:curfew|lockdown)\s+pass.{0,25}(?:download|apply|paid)", 15,
     "Emergency: curfew-pass lure"),
    (r"health\s+(?:pass|status|certificate).{0,30}(?:update|verify|renew).{0,20}(?:fee|pay)", 20,
     "Emergency: paid health-certificate lure"),

    # -- Charity / donation ---------------------------------------------
    # Emergencies produce genuine appeals, so the pattern requires a payment
    # rail alongside the appeal rather than the appeal alone.
    (r"donate.{0,40}(?:upi|paytm|gpay|phonepe|qr|scan|account\s+no)", 20,
     "Emergency: donation appeal with direct payment rail"),
    (r"(?:migrant|daily\s+wage|stranded)\s+(?:worker|labour|labor).{0,40}(?:donate|help\s+by\s+send)", 15,
     "Emergency: distress-charity appeal"),
    (r"(?:pm|cm|prime\s+minister|chief\s+minister)\s+(?:relief|care)\s+fund", 15,
     "Emergency: official-relief-fund invocation"),

    # -- Work-from-home / income replacement ----------------------------
    # Job loss is the emergency's second-order effect, and the fraud that
    # follows it is the highest-volume category after relief scams.
    (r"work\s+from\s+home.{0,40}(?:daily|guaranteed|earn).{0,20}(?:rs\.?|₹|\d)", 20,
     "Emergency: work-from-home income claim"),
    (r"ghar\s+baithe.{0,30}(?:kama|income|kamai|job)", 20,
     "Emergency (Hinglish): work-from-home income claim"),
    (r"(?:part\s*time|online)\s+job.{0,30}(?:registration|security|joining)\s+fee", 25,
     "Emergency: advance-fee job scam"),
    (r"(?:data\s+entry|typing|form\s+filling)\s+(?:job|work).{0,30}(?:daily|per\s+day)", 15,
     "Emergency: task-work income lure"),
    (r"(?:lost\s+your\s+job|job\s+gaya|naukri\s+gayi).{0,40}(?:earn|kamai|income)", 15,
     "Emergency: job-loss targeting"),

    # -- Teleconsultation / delivery ------------------------------------
    (r"(?:online|tele)\s*(?:consult|doctor|clinic).{0,30}(?:advance|pay\s+first|fee\s+before)", 15,
     "Emergency: advance-fee teleconsultation"),
    (r"(?:essential|grocery|medicine)\s+delivery.{0,30}(?:advance|prepaid\s+only|pay\s+now)", 15,
     "Emergency: advance-payment delivery offer"),

    # -- Insurance / claim ----------------------------------------------
    (r"(?:covid|health|emergency)\s+insurance.{0,30}(?:claim|payout).{0,25}(?:process|fee|verify)", 15,
     "Emergency: insurance-claim processing lure"),
]

# Native-script terms an analyst may want to review directly. These are folded
# into Latin by multilingual.transliterate_devanagari() before matching, so the
# patterns above stay ASCII.
DEVANAGARI_EMERGENCY_TERMS = {
    "राहत": "relief", "सहायता": "assistance", "कोष": "fund",
    "टीका": "vaccine", "ऑक्सीजन": "oxygen", "दवाई": "medicine",
    "अस्पताल": "hospital", "पास": "pass", "जुर्माना": "fine",
    "मुफ्त": "free", "राशन": "ration", "नौकरी": "job",
}


# -- Activation ------------------------------------------------------------

def _env_flag():
    return os.environ.get("EMERGENCY_MODE", "0").strip().lower() in ("1", "true", "yes", "on")


_runtime_override = None


def set_emergency_mode(enabled):
    """
    Turn the bank on or off at runtime.

    Returns the resulting state. Passing None clears the override and hands
    control back to the environment variable, which is what a deployment sets.
    """
    global _runtime_override
    _runtime_override = None if enabled is None else bool(enabled)
    return is_active()


def is_active():
    """True when emergency vocabulary should be scored."""
    return _env_flag() if _runtime_override is None else _runtime_override


# -- Scoring ---------------------------------------------------------------

def score_emergency(text, force=False):
    """
    Score `text` against the emergency bank.

    Returns (score, reasons) on the same 0-100 scale and with the same reason
    wording as every other bank, so a caller can max() or concatenate without
    special-casing.

    Returns (0, []) when emergency mode is off — the caller does not have to
    check is_active() first, and cannot accidentally score these terms during
    normal operations. `force=True` scores regardless, for the evaluation
    harness and tests.
    """
    if not (force or is_active()):
        return 0, []

    try:
        from services.intel.multilingual import normalise
        forms = normalise(text)
        haystacks = {
            forms["canonical"].lower(),
            forms["deobfuscated"].lower(),
            forms["transliterated"].lower(),
            forms["original"].lower(),
        }
    except Exception:
        haystacks = {(text or "").lower()}

    score = 0
    reasons = []
    seen = set()
    for pattern, weight, label in PANDEMIC_SCAM_KEYWORDS:
        if label in seen:
            continue
        for hay in haystacks:
            if re.search(pattern, hay):
                score += weight
                seen.add(label)
                reasons.append("Detected high-risk phrasing: %s" % label)
                break

    return min(score, 100), reasons


def status():
    """Machine-readable state, for /healthz and the admin toggle UI."""
    return {
        "active": is_active(),
        "source": "runtime override" if _runtime_override is not None else "environment",
        "patterns": len(PANDEMIC_SCAM_KEYWORDS),
        "note": (
            "Emergency vocabulary is scored only while an emergency is "
            "declared. Outside one these terms appear in legitimate "
            "circulars and scoring them would manufacture false positives."
        ),
    }
