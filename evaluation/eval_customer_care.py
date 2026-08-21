"""
evaluation/eval_customer_care.py
--------------------------------
Scenario tests for the customer-care risk scorer.

Each case states a situation — which brand the poster claims to be, which
number it shows, whether that number is on the threat list — and the severity
band the tool is supposed to land in. That makes these *specification* tests:
they check the scorer against its own documented intent, so a failure is
either a real regression or a decision that the intent should change.

This is weaker evidence than the extraction suite (where the right answer is
mechanical) but stronger than a hand-written scam corpus (where the label is
one person's opinion). The scenarios are constructed from the official-contact
records the tool ships with, so the ground truth comes from the tool's own
reference data rather than from a guess about what a scam looks like.

The image path (PaddleOCR → text) is NOT covered. Measuring OCR quality needs
a set of real scam screenshots with transcribed ground truth; see RESULTS.md.
"""

from __future__ import annotations

import importlib.util
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evaluation.metrics import ExactMatchResult, render_exact_match, use_utf8_stdout  # noqa: E402

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CC_DIR = os.path.join(BASE_DIR, "fake customer carer")

SEVERITY_ORDER = ["Safe", "Suspicious", "High Risk", "Critical"]


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, os.path.join(CC_DIR, filename))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _phone(normalized: str, ptype: str = "Mobile") -> dict:
    return {"normalized": normalized, "original": normalized, "type": ptype}


# (id, brand, phone_info, official_phone|None, is_threat, reports, allowed severities)
SCENARIOS = [
    # ── Genuine brand posters. Every one of these was scored "High Risk" with
    #    a CRITICAL MISMATCH before, because the extractor could not represent
    #    short codes, short toll-free numbers or landlines at all.
    ("genuine-airtel-shortcode",
     "Airtel", _phone("121", "Short Code"), "121", False, 0, {"Safe"}),
    ("genuine-icici-tollfree",
     "ICICI Bank", _phone("18001080", "Toll-Free"), "1800-1080", False, 0, {"Safe"}),
    ("genuine-paytm-landline",
     "Paytm", _phone("01204456456", "Landline"), "0120-4456-456", False, 0, {"Safe"}),
    ("genuine-phonepe-landline",
     "PhonePe", _phone("08068727374", "Landline"), "080-68727374", False, 0, {"Safe"}),
    ("genuine-amazon-tollfree",
     "Amazon", _phone("180030009009", "Toll-Free"), "1800-3000-9009", False, 0, {"Safe"}),
    ("genuine-with-country-code",
     "SBI", _phone("911800112211", "Toll-Free"), "1800-11-2211", False, 0, {"Safe"}),

    # ── Impersonation: a personal mobile claiming to be a brand helpline.
    #    This is the core scam pattern the tool exists to catch.
    ("impersonation-sbi",
     "SBI", _phone("9876543210"), "1800-11-2211", False, 0, {"High Risk", "Critical"}),
    ("impersonation-amazon",
     "Amazon", _phone("9821234567"), "1800-3000-9009", False, 0, {"High Risk", "Critical"}),
    ("impersonation-hdfc",
     "HDFC Bank", _phone("9911223344"), "1800-202-6161", False, 0, {"High Risk", "Critical"}),

    # ── Impersonation plus a number already on the threat list. Must escalate
    #    above a plain mismatch.
    ("impersonation-known-threat",
     "SBI", _phone("9876543210"), "1800-11-2211", True, 3, {"Critical"}),
    ("impersonation-heavily-reported",
     "Amazon", _phone("9876543210"), "1800-3000-9009", True, 12, {"Critical"}),

    # ── No brand context.
    ("unknown-brand-clean-number",
     "Unknown", _phone("9876543210"), None, False, 0, {"Safe"}),
    ("unknown-brand-known-threat",
     "Unknown", _phone("9876543210"), None, True, 5, {"High Risk", "Critical"}),

    # ── Branded poster with no readable number. OCR misses numbers printed
    #    over styled backgrounds, and a branded helpline poster with no
    #    verifiable number is itself a known scam pattern — so this must not
    #    come back clean. The blueprint used to short-circuit it to Safe/0.
    ("brand-no-number",
     "SBI", None, None, False, 0, {"Suspicious"}),
    ("no-brand-no-number",
     "Unknown", None, None, False, 0, {"Safe"}),

    # ── A bare 3-digit token near brand text is ambiguous ("Rs 199", "150 MB")
    #    and must not on its own produce an accusation.
    ("ambiguous-shortcode-not-official",
     "Amazon", _phone("199", "Short Code"), "1800-3000-9009", False, 0, {"Safe"}),
]


def evaluate() -> list[ExactMatchResult]:
    scoring = _load("cc_scoring_eval", "scoring.py")
    results = []
    for case_id, brand, phone, official, is_threat, reports, allowed in SCENARIOS:
        official_contact = {"official_phone": official} if official else None
        score, severity, reasons, rec = scoring.calculate_risk_score(
            brand, phone, official_contact, is_threat, reports
        )
        results.append(ExactMatchResult(
            identifier=case_id,
            expected=" or ".join(sorted(allowed, key=SEVERITY_ORDER.index)),
            actual=f"{severity} ({score})",
            passed=severity in allowed,
            note=reasons[0][:90] if reasons and severity not in allowed else "",
        ))
    return results


def report(results: list[ExactMatchResult]) -> str:
    out = []
    out.append("=" * 66)
    out.append("CUSTOMER CARE — RISK SCORING SCENARIOS")
    out.append("Specification tests against the tool's own reference data")
    out.append("=" * 66)
    out.append("")
    out.append(render_exact_match("Risk scoring", results))
    return "\n".join(out)


if __name__ == "__main__":
    use_utf8_stdout()
    print(report(evaluate()))
