"""
evaluation/eval_extraction.py
-----------------------------
Exact-match evaluation of the customer-care detector's extraction stages.

These are the most trustworthy numbers in the suite. "Did this text contain
+91 93218 76543, and did we pull out 9321876543?" has one correct answer that
does not depend on anyone's judgement about what counts as a scam. Nothing
here is a matter of opinion, so nothing here can be quietly tuned to look good.

Three suites:

  1. phone_extraction  — must find the right numbers, in the formats real
                         posters use, including the official helpline formats
                         the detector previously could not represent at all.
  2. phone_rejection   — must NOT invent phone numbers out of order ids,
                         dates, invoice references and amounts.
  3. brand_detection   — must identify the impersonated brand from the text.

Cases are authored, not scraped. That is fine here precisely because the
ground truth is mechanical: the expected output follows from the input by
definition, not from a labeller's opinion.
"""

from __future__ import annotations

import importlib.util
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evaluation.metrics import ExactMatchResult, render_exact_match  # noqa: E402

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CC_DIR = os.path.join(BASE_DIR, "fake customer carer")


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, os.path.join(CC_DIR, filename))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── Suite 1: numbers that must be found ──────────────────────────────────────
# (id, text, set of normalised numbers that must appear in the output)
PHONE_EXTRACTION_CASES = [
    # -- Official helpline formats. Every one of these was invisible to the
    #    extractor before: the toll-free pattern required 6+ digits after the
    #    1800 prefix, and there was no landline or short-code pattern at all.
    #    A genuine poster showing these was reported as "no phone detected",
    #    or worse, as a CRITICAL MISMATCH against the brand.
    ("official-airtel-shortcode",
     "Airtel customer care: dial 121 for support", {"121"}),
    ("official-icici-short-tollfree",
     "ICICI Bank 24x7 helpline 1800-1080", {"18001080"}),
    ("official-paytm-landline",
     "Paytm support desk 0120-4456-456", {"01204456456"}),
    ("official-phonepe-landline",
     "PhonePe grievance officer 080-68727374", {"08068727374"}),
    ("official-amazon-tollfree",
     "Amazon customer service 1800-3000-9009", {"180030009009"}),
    ("official-sbi-tollfree",
     "SBI toll free 1800-11-2211 available 24 hours", {"1800112211"}),

    # -- Standard mobile formats seen on scam posters.
    ("mobile-plain",
     "Call our executive at 9876543210 now", {"9876543210"}),
    ("mobile-country-code",
     "WhatsApp +91 9821234567 for instant refund", {"9821234567"}),
    ("mobile-spaced",
     "Helpline 98212 34567 open now", {"9821234567"}),
    ("mobile-hyphenated",
     "Contact 98212-34567 immediately", {"9821234567"}),
    ("mobile-leading-zero",
     "Dial 09821234567 to speak to an officer", {"9821234567"}),

    # -- OCR failure modes the extractor's three-pass design exists to handle.
    ("ocr-multiline-fragments",
     "Customer Care\n+91\n93218\n76543\nCall now", {"9321876543"}),
    ("ocr-stray-icon-digit",
     "Support +91 93218 3 76543", {"9321876543"}),

    # -- Two numbers present: a scam poster showing a real number alongside a
    #    fake one to borrow credibility. Both must be found — scoring only the
    #    first one let the fake hide behind the real one.
    ("two-numbers-real-and-fake",
     "SBI official 1800-11-2211 or call agent directly 9876543210",
     {"1800112211", "9876543210"}),
]

# ── Suite 2: things that must NOT be read as phone numbers ───────────────────
# Every one of these produced a bogus "detected phone number" before, because
# two of the three normalisation passes strip whitespace between digits across
# the whole document, gluing unrelated numbers together.
PHONE_REJECTION_CASES = [
    ("reject-order-id",
     "Order 1234 5678 90 was placed on 12 03 2024"),
    ("reject-invoice",
     "Invoice 4455 6677 8899 total 500 20 rupees"),
    ("reject-amounts",
     "Pay 2500 00 for 12 months at 15 00 interest"),
    ("reject-dates-only",
     "Valid from 01 01 2024 until 31 12 2025"),
    ("reject-plain-prose",
     "Thank you for shopping with us. Your package is on the way."),
]

# ── Suite 3: brand identification ────────────────────────────────────────────
BRAND_CASES = [
    ("brand-sbi-abbrev",       "Your SBI account has been blocked", "SBI"),
    ("brand-sbi-full",         "State Bank of India security alert", "SBI"),
    ("brand-hdfc",             "HDFC Bank KYC verification pending", "HDFC Bank"),
    ("brand-icici",            "ICICI Bank net banking suspended", "ICICI Bank"),
    ("brand-axis",             "Axis Bank card blocked, call support", "Axis Bank"),
    ("brand-amazon",           "Amazon refund failed, contact care", "Amazon"),
    ("brand-flipkart",         "Flipkart order cancelled, call now", "Flipkart"),
    ("brand-paytm",            "Paytm wallet KYC expiring today", "Paytm"),
    ("brand-phonepe",          "PhonePe transaction reversal helpdesk", "PhonePe"),
    ("brand-phonepe-spaced",   "Phone Pe customer care number", "PhonePe"),
    ("brand-airtel",           "Airtel prepaid recharge failed", "Airtel"),
    ("brand-jio",              "Reliance Jio SIM will be deactivated", "Jio"),
    # Negative: no brand mentioned at all.
    ("brand-none",             "Please call our helpline for assistance", "Unknown"),
    # Regression: "fk" is a Flipkart alias. As a bare substring it matched any
    # word containing those two letters.
    ("brand-no-false-substring",
     "Please confirm your booking at the front desk", "Unknown"),
]


def run_phone_extraction(det) -> list[ExactMatchResult]:
    results = []
    for case_id, text, expected in PHONE_EXTRACTION_CASES:
        found = {p["normalized"] for p in det.extract_phone_numbers(text)}
        missing = expected - found
        results.append(ExactMatchResult(
            identifier=case_id,
            expected=sorted(expected),
            actual=sorted(found),
            passed=not missing,
            note=f"missing {sorted(missing)}" if missing else "",
        ))
    return results


def run_phone_rejection(det) -> list[ExactMatchResult]:
    results = []
    for case_id, text in PHONE_REJECTION_CASES:
        found = [p["original"] for p in det.extract_phone_numbers(text)]
        results.append(ExactMatchResult(
            identifier=case_id,
            expected="no phone numbers",
            actual=found or "no phone numbers",
            passed=not found,
            note="invented a phone number from unrelated digits" if found else "",
        ))
    return results


def run_brand_detection(det) -> list[ExactMatchResult]:
    results = []
    for case_id, text, expected in BRAND_CASES:
        brand, method, conf = det.detect_brand(text)
        results.append(ExactMatchResult(
            identifier=case_id,
            expected=expected,
            actual=brand,
            passed=brand == expected,
            note=f"method={method} conf={conf}" if brand != expected else "",
        ))
    return results


def evaluate() -> dict:
    det = _load("cc_detector_eval", "detector.py")
    return {
        "phone_extraction": run_phone_extraction(det),
        "phone_rejection": run_phone_rejection(det),
        "brand_detection": run_brand_detection(det),
    }


def report(data: dict) -> str:
    out = []
    out.append("=" * 66)
    out.append("CUSTOMER CARE — EXTRACTION ACCURACY (exact match)")
    out.append("Ground truth is mechanical, not a labelling judgement.")
    out.append("=" * 66)
    out.append("")
    out.append(render_exact_match("Phone extraction (must find)", data["phone_extraction"]))
    out.append("")
    out.append(render_exact_match("Phone rejection (must not invent)", data["phone_rejection"]))
    out.append("")
    out.append(render_exact_match("Brand detection", data["brand_detection"]))

    total = sum(len(v) for v in data.values())
    passed = sum(1 for v in data.values() for r in v if r.passed)
    out.append("")
    out.append(f"OVERALL: {passed}/{total} ({passed / total:.1%})")
    return "\n".join(out)


if __name__ == "__main__":
    print(report(evaluate()))
