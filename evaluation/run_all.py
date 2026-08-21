"""
evaluation/run_all.py
---------------------
Runs every evaluation suite and writes a combined report.

    python evaluation/run_all.py                 # console + evaluation/REPORT.txt
    python evaluation/run_all.py --quick         # skip the slow ML suites
    python evaluation/run_all.py --json          # machine-readable summary

Suites that cannot run (missing data, missing dependency) report that fact and
do not stop the rest. A suite reporting "NOT RUN" is a result too: it means
that part of the system currently has no measured accuracy.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import traceback
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evaluation.metrics import use_utf8_stdout, confusion_from_results  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
REPORT_PATH = os.path.join(HERE, "REPORT.txt")


def _run(name, fn):
    """Run one suite, capturing failures so one broken suite cannot hide the rest."""
    try:
        return {"name": name, "ok": True, "text": fn()}
    except Exception as exc:
        return {
            "name": name, "ok": False,
            "text": f"{name}: SUITE FAILED — {type(exc).__name__}: {exc}\n\n"
                    + traceback.format_exc(),
        }


def suite_extraction():
    from evaluation import eval_extraction
    data = eval_extraction.evaluate()
    text = eval_extraction.report(data)
    total = sum(len(v) for v in data.values())
    passed = sum(1 for v in data.values() for r in v if r.passed)
    return text, {"passed": passed, "total": total, "pct": round(passed / total, 4)}


def suite_customer_care():
    from evaluation import eval_customer_care
    results = eval_customer_care.evaluate()
    text = eval_customer_care.report(results)
    passed = sum(1 for r in results if r.passed)
    return text, {"passed": passed, "total": len(results),
                  "pct": round(passed / len(results), 4)}


def suite_betting():
    from evaluation import eval_betting_text
    data = eval_betting_text.evaluate()
    text = eval_betting_text.report(data)
    cm = confusion_from_results(data["results"])
    return text, cm.as_dict()


def suite_betting_images():
    """The half suite_betting cannot reach: OCR and fusion on real images."""
    from pathlib import Path
    from evaluation import eval_betting_images
    data = eval_betting_images.evaluate(Path(eval_betting_images.DATASET_DIR))
    text = eval_betting_images.report(data)
    cm = confusion_from_results(data["results"])
    summary = cm.as_dict()
    summary["scored"] = len(data["results"])
    summary["ran"] = bool(data["results"])
    return text, summary


def suite_investment():
    from evaluation import eval_investment
    data = eval_investment.evaluate(verbose=False)
    text = eval_investment.report(data)
    cm = confusion_from_results(data["full"])
    return text, cm.as_dict()


def suite_deepfake():
    from evaluation import eval_deepfake
    data = eval_deepfake.evaluate()
    text = eval_deepfake.report(data)
    return text, {"available": data["available"], "total": data["total"],
                  "ran": bool(data["results"])}


SUITES = [
    ("Customer care — extraction", suite_extraction, False),
    ("Customer care — risk scoring", suite_customer_care, False),
    ("Betting — text classifier", suite_betting, True),
    ("Betting — image pipeline", suite_betting_images, True),
    ("Investment — scam classification", suite_investment, True),
    ("Deepfake — video classification", suite_deepfake, True),
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", help="Skip suites that load ML models")
    ap.add_argument("--json", action="store_true", help="Print a machine-readable summary")
    args = ap.parse_args()

    sections, summary = [], {}

    header = [
        "CYBERSURAKSHAA — EVALUATION REPORT",
        f"generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "Read evaluation/RESULTS.md before quoting any number from this file.",
        "It records where each dataset came from, and which figures do not mean",
        "what their label suggests.",
        "",
    ]

    for name, fn, is_slow in SUITES:
        if args.quick and is_slow:
            sections.append(f"{name}: SKIPPED (--quick)")
            continue
        print(f"[running] {name} ...", file=sys.stderr)

        def wrapped(fn=fn, name=name):
            text, stats = fn()
            summary[name] = stats
            return text

        sections.append(_run(name, wrapped)["text"])

    report = "\n".join(header) + "\n\n" + ("\n\n\n".join(sections)) + "\n"

    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        f.write(report)

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(report)

    print(f"\n[written] {REPORT_PATH}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    use_utf8_stdout()
    sys.exit(main())
