"""
evaluation/eval_betting_text.py
-------------------------------
Evaluates the *text* half of the betting detector — models/text_classifier.py.

⚠ THIS IS NOT AN EVALUATION OF THE BETTING DETECTOR AS A WHOLE. ⚠

The shipped pipeline fuses text with vision, and the vision half is currently
inert: no custom betting model exists at detector/saved/betting_yolo.pt, so
YOLO falls back to COCO, whose classes say nothing about betting and are now
excluded from the score. Whatever this file reports, the deployed detector's
real-world accuracy on betting *images* is unmeasured, and cannot be measured
until there is a labelled image set. See RESULTS.md.

⚠ THE CASES BELOW ARE AUTHORED, NOT COLLECTED. ⚠

That is a weaker basis than the investment corpus, and the weakness is
specific: these examples were written by someone who had read the keyword
list, so they over-represent the vocabulary the classifier already knows.
Treat the score as a REGRESSION SUITE — it catches the day someone breaks
keyword matching — not as a measure of field accuracy. The benign half is the
more informative half, because those are the cases the detector has no reason
to get right by construction.
"""

from __future__ import annotations

import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evaluation.metrics import (  # noqa: E402
    ScoredResult, confusion_from_results, render_sweep,
    failure_cases, use_utf8_stdout,
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BETTING_DIR = os.path.join(BASE_DIR, "danish betting", "betting_detector")

# Classified as betting above this probability (fusion's SUSPICIOUS floor).
DECISION_THRESHOLD = 0.40

# (text, is_betting)
CASES: list[tuple[str, bool]] = [
    # ── Betting content ──────────────────────────────────────────────────
    ("1XBET WELCOME BONUS 100% on first deposit. Sign up now!", True),
    ("IPL match prediction 100% sure win. Join our telegram group for VIP tips", True),
    ("Teen Patti Gold — get unlimited chips, guaranteed winning cards", True),
    ("Bet365 live betting odds for tonight's cricket match", True),
    ("Online casino India — roulette, blackjack, baccarat. Free bet on signup", True),
    ("Parimatch cricket betting app download. Deposit bonus 500 INR", True),
    ("Fixed match tips available. DM for tips. Win daily guaranteed", True),
    ("Melbet promo code for free bet. No deposit needed, instant cashback", True),
    ("Play rummy and poker for real cash. Jackpot up to 10 lakh", True),
    ("Dafabet sportsbook — best odds on IPL. Register and claim welcome bonus", True),
    ("Crypto casino accepting bitcoin bet. Provably fair slots and spin wheel", True),
    ("Join our VIP tips channel — accumulator and parlay predictions daily", True),

    # ── Benign content ───────────────────────────────────────────────────
    # These are the cases that actually test something. Several contain words
    # that a substring matcher fires on: "alphabet" contains "bet", "mistake"
    # contains "stake", "spinach" contains "spin", "chipset" contains "chips".
    ("The children are learning the alphabet at school today", False),
    ("It was a mistake to leave the documents on the table", False),
    ("Add spinach to the pan and cook for five minutes", False),
    ("The new laptop has an upgraded chipset and better battery life", False),
    ("Our pilots complete recurrent training every six months", False),
    ("Please submit the quarterly report before Friday deadline", False),
    ("India won the cricket match by 5 wickets in a thrilling finish", False),
    ("The stock market closed higher today on strong earnings", False),
    ("Book your railway tickets online at the official IRCTC portal", False),
    ("Download the official banking app from Google Play Store", False),
    ("Register for the free webinar on cyber security awareness", False),
    ("The odds of rain tomorrow are low according to the forecast", False),
]


def _stub_loguru():
    """The betting modules import loguru; stub it if it is not installed."""
    if "loguru" in sys.modules:
        return
    try:
        import loguru  # noqa: F401
    except ImportError:
        mod = types.ModuleType("loguru")

        class _Logger:
            def __getattr__(self, _):
                return lambda *a, **k: None

        mod.logger = _Logger()
        sys.modules["loguru"] = mod


def evaluate() -> dict:
    _stub_loguru()
    if BETTING_DIR not in sys.path:
        sys.path.insert(0, BETTING_DIR)
    from models.text_classifier import TextClassifier

    clf = TextClassifier()
    method_used = (
        "bert" if clf._bert_pipeline is not None
        else "tfidf" if clf._tfidf_pipeline is not None
        else "keyword"
    )

    results = []
    for i, (text, is_betting) in enumerate(CASES):
        r = clf.classify(text)
        prob = r.betting_probability
        results.append(ScoredResult(
            identifier=f"case{i}",
            actual_threat=is_betting,
            score=prob * 100,
            predicted_threat=prob >= DECISION_THRESHOLD,
            detail=text[:80],
            group="betting" if is_betting else "benign",
            extra={"method": r.method, "keywords": r.matched_keywords},
        ))
    return {"results": results, "method": method_used, "classifier": clf}


def report(data: dict) -> str:
    results = data["results"]
    cm = confusion_from_results(results)

    out = []
    out.append("=" * 66)
    out.append("BETTING DETECTOR — TEXT CLASSIFIER ONLY")
    out.append("*** SYNTHETIC regression suite — authored, not collected ***")
    out.append("*** Vision half is UNMEASURED: no custom model exists     ***")
    out.append("=" * 66)
    out.append("")
    out.append(f"  active strategy: {data['method']}")
    out.append("")
    out.append(cm.render(f"Text classifier @ p >= {DECISION_THRESHOLD}"))
    out.append("")
    out.append("Threshold sweep")
    out.append(render_sweep(results))
    out.append("")

    fails = failure_cases(results, limit=6)
    out.append("Missed betting content")
    if not fails["missed_threats"]:
        out.append("  none")
    for r in fails["missed_threats"]:
        out.append(f"  [p={r.score / 100:.2f}] {r.detail}")
    out.append("")
    out.append("False alarms on benign text  <- the informative half")
    if not fails["false_alarms"]:
        out.append("  none")
    for r in fails["false_alarms"]:
        kws = r.extra.get("keywords", [])
        out.append(f"  [p={r.score / 100:.2f}] {r.detail}")
        out.append(f"             matched: {kws}")
    return "\n".join(out)


if __name__ == "__main__":
    use_utf8_stdout()
    print(report(evaluate()))
