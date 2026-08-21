"""
evaluation/eval_investment.py
-----------------------------
Evaluates the investment scam detector end to end: nlp_analyzer (Engine A
XGBoost + keyword fallback, Engine B if loaded) combined through fraud_scorer,
exactly as blueprints/investment.py does it.

Dataset: scam-detector-capstone/data/multilingual_scams_real.csv
  320 rows, balanced 160 scam / 160 benign, English / Hindi / Marathi.

  ⚠ PROVENANCE CAVEAT ⚠
  This file ships alongside the trained XGBoost model in the same capstone
  directory. The training script did not survive (the notebook is empty), so
  we cannot prove the model was not fitted on these exact rows. If it was, the
  Engine A numbers here are memorisation, not generalisation.

  The script therefore reports Engine A and the keyword-only baseline
  separately. A very large gap between them, or a near-perfect Engine A score,
  is the signature of a contaminated split — see the warning it prints.

Link checking is disabled during evaluation: it performs live WHOIS and HTTP
lookups, which would make results depend on network conditions and registrar
availability rather than on the detector.
"""

from __future__ import annotations

import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evaluation.metrics import (  # noqa: E402
    ScoredResult, confusion_from_results, render_sweep,
    group_breakdown, failure_cases, use_utf8_stdout,
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET = os.path.join(BASE_DIR, "scam-detector-capstone", "data", "multilingual_scams_real.csv")

# The app calls a message "scam" (red) above 70 and "suspicious" (yellow)
# above 30. For a binary threat/benign judgement we treat yellow-and-above as
# flagged, because that is the point at which the UI warns the user.
DECISION_THRESHOLD = 31


def load_dataset(path: str = DATASET) -> list[dict]:
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Dataset not found: {path}\n"
            "Expected the capstone scam corpus. See evaluation/README.md."
        )
    with open(path, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def evaluate(limit: int | None = None, verbose: bool = True) -> dict:
    from services.scam_detector import nlp_analyzer, fraud_scorer

    nlp_analyzer.ensure_engines_loaded()
    engine_a_live = nlp_analyzer.vectorizer is not None and nlp_analyzer.xgb_model is not None
    engine_b_live = nlp_analyzer.roberta_model is not None

    if verbose:
        print(f"  Engine A (XGBoost)     : {'loaded' if engine_a_live else 'ABSENT — keyword fallback'}")
        print(f"  Engine B (XLM-RoBERTa) : {'loaded' if engine_b_live else 'absent'}")
        print(f"  Link checking          : disabled (network-dependent)")
        print()

    rows = load_dataset()
    if limit:
        rows = rows[:limit]

    full_results: list[ScoredResult] = []      # pipeline as shipped
    keyword_results: list[ScoredResult] = []   # keyword rules only — the baseline

    for i, row in enumerate(rows):
        text = row["text"]
        actual = row["is_scam"] == "1"
        language = row.get("language", "Unknown")

        engine_a, engine_b, reasons, status = nlp_analyzer.analyze_text(text)

        # Mirror blueprints/investment.py's blending.
        if status.get("engine_b_online") and engine_b > 0:
            blended = 0.7 * engine_a + 0.3 * engine_b
            effective = int(round(max(engine_a, blended)))
        else:
            effective = engine_a

        # link_risk = 0: link checking is deliberately excluded, see docstring.
        score, colour = fraud_scorer.compute_risk(effective, 0)

        full_results.append(ScoredResult(
            identifier=f"row{i}",
            actual_threat=actual,
            score=score,
            predicted_threat=score >= DECISION_THRESHOLD,
            detail=text[:100],
            group=language,
            extra={"engine_a": engine_a, "engine_b": engine_b, "colour": colour},
        ))

        # Keyword-only baseline: what the system scores with no ML at all.
        kw_score = _keyword_only_score(nlp_analyzer, text)
        kw_final, _ = fraud_scorer.compute_risk(kw_score, 0)
        keyword_results.append(ScoredResult(
            identifier=f"row{i}",
            actual_threat=actual,
            score=kw_final,
            predicted_threat=kw_final >= DECISION_THRESHOLD,
            detail=text[:100],
            group=language,
        ))

    return {
        "full": full_results,
        "keyword_baseline": keyword_results,
        "engine_a_live": engine_a_live,
        "engine_b_live": engine_b_live,
        "n": len(rows),
    }


def _keyword_only_score(nlp_analyzer, text: str) -> int:
    """Recompute the keyword score in isolation, bypassing both ML engines."""
    import re
    text_lower = text.lower()
    score = 0
    seen: set[str] = set()
    for pattern, weight, label in nlp_analyzer.SCAM_KEYWORDS:
        if label not in seen and re.search(pattern, text_lower):
            score += weight
            seen.add(label)
    return min(score, nlp_analyzer.MAX_POSSIBLE_SCORE)


def report(data: dict) -> str:
    full = data["full"]
    baseline = data["keyword_baseline"]

    cm_full = confusion_from_results(full)
    cm_base = confusion_from_results(baseline)

    out = []
    out.append("=" * 66)
    out.append("INVESTMENT SCAM DETECTOR")
    out.append("Dataset: multilingual_scams_real.csv (real, human-labelled)")
    out.append("=" * 66)
    out.append("")
    out.append(cm_full.render(f"Full pipeline @ score >= {DECISION_THRESHOLD}"))
    out.append("")
    out.append(cm_base.render("Keyword rules only (no ML) — baseline"))
    out.append("")

    lift = cm_full.f1 - cm_base.f1
    out.append(f"  ML lift over keyword baseline: {lift:+.1%} F1")
    out.append("")

    # Contamination check.
    if data["engine_a_live"] and cm_full.accuracy >= 0.97:
        out.append("  !! CONTAMINATION WARNING !!")
        out.append("  Accuracy at or above 97% on the corpus that ships next to the")
        out.append("  model strongly suggests the model was trained on these rows.")
        out.append("  Treat this as an upper bound, not as generalisation performance.")
        out.append("  Re-train on a split that excludes a held-out test set before")
        out.append("  quoting this number anywhere.")
        out.append("")

    out.append("Threshold sweep (full pipeline)")
    out.append(render_sweep(full))
    out.append("")

    out.append("Per-language breakdown (full pipeline)")
    out.append("  " + "-" * 56)
    out.append(f"  {'language':<12} {'n':>4} {'precision':>10} {'recall':>8} {'F1':>8}")
    for lang, cm in sorted(group_breakdown(full).items()):
        out.append(f"  {lang:<12} {cm.total:>4} {cm.precision:>10.1%} "
                   f"{cm.recall:>8.1%} {cm.f1:>8.1%}")
    out.append("")

    fails = failure_cases(full, limit=5)
    out.append("Missed threats (scams scored as safe) — worst first")
    if not fails["missed_threats"]:
        out.append("  none")
    for r in fails["missed_threats"]:
        out.append(f"  [score {r.score:>3}] {r.group:<8} {r.detail[:78]}")
    out.append("")
    out.append("False alarms (benign scored as scam) — worst first")
    if not fails["false_alarms"]:
        out.append("  none")
    for r in fails["false_alarms"]:
        out.append(f"  [score {r.score:>3}] {r.group:<8} {r.detail[:78]}")

    return "\n".join(out)


if __name__ == "__main__":
    use_utf8_stdout()
    print(report(evaluate()))
