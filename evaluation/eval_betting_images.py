"""
eval_betting_images.py
----------------------
Betting detector — IMAGE pipeline (OCR -> text classifier -> YOLO -> fusion).

This is the half `eval_betting_text.py` cannot reach. That suite feeds clean
strings straight to the classifier, so it measures the classifier and nothing
else. Everything that actually happens to a real poster -- OCR reading curved
or low-contrast text, the fusion engine weighing vision against text -- is
untouched by it.

Data
----
Image-level labels only. No bounding boxes are required, which is what makes
this cheap enough to actually collect:

    evaluation/datasets/betting_images/
    |-- manifest.csv
    |-- betting/     img_001.jpg ...
    +-- benign/      img_101.jpg ...

    filename,is_betting,source,notes
    betting/img_001.jpg,1,instagram_ad,1xbet logo + odds table
    benign/img_101.jpg,0,news_screenshot,cricket scorecard - hard negative

Bounding boxes are only needed to *train* a custom YOLO model
(`train_yolo.py`). They are not needed to measure whether the pipeline gets
the verdict right, so collect this set first.

Usage
-----
    python evaluation/eval_betting_images.py
    python evaluation/eval_betting_images.py --dataset /path/to/betting_images
    python evaluation/eval_betting_images.py --limit 20

Reports NOT RUN rather than a fabricated score when the dataset is absent --
a module with no measured accuracy is a finding, not a blank.
"""

from __future__ import annotations

import argparse
import csv
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from metrics import (  # noqa: E402
    ScoredResult, confusion_from_results, render_sweep, failure_cases,
    group_breakdown, use_utf8_stdout,
)

BASE_DIR = Path(__file__).resolve().parent.parent
DATASET_DIR = BASE_DIR / "evaluation" / "datasets" / "betting_images"
MANIFEST = "manifest.csv"

# The betting blueprint's own decision point, kept in one place so this suite
# cannot silently drift from what the application actually does.
DECISION_THRESHOLD = 50.0


# ---------------------------------------------------------------------------
# Dataset loading
# ---------------------------------------------------------------------------
def load_manifest(dataset_dir: Path) -> tuple[list[dict], list[str]]:
    """Return (rows, problems). Never raises on bad data -- reports it."""
    problems: list[str] = []
    manifest = dataset_dir / MANIFEST

    if not manifest.exists():
        return [], ["no manifest at %s" % manifest]

    rows: list[dict] = []
    with open(manifest, encoding="utf-8-sig", newline="") as f:
        for i, raw in enumerate(csv.DictReader(f), start=2):
            fn = (raw.get("filename") or "").strip()
            lab = (raw.get("is_betting") or "").strip()
            if not fn:
                problems.append("line %d: empty filename" % i)
                continue
            if lab not in ("0", "1"):
                problems.append("line %d: is_betting must be 0 or 1, got %r" % (i, lab))
                continue
            path = dataset_dir / fn
            if not path.exists():
                problems.append("line %d: file not found: %s" % (i, fn))
                continue
            rows.append({
                "path": str(path),
                "filename": fn,
                "actual": lab == "1",
                "source": (raw.get("source") or "").strip(),
                "notes": (raw.get("notes") or "").strip(),
            })
    return rows, problems


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------
def score_image(path: str) -> tuple[float, dict]:
    """Run the real betting pipeline over one image. Returns (0-100, detail)."""
    from blueprints import betting as b

    ocr = b._get_ocr()
    try:
        ocr_result = ocr.extract(path)
        text = ocr_result.extracted_text
    except Exception as exc:  # OCR failure is a result, not a crash
        return -1.0, {"error": "OCR failed: %r" % exc}

    clf = b._get_classifier()
    res = clf.classify(text)

    det = b._get_detector()
    logos: list[str] = []
    mode = "unknown"
    vision_prob = 0.0
    try:
        yr = det.detect(image_path=path, ocr_words=ocr_result.words)
        mode = yr.mode
        logos = [o.label for o in yr.detected_objects]
        vision_prob = float(yr.confidence)
    except Exception as exc:
        mode = "error: %r" % exc

    # Score through the SAME fusion the blueprint uses. An earlier version of
    # this suite scored `res.betting_probability` directly, which silently
    # dropped the vision half -- reproducing the exact blind spot this file
    # exists to remove, and making brand-list changes look like no-ops.
    fusion = b._get_fusion()
    fused = fusion.fuse(text_probability=res.betting_probability,
                        vision_probability=vision_prob)
    score = float(fused.final_score) * 100.0

    return score, {
        "chars": len(text),
        "snippet": " ".join(text.split())[:70],
        "method": res.method,
        "keywords": res.matched_keywords[:6],
        "text_p": round(float(res.betting_probability), 3),
        "vision_p": round(vision_prob, 3),
        "verdict": fused.classification,
        "yolo_mode": mode,
        "logos": logos,
    }


def evaluate(dataset_dir: Path, limit: int | None = None) -> dict:
    rows, problems = load_manifest(dataset_dir)
    if not rows:
        return {"rows": 0, "problems": problems, "results": [], "modes": {}}

    if limit:
        rows = rows[:limit]

    results: list[ScoredResult] = []
    modes: dict[str, int] = {}
    ocr_failures = 0

    for i, r in enumerate(rows, start=1):
        score, detail = score_image(r["path"])
        if score < 0:
            ocr_failures += 1
            print("  [%d/%d] OCR FAIL %s" % (i, len(rows), r["filename"]), flush=True)
            continue

        mode = detail.get("yolo_mode", "unknown")
        modes[mode] = modes.get(mode, 0) + 1

        results.append(ScoredResult(
            identifier=r["filename"],
            actual_threat=r["actual"],
            score=score,
            predicted_threat=score >= DECISION_THRESHOLD,
            detail="%s | %s" % (r["filename"], detail.get("snippet", "")),
            group=r["source"] or "unspecified",
            extra=detail,
        ))
        print("  [%d/%d] %5.1f  %s  %s" % (
            i, len(rows), score, "BET " if r["actual"] else "safe", r["filename"][:46]),
            flush=True)

    return {
        "rows": len(rows),
        "problems": problems,
        "results": results,
        "modes": modes,
        "ocr_failures": ocr_failures,
        "dataset_dir": str(dataset_dir),
    }


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def _not_run(dataset_dir: Path, problems: list[str]) -> str:
    out = [
        "=" * 66,
        "BETTING DETECTOR — IMAGE PIPELINE (OCR + YOLO + fusion)",
        "=" * 66,
        "",
        "  NOT RUN — no labelled image dataset present.",
        "",
        "  Expected: %s" % (dataset_dir / MANIFEST),
        "",
        "  Consequence: the betting IMAGE pipeline has NO measured accuracy.",
        "  eval_betting_text.py measures the text classifier on clean strings",
        "  only; it says nothing about OCR or fusion on real posters.",
        "",
        "  To run, collect image-level labels (no bounding boxes needed):",
        "",
        "    evaluation/datasets/betting_images/",
        "    |-- manifest.csv        filename,is_betting,source,notes",
        "    |-- betting/            150 betting ads",
        "    +-- benign/             150 hard negatives — cricket scorecards,",
        "                            fantasy-sports apps, casino news articles",
        "",
        "  See evaluation/LABELLING_GUIDE.md for sourcing rules.",
    ]
    if problems:
        out.append("")
        out.append("  Manifest problems (%d):" % len(problems))
        for p in problems[:12]:
            out.append("    - %s" % p)
    return "\n".join(out)


def report(data: dict) -> str:
    dataset_dir = Path(data.get("dataset_dir", DATASET_DIR))
    results = data["results"]
    if not results:
        return _not_run(dataset_dir, data.get("problems", []))

    cm = confusion_from_results(results)
    n_bet = sum(1 for r in results if r.actual_threat)

    out = [
        "=" * 66,
        "BETTING DETECTOR — IMAGE PIPELINE (OCR + YOLO + fusion)",
        "Dataset: %s" % dataset_dir,
        "=" * 66,
        "",
        "  scored: %d images (%d betting / %d benign)" % (
            len(results), n_bet, len(results) - n_bet),
    ]

    if data.get("ocr_failures"):
        out.append("  OCR failures excluded from the matrix: %d" % data["ocr_failures"])

    modes = data.get("modes", {})
    if modes:
        out.append("  YOLO mode: %s" % ", ".join(
            "%s x%d" % (k, v) for k, v in sorted(modes.items())))
        if "pretrained" in modes or "stub" in modes:
            out.append("")
            out.append("  NOTE: YOLO is NOT running a custom betting model. The vision")
            out.append("  signal in these scores comes from matching brand names in the")
            out.append("  OCR text, not from recognising a logo visually -- so a")
            out.append("  stylised mark with no readable text still scores 0 on vision.")
            out.append("  Train a model with train_yolo.py before reading any figure")
            out.append("  here as a measure of visual logo detection.")

    out += ["", cm.render("Image pipeline @ score >= %g" % DECISION_THRESHOLD), ""]
    out.append("Threshold sweep")
    out.append(render_sweep(results))

    groups = group_breakdown(results)
    if len(groups) > 1:
        out += ["", "Per-source breakdown", "  " + "-" * 56,
                "  %-20s %5s %10s %8s %8s" % ("source", "n", "precision", "recall", "F1")]
        for name, g in sorted(groups.items()):
            out.append("  %-20s %5d %9.1f%% %7.1f%% %7.1f%%" % (
                name[:20], g.total, g.precision * 100, g.recall * 100, g.f1 * 100))

    fails = failure_cases(results, limit=8)
    out += ["", "Missed betting images (scored safe) — worst first"]
    if not fails["missed_threats"]:
        out.append("  none")
    for r in fails["missed_threats"]:
        out.append("  [score %5.1f] %s" % (r.score, r.detail[:78]))
        out.append("               ocr chars=%s logos=%s" % (
            r.extra.get("chars"), r.extra.get("logos")))

    out += ["", "False alarms on benign images — worst first  <- the informative half"]
    if not fails["false_alarms"]:
        out.append("  none")
    for r in fails["false_alarms"]:
        out.append("  [score %5.1f] %s" % (r.score, r.detail[:78]))

    return "\n".join(out)


if __name__ == "__main__":
    use_utf8_stdout()
    ap = argparse.ArgumentParser(description="Evaluate the betting IMAGE pipeline")
    ap.add_argument("--dataset", help="Directory containing manifest.csv",
                    default=str(DATASET_DIR))
    ap.add_argument("--limit", type=int, help="Only score the first N images")
    args = ap.parse_args()

    print(report(evaluate(Path(args.dataset), limit=args.limit)))
