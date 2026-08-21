"""
evaluation/eval_deepfake.py
---------------------------
Evaluates the deepfake detector against the validation split produced by
dataset_split/build_splits.py.

STATUS ON THIS MACHINE: CANNOT RUN — the media is missing.

  val_small.csv holds 153 rows (79 manipulated / 74 original) from the DFD
  corpus, but every path points at D:\\archive\\..., which does not exist here.
  The split file is a list of pointers, not the data.

That is worth stating plainly rather than papering over: the deepfake model
currently has NO published accuracy. It was trained, a validation split was
defined, and the resulting numbers were never recorded anywhere in the repo.
Until this script is run on a machine that has the corpus, any claim about how
well the deepfake detector performs is unsupported.

To produce real numbers:
  1. Restore or re-download the DFD dataset so the paths in val_small.csv
     resolve (or pass --media-root to remap them).
  2. python evaluation/eval_deepfake.py --media-root /path/to/archive
  3. Paste the output into RESULTS.md.

The evaluation itself is deliberately run through blueprints/deepfake.py's own
_run_prediction, so it measures the code path the application actually serves,
including MTCNN face detection and the frame-sampling logic — not just the
classifier in isolation.
"""

from __future__ import annotations

import argparse
import csv
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evaluation.metrics import (  # noqa: E402
    ScoredResult, confusion_from_results, render_sweep,
    failure_cases, use_utf8_stdout,
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VAL_SPLIT = os.path.join(
    BASE_DIR, "deepfake detection", "deepfake-detection",
    "dataset_split", "val_small.csv"
)

# The app calls anything above 0.5 mean fake-probability FAKE.
DECISION_THRESHOLD = 50.0


def load_split(path: str = VAL_SPLIT, media_root: str | None = None) -> list[dict]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Validation split not found: {path}")
    rows = []
    with open(path, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            original = row["path"]
            resolved = original
            if media_root:
                # Remap "D:\archive\<rest>" onto <media_root>/<rest>.
                tail = original.replace("\\", "/").split("/archive/", 1)
                resolved = os.path.join(media_root, tail[1]) if len(tail) == 2 \
                    else os.path.join(media_root, os.path.basename(original))
            rows.append({
                "path": resolved,
                "original_path": original,
                "label": int(row["label"]),      # 1 = manipulated/fake
            })
    return rows


def check_availability(rows: list[dict]) -> tuple[int, int]:
    present = sum(1 for r in rows if os.path.exists(r["path"]))
    return present, len(rows)


def evaluate(media_root: str | None = None, limit: int | None = None) -> dict:
    rows = load_split(media_root=media_root)
    present, total = check_availability(rows)

    if present == 0:
        return {"available": 0, "total": total, "rows": rows, "results": []}

    rows = [r for r in rows if os.path.exists(r["path"])]
    if limit:
        rows = rows[:limit]

    from blueprints.deepfake import _run_prediction

    results: list[ScoredResult] = []
    for i, row in enumerate(rows, 1):
        actual_fake = row["label"] == 1
        try:
            # _run_prediction returns 4 values: the Grad-CAM work added
            # `artefacts` (the highest-scoring face + its input tensor) and
            # this call site was never updated, so every clip raised
            # "too many values to unpack" and was skipped -- which the report
            # then rendered as NOT RUN. The explanation artefacts are not
            # needed here; only the verdict is being measured.
            verdict, score, frames, _artefacts = _run_prediction(Path(row["path"]))
        except Exception as exc:
            print(f"  [{i}/{len(rows)}] ERROR {os.path.basename(row['path'])}: {exc}")
            continue

        if verdict is None:
            # No face found. Counted as "not flagged": that is what the user
            # sees, and a detector that cannot find a face in a manipulated
            # clip has still failed to catch it.
            results.append(ScoredResult(
                identifier=os.path.basename(row["path"]),
                actual_threat=actual_fake, score=0.0, predicted_threat=False,
                detail="no face detected",
                group="no_face",
            ))
            continue

        pct = score * 100
        results.append(ScoredResult(
            identifier=os.path.basename(row["path"]),
            actual_threat=actual_fake,
            score=pct,
            predicted_threat=pct >= DECISION_THRESHOLD,
            detail=f"{verdict} over {frames} frame(s)",
            group="scored",
        ))
        if i % 10 == 0:
            print(f"  ...{i}/{len(rows)}")

    return {"available": present, "total": total, "rows": rows, "results": results}


def report(data: dict) -> str:
    out = []
    out.append("=" * 66)
    out.append("DEEPFAKE DETECTOR")
    out.append("Dataset: dataset_split/val_small.csv (real, held-out split)")
    out.append("=" * 66)
    out.append("")

    if not data["results"]:
        out.append(f"  NOT RUN — 0 of {data['total']} media files are present on this machine.")
        out.append("")
        out.append("  val_small.csv references paths under D:\\archive\\ which do not")
        out.append("  exist here. The split is a list of pointers, not the data itself.")
        out.append("")
        out.append("  Consequence: the deepfake detector has NO measured accuracy.")
        out.append("  Do not quote a figure for it until this has been run.")
        out.append("")
        out.append("  To run:")
        out.append("    python evaluation/eval_deepfake.py --media-root /path/to/archive")
        if data["rows"]:
            out.append("")
            out.append(f"  Split composition: {data['total']} clips "
                       f"({sum(1 for r in data['rows'] if r['label'] == 1)} fake / "
                       f"{sum(1 for r in data['rows'] if r['label'] == 0)} real)")
            out.append(f"  Example expected path: {data['rows'][0]['original_path']}")
        return "\n".join(out)

    results = data["results"]
    cm = confusion_from_results(results)
    no_face = [r for r in results if r.group == "no_face"]

    out.append(f"  evaluated {len(results)} of {data['total']} clips")
    out.append(f"  no face detected in {len(no_face)} clip(s)")
    out.append("")
    out.append(cm.render(f"Deepfake detector @ fake-probability >= {DECISION_THRESHOLD}%"))
    out.append("")
    out.append("Threshold sweep")
    out.append(render_sweep(results))
    out.append("")

    fails = failure_cases(results, limit=8)
    out.append("Missed fakes (manipulated media passed as real)")
    for r in fails["missed_threats"] or []:
        out.append(f"  [{r.score:5.1f}%] {r.identifier} — {r.detail}")
    out.append("")
    out.append("False alarms (authentic media called fake)")
    for r in fails["false_alarms"] or []:
        out.append(f"  [{r.score:5.1f}%] {r.identifier} — {r.detail}")
    return "\n".join(out)


def smoke_test() -> str:
    """
    Run the prediction pipeline on whatever media is on hand.

    This measures NOTHING about accuracy — the files have no labels. It answers
    a different and currently unanswered question: does the pipeline still run
    end to end? Two recent fixes have never been exercised against real media:

      * .cpu() before .numpy() on the MTCNN output (crashes on CUDA hosts)
      * the frame-count fallback for codecs reporting 0 or -1 frames, which
        previously produced an empty sample loop and surfaced to the user as a
        misleading "No face detected"

    A green run here means the code path works. It does not mean the model is
    right.
    """
    upload_dir = os.path.join(BASE_DIR, "static", "uploads")
    media = []
    if os.path.isdir(upload_dir):
        for name in sorted(os.listdir(upload_dir)):
            if os.path.splitext(name)[1].lower() in {".mp4", ".avi", ".mov", ".mkv",
                                                     ".jpg", ".jpeg", ".png"}:
                media.append(os.path.join(upload_dir, name))

    out = ["=" * 66,
           "DEEPFAKE — PIPELINE SMOKE TEST (functional, NOT accuracy)",
           "=" * 66, ""]
    if not media:
        out.append("  No media found in static/uploads — nothing to exercise.")
        return "\n".join(out)

    # Deduplicate identical files: the uploads folder holds the same clip
    # several times under different ids, which would just repeat the test.
    seen_sizes: dict[int, str] = {}
    unique = []
    for path in media:
        size = os.path.getsize(path)
        if size in seen_sizes:
            continue
        seen_sizes[size] = path
        unique.append(path)

    out.append(f"  {len(media)} file(s) present, {len(unique)} unique by size")
    out.append("  Labels: NONE. No accuracy can be computed from these.")
    out.append("")

    from blueprints.deepfake import _run_prediction

    ok = failed = 0
    for path in unique[:5]:
        name = os.path.basename(path)
        try:
            verdict, score, frames = _run_prediction(Path(path))
            if verdict is None:
                out.append(f"  {name[:44]:<46} ran, no face detected")
            else:
                out.append(f"  {name[:44]:<46} {verdict} "
                           f"({score * 100:.1f}%) over {frames} frame(s)")
            ok += 1
        except Exception as exc:
            out.append(f"  {name[:44]:<46} FAILED: {type(exc).__name__}: {exc}")
            failed += 1

    out.append("")
    out.append(f"  pipeline ran without error on {ok}/{ok + failed} file(s)")
    if failed:
        out.append("  ^ investigate the failures above before trusting any run")
    return "\n".join(out)


if __name__ == "__main__":
    use_utf8_stdout()
    ap = argparse.ArgumentParser()
    ap.add_argument("--media-root", help="Directory the archive paths should resolve against")
    ap.add_argument("--limit", type=int, help="Evaluate only the first N clips")
    ap.add_argument("--smoke-test", action="store_true",
                    help="Exercise the pipeline on unlabelled local media (no accuracy)")
    ap.add_argument("--dump", metavar="PATH",
                    help="Write per-clip (identifier,score,label) rows to CSV. "
                         "These are the held-out pairs services/intel/calibration.py "
                         "needs to fit a calibrator, and the only way to pick a "
                         "threshold on one split and verify it on another.")
    args = ap.parse_args()
    if args.smoke_test:
        print(smoke_test())
    else:
        data = evaluate(media_root=args.media_root, limit=args.limit)
        if args.dump:
            import csv as _csv
            with open(args.dump, "w", encoding="utf-8", newline="") as fh:
                w = _csv.writer(fh)
                w.writerow(["identifier", "score", "label"])
                for r in data["results"]:
                    w.writerow([r.identifier, "%.6f" % r.score, int(r.actual_threat)])
            print("wrote %d rows to %s" % (len(data["results"]), args.dump))
        print(report(data))
