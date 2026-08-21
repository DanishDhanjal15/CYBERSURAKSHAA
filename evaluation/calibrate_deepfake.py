"""
calibrate_deepfake.py
---------------------
Fit a probability calibrator for the deepfake module, and choose its decision
threshold honestly.

WHY
---
Every module currently reports `calibrated: false`, and the UI prints the raw
score as a percentage. services/intel/calibration.py explains why that is not
a probability and implements the fix; all it ever needed was held-out
(score, label) pairs. evaluation/eval_deepfake.py now produces 153 of them.

TWO THINGS THIS DOES, AND WHY THEY ARE SPLIT
--------------------------------------------
1. Fits a Platt calibrator so 0.80 means "roughly 80 of every 100 such clips
   are manipulated", and reports ECE and Brier before/after so the improvement
   is measured rather than assumed.

2. Picks a decision threshold on one half of the data and reports it on the
   other. Reading the threshold sweep off the full set -- which is how the
   "50 -> 60 looks better" observation was first made -- tunes a parameter on
   the same clips used to score it. That number is optimistic by construction.
   A split costs nothing here and is the difference between a measurement and
   a guess.

The split is deterministic (sorted by identifier, alternating) so re-running
gives the same answer and the result can be checked.

Usage
-----
    python evaluation/eval_deepfake.py --dump scratch/deepfake_scores.csv
    python evaluation/calibrate_deepfake.py scratch/deepfake_scores.csv
    python evaluation/calibrate_deepfake.py scratch/deepfake_scores.csv --save
"""

from __future__ import annotations

import argparse
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from metrics import ConfusionMatrix, use_utf8_stdout  # noqa: E402
from services.intel import calibration  # noqa: E402

MODULE = "deepfake"


def load(path):
    rows = []
    with open(path, encoding="utf-8-sig", newline="") as f:
        for r in csv.DictReader(f):
            rows.append((r["identifier"], float(r["score"]), int(r["label"])))
    return rows


def split_alternating(rows):
    """Deterministic 50/50 split. Sorted first so file order cannot bias it."""
    ordered = sorted(rows, key=lambda r: r[0])
    return ordered[0::2], ordered[1::2]


def cm_at(rows, threshold):
    cm = ConfusionMatrix()
    for _, score, label in rows:
        cm.add(score >= threshold, bool(label))
    return cm


def sweep(rows, lo=30, hi=80, step=5):
    out = []
    t = lo
    while t <= hi:
        out.append((t, cm_at(rows, t)))
        t += step
    return out


def main():
    use_utf8_stdout()
    ap = argparse.ArgumentParser()
    ap.add_argument("scores_csv")
    ap.add_argument("--save", action="store_true",
                    help="Persist the fitted calibrator so the app uses it")
    args = ap.parse_args()

    rows = load(args.scores_csv)
    scores01 = [s / 100.0 for _, s, _ in rows]
    labels = [l for _, _, l in rows]

    print("=" * 66)
    print("DEEPFAKE — CALIBRATION AND THRESHOLD SELECTION")
    print("=" * 66)
    print()
    print("  pairs: %d  (%d manipulated / %d authentic)"
          % (len(rows), sum(labels), len(labels) - sum(labels)))
    print()

    # ---------------------------------------------------------------- part 1
    print("-" * 66)
    print("1. PROBABILITY CALIBRATION (Platt)")
    print("-" * 66)

    ece_before = calibration.expected_calibration_error(scores01, labels)
    brier_before = calibration.brier_score(scores01, labels)

    model = calibration.fit_platt(scores01, labels)
    cal = [calibration.apply(model, s) for s in scores01]

    ece_after = calibration.expected_calibration_error(cal, labels)
    brier_after = calibration.brier_score(cal, labels)

    print()
    print("  %-28s %10s  %10s" % ("", "raw", "calibrated"))
    print("  %-28s %10.4f  %10.4f" % ("expected calibration error", ece_before, ece_after))
    print("  %-28s %10.4f  %10.4f" % ("Brier score", brier_before, brier_after))
    print()
    print("  Lower is better for both. ECE is the average gap between the")
    print("  confidence shown and the frequency actually observed.")
    rep = calibration.reliability_report(scores01, labels, model=model)
    print("  Reliability — does the stated confidence match reality?")
    print("    %-14s %6s  %12s  %10s" % ("bucket", "n", "said", "actually"))
    for row in rep["curve_after"]:
        if not row["count"]:
            continue
        print("    %.1f - %.1f      %4d  %11.1f%%  %9.1f%%" % (
            row["bin_lo"], row["bin_hi"], row["count"],
            row["mean_predicted"] * 100, row["observed"] * 100))
    print()
    print("    'said' is the average calibrated confidence in that bucket;")
    print("    'actually' is how many really were fakes. Close = trustworthy.")

    # ---------------------------------------------------------------- part 2
    print()
    print("-" * 66)
    print("2. DECISION THRESHOLD — chosen on split A, reported on split B")
    print("-" * 66)

    a, b = split_alternating(rows)
    print()
    print("  split A: %d clips (%d fake)   split B: %d clips (%d fake)"
          % (len(a), sum(r[2] for r in a), len(b), sum(r[2] for r in b)))
    print()

    print("  Sweep on SPLIT A (selection only):")
    print("    thresh   precision   recall       F1")
    best_t, best_f1 = None, -1.0
    for t, cm in sweep(a):
        print("    %6d %10.1f%% %8.1f%% %8.1f%%"
              % (t, cm.precision * 100, cm.recall * 100, cm.f1 * 100))
        if cm.f1 > best_f1:
            best_t, best_f1 = t, cm.f1

    print()
    print("  best on A: threshold %d  (F1 %.1f%%)" % (best_t, best_f1 * 100))
    print()

    cur_b = cm_at(b, 50)
    new_b = cm_at(b, best_t)

    print("  Held-out check on SPLIT B — the number that counts:")
    print("    %-22s %10s %10s" % ("", "thresh 50", "thresh %d" % best_t))
    print("    %-22s %9.1f%% %9.1f%%" % ("precision", cur_b.precision * 100, new_b.precision * 100))
    print("    %-22s %9.1f%% %9.1f%%" % ("recall", cur_b.recall * 100, new_b.recall * 100))
    print("    %-22s %9.1f%% %9.1f%%" % ("F1", cur_b.f1 * 100, new_b.f1 * 100))
    print("    %-22s %9d %10d" % ("false alarms", cur_b.fp, new_b.fp))
    print("    %-22s %9d %10d" % ("missed fakes", cur_b.fn, new_b.fn))
    print()

    delta = (new_b.f1 - cur_b.f1) * 100
    if best_t == 50:
        print("  VERDICT: selection landed on 50. Keep the current threshold.")
    elif delta > 0.5:
        print("  VERDICT: %d holds up on unseen clips (+%.1f F1). Worth adopting."
              % (best_t, delta))
    elif delta < -0.5:
        print("  VERDICT: %d does NOT transfer (%.1f F1 on B). Keep 50."
              % (best_t, delta))
    else:
        print("  VERDICT: difference on B is %.1f F1 -- within noise at this n." % delta)
        print("  The apparent gain on the full set was threshold-fitting, not a")
        print("  real improvement. Keep 50 until there is more data.")

    # ---------------------------------------------------------------- save
    if args.save:
        calibration.save_calibrator(MODULE, model)
        print()
        print("  saved calibrator -> %s" % calibration.calibrator_path(MODULE))
        probe = calibration.assess(80.0, module=MODULE)
        print("  probe: raw 80.0 -> calibrated=%s probability=%.3f band=%s"
              % (probe.get("calibrated"), probe.get("probability"), probe.get("band")))
    else:
        print()
        print("  (dry run -- pass --save to persist the calibrator)")


if __name__ == "__main__":
    main()
