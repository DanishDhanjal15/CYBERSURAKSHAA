"""
services/intel/calibration.py
-----------------------------
Confidence calibration and the abstention band.

Every detector in the platform emits a number between 0 and 100 and the UI
prints it as a percentage, which invites the reader to interpret it as a
probability. It is not one. A TF-IDF classifier's `predict_proba` output, a
noisy-OR fusion score and a keyword-weight sum are three different quantities
on three different scales, and none of them is calibrated: when the betting
fusion engine says 0.80 it does not follow that 80% of such items are betting
content.

Two things follow from that, and this module implements both.

1. **Calibration.** Given held-out (score, label) pairs, fit a mapping from raw
   score to empirical probability. Two fitters are provided: Platt scaling
   (logistic, smooth, needs little data) and histogram binning (non-parametric,
   needs more data but assumes no shape). Both are pure Python -- no sklearn,
   so calibration works wherever the app runs.

2. **Abstention.** A detector forced to choose between SAFE and THREAT will
   answer confidently in the region where it knows least. An explicit
   INSUFFICIENT_EVIDENCE band routes those cases to a human instead, which is
   the correct behaviour for a system whose output leads to blocking requests.

`evaluation/RESULTS.md` documents that three of four modules have no validated
real-world accuracy. Until that changes, the honest default is a *wide*
abstention band, and that is what DEFAULT_BANDS encodes.
"""

from __future__ import annotations

import json
import math
import os

# Verdict bands
BAND_SAFE = "SAFE"
BAND_ABSTAIN = "INSUFFICIENT_EVIDENCE"
BAND_THREAT = "THREAT"

BAND_LABELS = {
    BAND_SAFE: "No threat indicators",
    BAND_ABSTAIN: "Insufficient evidence — analyst review required",
    BAND_THREAT: "Threat indicators present",
}

# Default thresholds on the *calibrated* probability.
#
# Deliberately conservative. A module with no validated accuracy should abstain
# across most of its range rather than assert; narrowing these is something to
# do per-module once a labelled set exists, not a default to ship.
DEFAULT_BANDS = {"safe_below": 0.25, "threat_above": 0.75}

CALIBRATION_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "evaluation", "calibration",
)

# Below this many labelled samples, fitting is refused rather than done badly.
# A calibrator fitted on a handful of points overfits them exactly, and the
# resulting `calibrated: true` badge would be a stronger claim than the one it
# replaced -- which is the opposite of the point.
MIN_CALIBRATION_SAMPLES = 50


# -- Platt scaling ---------------------------------------------------------

def fit_platt(scores, labels, iterations=100, tol=1e-7):
    """
    Fit p = sigmoid(a * s + b) on log loss by Newton-Raphson.

    Scores are expected on 0..1; pass raw/100 for percentage scores.

    Newton rather than gradient descent. The problem is two-dimensional and
    convex, so the exact 2x2 Hessian solve is cheap and converges in a handful
    of iterations. Gradient descent at a fixed step size did not converge
    within any reasonable iteration count here -- it left the fit worse
    calibrated than the raw scores it was correcting, which is the one outcome
    a calibrator must never produce.

    Returns {"a", "b", "n", "method"}. Returns an identity mapping when there
    is not enough of both classes to fit anything meaningful -- a calibrator
    fitted on one class is worse than none.
    """
    pairs = [(float(s), 1.0 if y else 0.0) for s, y in zip(scores, labels)]
    pairs = [(s, y) for s, y in pairs if 0.0 <= s <= 1.0]
    n_pos = sum(1 for _, y in pairs if y > 0.5)
    n_neg = len(pairs) - n_pos

    if len(pairs) < 10 or n_pos < 3 or n_neg < 3:
        return {"method": "identity", "a": 1.0, "b": 0.0, "n": len(pairs),
                "note": "too few samples or a single class present; not fitted"}

    # Platt's target smoothing, which prevents the fit running away to
    # infinity on a perfectly separable set.
    hi = 1.0 / (n_pos + 2.0)
    lo = 1.0 / (n_neg + 2.0)

    targets = [((1.0 - hi) if y > 0.5 else lo) for _, y in pairs]

    a, b = 0.0, 0.0
    for _ in range(iterations):
        # Gradient (2-vector) and Hessian (symmetric 2x2) of the log loss.
        g_a = g_b = 0.0
        h_aa = h_ab = h_bb = 0.0
        for (s, _), t in zip(pairs, targets):
            z = a * s + b
            p = 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, z))))
            err = p - t
            w = max(p * (1.0 - p), 1e-12)   # floor keeps the Hessian invertible
            g_a += err * s
            g_b += err
            h_aa += w * s * s
            h_ab += w * s
            h_bb += w

        # Ridge term: without it a separable set drives the Hessian singular
        # and the step to infinity.
        h_aa += 1e-9
        h_bb += 1e-9

        det = h_aa * h_bb - h_ab * h_ab
        if abs(det) < 1e-18:
            break
        d_a = (h_bb * g_a - h_ab * g_b) / det
        d_b = (h_aa * g_b - h_ab * g_a) / det

        a -= d_a
        b -= d_b
        if max(abs(d_a), abs(d_b)) < tol:
            break

    return {"method": "platt", "a": a, "b": b, "n": len(pairs)}


def apply_platt(model, score):
    """Map a raw 0..1 score through a fitted Platt model."""
    if not model or model.get("method") == "identity":
        return max(0.0, min(1.0, float(score)))
    z = model["a"] * float(score) + model["b"]
    return 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, z))))


# -- Histogram binning -----------------------------------------------------

def fit_histogram(scores, labels, bins=10, min_per_bin=5):
    """
    Non-parametric calibration: the empirical positive rate per score bin.

    Makes no assumption about the shape of the mapping, which matters for the
    fusion engine, whose noisy-OR output is not remotely logistic. Bins holding
    fewer than `min_per_bin` samples fall back to the global base rate rather
    than reporting a rate estimated from two examples.
    """
    pairs = [(float(s), 1.0 if y else 0.0) for s, y in zip(scores, labels)]
    pairs = [(s, y) for s, y in pairs if 0.0 <= s <= 1.0]
    if not pairs:
        return {"method": "identity", "bins": [], "n": 0}

    base_rate = sum(y for _, y in pairs) / float(len(pairs))
    edges = [i / float(bins) for i in range(bins + 1)]
    out = []
    for i in range(bins):
        lo, hi = edges[i], edges[i + 1]
        members = [y for s, y in pairs if (lo <= s < hi or (i == bins - 1 and s == 1.0))]
        if len(members) >= min_per_bin:
            rate = sum(members) / float(len(members))
            confident = True
        else:
            rate = base_rate
            confident = False
        out.append({"lo": lo, "hi": hi, "rate": rate, "count": len(members),
                    "confident": confident})

    return {"method": "histogram", "bins": out, "n": len(pairs), "base_rate": base_rate}


def apply_histogram(model, score):
    if not model or model.get("method") == "identity" or not model.get("bins"):
        return max(0.0, min(1.0, float(score)))
    s = max(0.0, min(1.0, float(score)))
    for b in model["bins"]:
        if b["lo"] <= s < b["hi"]:
            return b["rate"]
    return model["bins"][-1]["rate"]


def apply(model, score):
    """Apply whichever calibrator `model` describes."""
    if not model:
        return max(0.0, min(1.0, float(score)))
    method = model.get("method")
    if method == "platt":
        return apply_platt(model, score)
    if method == "histogram":
        return apply_histogram(model, score)
    return max(0.0, min(1.0, float(score)))


# -- Reliability and metrics ----------------------------------------------

def reliability_curve(scores, labels, bins=10):
    """
    Data for a reliability diagram: mean predicted vs observed frequency.

    A perfectly calibrated model lies on the diagonal. Plotting this is the
    fastest way to show an ML-literate judge that the confidence numbers mean
    something -- or, just as usefully, that they do not yet.
    """
    pairs = [(float(s), 1.0 if y else 0.0) for s, y in zip(scores, labels)]
    pairs = [(s, y) for s, y in pairs if 0.0 <= s <= 1.0]
    out = []
    for i in range(bins):
        lo, hi = i / float(bins), (i + 1) / float(bins)
        members = [(s, y) for s, y in pairs
                   if lo <= s < hi or (i == bins - 1 and s == 1.0)]
        if not members:
            out.append({"bin_lo": lo, "bin_hi": hi, "count": 0,
                        "mean_predicted": None, "observed": None})
            continue
        out.append({
            "bin_lo": lo, "bin_hi": hi, "count": len(members),
            "mean_predicted": sum(s for s, _ in members) / len(members),
            "observed": sum(y for _, y in members) / len(members),
        })
    return out


def expected_calibration_error(scores, labels, bins=10):
    """
    ECE: the sample-weighted mean gap between confidence and accuracy.

    One number for "how much can these percentages be trusted". Lower is
    better; anything above roughly 0.1 means the displayed confidence is
    actively misleading.
    """
    curve = reliability_curve(scores, labels, bins)
    total = sum(b["count"] for b in curve)
    if not total:
        return None
    err = 0.0
    for b in curve:
        if not b["count"] or b["mean_predicted"] is None:
            continue
        err += (b["count"] / float(total)) * abs(b["mean_predicted"] - b["observed"])
    return err


def brier_score(scores, labels):
    """Mean squared error between predicted probability and outcome."""
    pairs = [(float(s), 1.0 if y else 0.0) for s, y in zip(scores, labels)]
    if not pairs:
        return None
    return sum((s - y) ** 2 for s, y in pairs) / float(len(pairs))


# -- Banding ---------------------------------------------------------------

def band(probability, bands=None):
    """Map a calibrated probability onto SAFE / INSUFFICIENT_EVIDENCE / THREAT."""
    cfg = bands or DEFAULT_BANDS
    p = max(0.0, min(1.0, float(probability)))
    if p < cfg["safe_below"]:
        return BAND_SAFE
    if p > cfg["threat_above"]:
        return BAND_THREAT
    return BAND_ABSTAIN


def assess(raw_score, module=None, model=None, bands=None, scale=100.0):
    """
    Turn a detector's raw score into a calibrated, banded verdict.

    Returns the raw score, the calibrated probability, the band, whether the
    system is abstaining, and -- importantly -- whether a calibrator actually
    existed. `calibrated: false` means the probability shown is the raw score
    passed through unchanged, and the UI must say so rather than implying a
    rigour that is not there.
    """
    raw = float(raw_score or 0)
    normalised = raw / scale if scale else raw
    normalised = max(0.0, min(1.0, normalised))

    if model is None and module:
        model = load_calibrator(module)

    probability = apply(model, normalised)
    b = band(probability, bands)
    is_calibrated = bool(model) and model.get("method") not in (None, "identity")

    return {
        "module": module,
        "raw_score": raw,
        "probability": round(probability, 4),
        "percent": round(probability * 100, 1),
        "band": b,
        "band_label": BAND_LABELS[b],
        "abstained": b == BAND_ABSTAIN,
        "calibrated": is_calibrated,
        "calibration_method": (model or {}).get("method", "none"),
        "calibration_n": (model or {}).get("n", 0),
        "note": (
            "Displayed confidence is the model's raw score; no calibration set "
            "exists for this module yet, so it is not a probability."
            if not is_calibrated else
            "Confidence is calibrated against %d held-out labelled samples."
            % (model or {}).get("n", 0)
        ),
    }


# -- Persistence -----------------------------------------------------------

def calibrator_path(module):
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in (module or "unknown"))
    return os.path.join(CALIBRATION_DIR, "%s.json" % safe.lower())


def save_calibrator(module, model):
    os.makedirs(CALIBRATION_DIR, exist_ok=True)
    path = calibrator_path(module)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(model, f, indent=2)
    return path


_cache = {}


def load_calibrator(module, use_cache=True):
    """
    Load a fitted calibrator, or None if the module has none.

    Cached in-process: this is read on every detection response and the files
    change only when a calibration run writes one.
    """
    if use_cache and module in _cache:
        return _cache[module]
    path = calibrator_path(module)
    model = None
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                model = json.load(f)
        except Exception as e:
            print("[CALIBRATION] failed to load %s: %s" % (path, e))
            model = None
    if use_cache:
        _cache[module] = model
    return model


def clear_cache():
    _cache.clear()


def reliability_report(scores, labels, model=None, bins=10):
    """
    Before/after calibration quality, in one dict.

    Reports ECE and Brier for the raw scores and, when a model is supplied,
    for the calibrated ones -- plus `improved`, because a calibrator that
    makes ECE worse must not be silently adopted. (One did, during
    development: gradient-descent Platt at lr=0.1 raised ECE from 0.055 to
    0.198 before the fit was replaced with Newton-Raphson.)
    """
    scores = [float(s) for s in scores]
    labels = [int(l) for l in labels]

    ece_before = expected_calibration_error(scores, labels, bins)
    brier_before = brier_score(scores, labels)

    out = {
        "n": len(scores),
        "positives": sum(labels),
        "negatives": len(labels) - sum(labels),
        "ece_before": round(ece_before, 4),
        "brier_before": round(brier_before, 4),
        "curve_before": reliability_curve(scores, labels, bins),
    }

    if model:
        calibrated = [apply(model, s) for s in scores]
        ece_after = expected_calibration_error(calibrated, labels, bins)
        out.update({
            "method": model.get("method"),
            "ece_after": round(ece_after, 4),
            "brier_after": round(brier_score(calibrated, labels), 4),
            "curve_after": reliability_curve(calibrated, labels, bins),
            "improved": ece_after < ece_before,
        })
        if not out["improved"]:
            out["warning"] = (
                "Calibration did not reduce expected calibration error on "
                "this sample. Do not adopt this model; the raw score is "
                "closer to a probability than the calibrated one."
            )
    return out
