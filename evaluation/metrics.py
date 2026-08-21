"""
evaluation/metrics.py
---------------------
Classification metrics with no third-party dependencies, so the harness runs
in any environment the app itself runs in.

Positive class = "threat" (scam / betting / fake / high-risk). That choice
matters for how the numbers read:

  precision — of everything we flagged, how much was actually a threat.
              Low precision means analysts waste time on false alarms.
  recall    — of all real threats, how many we caught.
              Low recall means threats slip through.

For this kind of tool recall is usually the more expensive one to get wrong,
but a detector that flags everything has perfect recall and is useless, which
is why both are always reported together.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field


def use_utf8_stdout() -> None:
    """
    Make stdout tolerate non-ASCII output.

    The corpus is multilingual, so failure-case listings contain Devanagari.
    On Windows the console defaults to cp1252 and printing those characters
    raises UnicodeEncodeError, killing the run after the metrics were already
    computed. Characters the terminal genuinely cannot render degrade to '?'
    rather than taking the report down with them.
    """
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass


@dataclass
class ConfusionMatrix:
    tp: int = 0   # flagged as threat, really was one
    fp: int = 0   # flagged as threat, actually benign   → false alarm
    tn: int = 0   # passed as benign, really was benign
    fn: int = 0   # passed as benign, actually a threat  → missed threat

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @property
    def accuracy(self) -> float:
        return (self.tp + self.tn) / self.total if self.total else 0.0

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def specificity(self) -> float:
        """Share of benign items correctly left alone."""
        denom = self.tn + self.fp
        return self.tn / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def false_positive_rate(self) -> float:
        denom = self.fp + self.tn
        return self.fp / denom if denom else 0.0

    def add(self, predicted_threat: bool, actual_threat: bool) -> None:
        if predicted_threat and actual_threat:
            self.tp += 1
        elif predicted_threat and not actual_threat:
            self.fp += 1
        elif not predicted_threat and not actual_threat:
            self.tn += 1
        else:
            self.fn += 1

    def as_dict(self) -> dict:
        return {
            "n": self.total,
            "tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn,
            "accuracy": round(self.accuracy, 4),
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "specificity": round(self.specificity, 4),
            "f1": round(self.f1, 4),
            "fpr": round(self.false_positive_rate, 4),
        }

    def render(self, title: str = "") -> str:
        lines = []
        if title:
            lines.append(title)
            lines.append("-" * len(title))
        lines.append(f"  n = {self.total}")
        lines.append("")
        lines.append("                     actual")
        lines.append("                threat   benign")
        lines.append(f"  pred threat   {self.tp:>6}   {self.fp:>6}")
        lines.append(f"  pred benign   {self.fn:>6}   {self.tn:>6}")
        lines.append("")
        lines.append(f"  accuracy    {self.accuracy:6.1%}")
        lines.append(f"  precision   {self.precision:6.1%}   (of flagged, how many were real)")
        lines.append(f"  recall      {self.recall:6.1%}   (of real threats, how many caught)")
        lines.append(f"  specificity {self.specificity:6.1%}   (of benign, how many left alone)")
        lines.append(f"  F1          {self.f1:6.1%}")
        return "\n".join(lines)


@dataclass
class ScoredResult:
    """One evaluated item: its true label, the model's score, and context."""
    identifier: str
    actual_threat: bool
    score: float                     # 0-100
    predicted_threat: bool
    detail: str = ""
    group: str = ""                  # optional slice key (language, module…)
    extra: dict = field(default_factory=dict)


def confusion_from_results(results: list[ScoredResult]) -> ConfusionMatrix:
    cm = ConfusionMatrix()
    for r in results:
        cm.add(r.predicted_threat, r.actual_threat)
    return cm


def confusion_at_threshold(results: list[ScoredResult], threshold: float) -> ConfusionMatrix:
    """Re-score the same results at a different decision threshold."""
    cm = ConfusionMatrix()
    for r in results:
        cm.add(r.score >= threshold, r.actual_threat)
    return cm


def threshold_sweep(results: list[ScoredResult],
                    thresholds: list[float] | None = None) -> list[tuple[float, ConfusionMatrix]]:
    """
    Metrics across a range of decision thresholds.

    Useful because the shipped thresholds were picked by hand. The sweep shows
    what the tuning actually costs: where recall falls off, and how many false
    alarms buying that recall would produce.
    """
    if thresholds is None:
        thresholds = [t * 10 for t in range(0, 11)]  # 0, 10, 20 ... 100
    return [(t, confusion_at_threshold(results, t)) for t in thresholds]


def render_sweep(results: list[ScoredResult]) -> str:
    lines = ["  threshold   precision   recall      F1     flagged"]
    lines.append("  " + "-" * 50)
    for t, cm in threshold_sweep(results):
        flagged = cm.tp + cm.fp
        lines.append(
            f"  {t:>7.0f}    {cm.precision:8.1%}  {cm.recall:8.1%}  {cm.f1:6.1%}   "
            f"{flagged:>4}/{cm.total}"
        )
    return "\n".join(lines)


def group_breakdown(results: list[ScoredResult]) -> dict[str, ConfusionMatrix]:
    """Per-slice confusion matrices (e.g. by language)."""
    groups: dict[str, ConfusionMatrix] = {}
    for r in results:
        key = r.group or "all"
        groups.setdefault(key, ConfusionMatrix()).add(r.predicted_threat, r.actual_threat)
    return groups


def failure_cases(results: list[ScoredResult], limit: int = 10) -> dict[str, list[ScoredResult]]:
    """
    The items the detector got wrong, worst first.

    These matter more than the headline number — they are what tells you
    *how* the detector fails, and they are what a reviewer will ask about.
    """
    misses = [r for r in results if r.actual_threat and not r.predicted_threat]
    alarms = [r for r in results if not r.actual_threat and r.predicted_threat]
    misses.sort(key=lambda r: r.score)            # most confidently missed
    alarms.sort(key=lambda r: -r.score)           # most confidently wrong
    return {
        "missed_threats": misses[:limit],
        "false_alarms": alarms[:limit],
    }


# ── Exact-match metrics (for extraction tasks) ───────────────────────────────

@dataclass
class ExactMatchResult:
    """
    For tasks where the answer is unambiguous — did we pull the right phone
    number out of this text, yes or no. No labelling judgement involved, so
    these numbers are the most trustworthy in the whole suite.
    """
    identifier: str
    expected: object
    actual: object
    passed: bool
    note: str = ""


def render_exact_match(name: str, results: list[ExactMatchResult]) -> str:
    passed = sum(1 for r in results if r.passed)
    total = len(results)
    pct = passed / total if total else 0.0
    lines = [f"{name}: {passed}/{total} passed ({pct:.1%})"]
    failures = [r for r in results if not r.passed]
    if failures:
        lines.append("  failures:")
        for r in failures:
            lines.append(f"    - {r.identifier}")
            lines.append(f"        expected: {r.expected!r}")
            lines.append(f"        actual:   {r.actual!r}")
            if r.note:
                lines.append(f"        note:     {r.note}")
    return "\n".join(lines)
