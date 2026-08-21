"""
services/scam_detector/fraud_scorer.py
--------------------------------------
Combines NLP text threat score and link risk score into a single
final risk score, then maps it to a traffic-light colour.

Scoring logic:
  - text_score  (0–100): from nlp_analyzer — keyword / ML signal
  - link_risk   (0–60) : from link_checker — domain age signal

  weighted    = 0.80 * text_score + 0.20 * link_risk
  final_score = max(weighted, link_risk)   (capped at 100)

  The max() matters. link_risk tops out at 60, not 100, so under a pure
  weighted average it could contribute at most 0.20 * 60 = 12 points. A
  message with clean wording but a link to a domain registered days earlier
  scored 12 and was reported green/Safe — discarding the single most reliable
  scam indicator the system has. Taking the max lets a strong link signal set
  a floor on the final score while the weighted term still lets the two
  signals reinforce each other.

  Colour mapping:
    0–30   → green  (Safe)
    31–70  → yellow (Suspicious)
    71–100 → red    (Scam / High Risk)
"""

from __future__ import annotations
from typing import Tuple

# Weight distribution (must sum to 1.0)
TEXT_WEIGHT = 0.8
LINK_WEIGHT = 0.2

# Thresholds
GREEN_MAX = 30
YELLOW_MAX = 70


def compute_risk(
    text_score: int,
    link_risk: int,
) -> Tuple[int, str]:
    """
    Compute a final risk score and traffic-light colour.

    Args:
        text_score: NLP keyword/ML score (0–100).
        link_risk:  Link/domain age score  (0–60).

    Returns:
        (final_score, colour) where colour ∈ {"green", "yellow", "red"}.
    """
    text_score = max(0, min(100, int(text_score)))
    link_risk = max(0, min(100, int(link_risk)))

    weighted = (TEXT_WEIGHT * text_score) + (LINK_WEIGHT * link_risk)
    # A freshly-registered domain is on its own enough to warrant a warning,
    # so link_risk acts as a floor rather than a 12-point nudge.
    raw = max(weighted, link_risk)
    final_score = int(min(round(raw), 100))

    if final_score <= GREEN_MAX:
        colour = "green"
    elif final_score <= YELLOW_MAX:
        colour = "yellow"
    else:
        colour = "red"

    return final_score, colour
