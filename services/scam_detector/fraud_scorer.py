"""
services/scam_detector/fraud_scorer.py
--------------------------------------
Combines NLP text threat score and link risk score into a single
final risk score, then maps it to a traffic-light colour.

Scoring logic:
  - text_score  (0–100): from nlp_analyzer — keyword / ML signal
  - link_risk   (0–60) : from link_checker — domain age signal

  final_score = 0.80 * text_score + 0.20 * link_risk  (capped at 100)

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
    raw = (TEXT_WEIGHT * text_score) + (LINK_WEIGHT * link_risk)
    final_score = int(min(round(raw), 100))

    if final_score <= GREEN_MAX:
        colour = "green"
    elif final_score <= YELLOW_MAX:
        colour = "yellow"
    else:
        colour = "red"

    return final_score, colour
