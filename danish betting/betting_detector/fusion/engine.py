"""
fusion/engine.py
----------------
Score Fusion Engine — combines OCR/NLP and YOLO confidence scores
into a single final classification.

Weights
-------
  text_probability  × 0.6
  vision_probability × 0.4

Classification thresholds
-------------------------
  final_score > 0.7  → "BETTING"
  final_score > 0.4  → "SUSPICIOUS"
  else               → "SAFE"
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from loguru import logger

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
TEXT_WEIGHT: float = 0.6
VISION_WEIGHT: float = 0.4

BETTING_THRESHOLD: float = 0.70
SUSPICIOUS_THRESHOLD: float = 0.40

Classification = Literal["BETTING", "SUSPICIOUS", "SAFE"]


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------
@dataclass
class FusionResult:
    """Full output from the fusion engine."""

    classification: Classification
    final_score: float
    text_probability: float
    vision_probability: float
    matched_keywords: list[str]
    detected_objects: list[str]
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "classification": self.classification,
            "confidence": round(self.final_score, 4),
            "text_probability": round(self.text_probability, 4),
            "vision_probability": round(self.vision_probability, 4),
            "matched_keywords": self.matched_keywords,
            "detected_objects": self.detected_objects,
            "reasons": self.reasons,
        }


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------
class FusionEngine:
    """
    Combines signals from the text classifier and YOLO detector.

    Parameters
    ----------
    text_weight : float
        Weight applied to the text classifier probability (default 0.6).
    vision_weight : float
        Weight applied to the YOLO vision probability (default 0.4).
    betting_threshold : float
        Minimum score to classify as BETTING (default 0.70).
    suspicious_threshold : float
        Minimum score to classify as SUSPICIOUS (default 0.40).
    """

    def __init__(
        self,
        text_weight: float = TEXT_WEIGHT,
        vision_weight: float = VISION_WEIGHT,
        betting_threshold: float = BETTING_THRESHOLD,
        suspicious_threshold: float = SUSPICIOUS_THRESHOLD,
    ) -> None:
        self.text_weight = text_weight
        self.vision_weight = vision_weight
        self.betting_threshold = betting_threshold
        self.suspicious_threshold = suspicious_threshold

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def fuse(
        self,
        text_probability: float,
        vision_probability: float,
        matched_keywords: list[str] | None = None,
        detected_objects: list[str] | None = None,
    ) -> FusionResult:
        """
        Compute the final score and classification.

        Parameters
        ----------
        text_probability : float
            Betting probability from the NLP text classifier (0-1).
        vision_probability : float
            Betting probability from the YOLO detector (0-1).
        matched_keywords : list[str] | None
            Keywords matched by the text classifier.
        detected_objects : list[str] | None
            Object labels detected by YOLO.

        Returns
        -------
        FusionResult
            Classification, score, and full explanation.
        """
        text_probability = float(max(0.0, min(1.0, text_probability)))
        vision_probability = float(max(0.0, min(1.0, vision_probability)))

        final_score = (
            self.text_weight * text_probability
            + self.vision_weight * vision_probability
        )

        classification = self._classify(final_score)
        reasons = self._build_reasons(
            classification, final_score, text_probability, vision_probability,
            matched_keywords or [], detected_objects or [],
        )

        logger.debug(
            f"Fusion → text={text_probability:.3f}, vision={vision_probability:.3f}, "
            f"final={final_score:.3f}, class={classification}"
        )

        return FusionResult(
            classification=classification,
            final_score=round(final_score, 4),
            text_probability=text_probability,
            vision_probability=vision_probability,
            matched_keywords=matched_keywords or [],
            detected_objects=detected_objects or [],
            reasons=reasons,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _classify(self, score: float) -> Classification:
        if score > self.betting_threshold:
            return "BETTING"
        if score > self.suspicious_threshold:
            return "SUSPICIOUS"
        return "SAFE"

    @staticmethod
    def _build_reasons(
        classification: Classification,
        final_score: float,
        text_prob: float,
        vision_prob: float,
        keywords: list[str],
        objects: list[str],
    ) -> list[str]:
        reasons: list[str] = []

        if keywords:
            reasons.append(
                f"Text classifier detected betting-related keywords: {', '.join(keywords)}"
            )
        if objects:
            reasons.append(
                f"YOLO detected betting-related objects: {', '.join(objects)}"
            )
        if text_prob > 0.5:
            reasons.append(
                f"High text betting probability ({text_prob:.0%})"
            )
        if vision_prob > 0.5:
            reasons.append(
                f"High visual betting probability ({vision_prob:.0%})"
            )
        if not reasons:
            reasons.append(
                f"Final score {final_score:.2f} → classified as {classification}"
            )

        return reasons
