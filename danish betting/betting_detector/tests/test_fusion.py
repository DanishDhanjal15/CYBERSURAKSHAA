"""
tests/test_fusion.py
--------------------
Unit tests for the Fusion Engine.
"""

from __future__ import annotations

import pytest

from fusion.engine import FusionEngine, FusionResult


class TestFusionEngine:
    """Test score fusion and classification thresholds."""

    @pytest.fixture
    def engine(self) -> FusionEngine:
        return FusionEngine()

    # ── Classification threshold tests ────────────────────────────────

    def test_high_scores_classified_betting(self, engine):
        result = engine.fuse(text_probability=0.9, vision_probability=0.9)
        assert result.classification == "BETTING"

    def test_medium_scores_classified_suspicious(self, engine):
        result = engine.fuse(text_probability=0.5, vision_probability=0.4)
        assert result.classification == "SUSPICIOUS"

    def test_low_scores_classified_safe(self, engine):
        result = engine.fuse(text_probability=0.1, vision_probability=0.0)
        assert result.classification == "SAFE"

    def test_boundary_betting_threshold(self, engine):
        # Score is STRICTLY > threshold to classify as BETTING.
        # 0.7 * 0.6 + 0.7 * 0.4 = 0.70 → NOT > 0.70 → SUSPICIOUS
        result = engine.fuse(text_probability=0.7, vision_probability=0.7)
        assert result.classification == "SUSPICIOUS"
        # 0.9 * 0.6 + 0.9 * 0.4 = 0.90 → BETTING
        result2 = engine.fuse(text_probability=0.9, vision_probability=0.9)
        assert result2.classification == "BETTING"

    def test_boundary_suspicious_threshold(self, engine):
        # Score just above 0.4 but below 0.7
        result = engine.fuse(text_probability=0.5, vision_probability=0.2)
        # 0.5*0.6 + 0.2*0.4 = 0.30 + 0.08 = 0.38 → SAFE
        assert result.classification == "SAFE"

    # ── Score calculation ──────────────────────────────────────────────

    def test_weighted_score_calculation(self, engine):
        result = engine.fuse(text_probability=1.0, vision_probability=0.0)
        assert abs(result.final_score - 0.6) < 0.001

    def test_vision_weight(self, engine):
        result = engine.fuse(text_probability=0.0, vision_probability=1.0)
        assert abs(result.final_score - 0.4) < 0.001

    def test_equal_weights_sum_to_one(self, engine):
        result = engine.fuse(text_probability=1.0, vision_probability=1.0)
        assert abs(result.final_score - 1.0) < 0.001

    # ── Input clamping ────────────────────────────────────────────────

    def test_probability_clamped_above_one(self, engine):
        result = engine.fuse(text_probability=2.0, vision_probability=2.0)
        assert result.final_score <= 1.0

    def test_probability_clamped_below_zero(self, engine):
        result = engine.fuse(text_probability=-1.0, vision_probability=-1.0)
        assert result.final_score >= 0.0

    # ── Metadata propagation ──────────────────────────────────────────

    def test_keywords_propagated(self, engine):
        result = engine.fuse(
            text_probability=0.8,
            vision_probability=0.7,
            matched_keywords=["bet365", "jackpot"],
        )
        assert "bet365" in result.matched_keywords

    def test_detected_objects_propagated(self, engine):
        result = engine.fuse(
            text_probability=0.8,
            vision_probability=0.7,
            detected_objects=["1xbet", "betting_slip"],
        )
        assert "1xbet" in result.detected_objects

    def test_reasons_not_empty_for_betting(self, engine):
        result = engine.fuse(
            text_probability=0.9,
            vision_probability=0.9,
            matched_keywords=["casino"],
        )
        assert len(result.reasons) > 0

    # ── to_dict ───────────────────────────────────────────────────────

    def test_to_dict_contains_all_fields(self, engine):
        result = engine.fuse(text_probability=0.5, vision_probability=0.5)
        d = result.to_dict()
        expected_keys = {
            "classification", "confidence", "text_probability",
            "vision_probability", "matched_keywords", "detected_objects", "reasons"
        }
        assert expected_keys.issubset(d.keys())

    # ── Custom thresholds ─────────────────────────────────────────────

    def test_custom_thresholds(self):
        engine = FusionEngine(betting_threshold=0.5, suspicious_threshold=0.2)
        result = engine.fuse(text_probability=0.6, vision_probability=0.6)
        # 0.6*0.6 + 0.6*0.4 = 0.36 + 0.24 = 0.60 > 0.50 → BETTING
        assert result.classification == "BETTING"
