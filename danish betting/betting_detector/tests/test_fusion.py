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

    # The four tests below asserted the old weighted-average formula
    # (0.6*text + 0.4*vision). FusionEngine._combine now uses a noisy-OR so
    # that a strong single signal is reachable — see the module docstring in
    # fusion/engine.py for why. They are restated against that contract:
    #
    #     t = text * 1.0,  v = vision * (0.4 / 0.6),  final = 1 - (1-t)(1-v)

    def test_boundary_betting_threshold(self, engine):
        # _classify uses >=, so a score of exactly 0.70 is BETTING. Drive the
        # score with the text signal alone, where final == text_probability.
        assert engine.fuse(text_probability=0.70, vision_probability=0.0).classification == "BETTING"
        assert engine.fuse(text_probability=0.699, vision_probability=0.0).classification == "SUSPICIOUS"

    def test_boundary_suspicious_threshold(self, engine):
        assert engine.fuse(text_probability=0.40, vision_probability=0.0).classification == "SUSPICIOUS"
        assert engine.fuse(text_probability=0.399, vision_probability=0.0).classification == "SAFE"

    # ── Score calculation ──────────────────────────────────────────────

    def test_text_signal_alone_reaches_full_score(self, engine):
        # Text carries the larger weight, so it is passed through unscaled: a
        # certain text detection must be able to reach 1.00 on its own.
        result = engine.fuse(text_probability=1.0, vision_probability=0.0)
        assert abs(result.final_score - 1.0) < 0.001

    def test_vision_signal_alone_clears_suspicious(self, engine):
        # Vision is scaled by 0.4/0.6, so a certain vision detection reaches
        # 0.667 — above SUSPICIOUS (0.40), which is the case image-only
        # betting creatives depend on.
        result = engine.fuse(text_probability=0.0, vision_probability=1.0)
        assert abs(result.final_score - 0.6667) < 0.001
        assert result.classification == "SUSPICIOUS"

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
        # noisy-OR: t=0.6, v=0.4 → 1 - 0.4*0.6 = 0.76 ≥ 0.50 → BETTING
        assert result.classification == "BETTING"
