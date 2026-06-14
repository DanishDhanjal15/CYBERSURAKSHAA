"""
tests/test_classifier.py
------------------------
Unit tests for the text classifier module.
"""

from __future__ import annotations

import pickle
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from models.text_classifier import BETTING_KEYWORDS, TextClassifier, TextClassificationResult


# ---------------------------------------------------------------------------
# Tests for TextClassificationResult
# ---------------------------------------------------------------------------
class TestTextClassificationResult:
    def test_to_dict(self):
        result = TextClassificationResult(
            betting_probability=0.85,
            matched_keywords=["bet365", "odds"],
            method="tfidf",
        )
        d = result.to_dict()
        assert d["betting_probability"] == 0.85
        assert "bet365" in d["matched_keywords"]
        assert d["method"] == "tfidf"


# ---------------------------------------------------------------------------
# Tests for keyword matching
# ---------------------------------------------------------------------------
class TestKeywordMatching:
    def _make_clf(self) -> TextClassifier:
        """Instantiate classifier with no models loaded (keyword-only mode)."""
        with patch.object(TextClassifier, "_load_models", return_value=None):
            clf = TextClassifier()
            clf._tfidf_pipeline = None
            clf._bert_pipeline = None
        return clf


    def test_detects_betting_keyword(self):
        clf = self._make_clf()
        result = clf.classify("place your bet365 bonus bet today")
        assert result.betting_probability > 0
        assert any("bet365" in kw or "bet" in kw for kw in result.matched_keywords)

    def test_no_keywords_returns_zero(self):
        clf = self._make_clf()
        result = clf.classify("beautiful sunset at the beach")
        assert result.betting_probability == 0.0
        assert result.matched_keywords == []

    def test_empty_text_returns_zero(self):
        clf = self._make_clf()
        result = clf.classify("")
        assert result.betting_probability == 0.0

    def test_whitespace_only_text(self):
        clf = self._make_clf()
        result = clf.classify("   \n\t  ")
        assert result.betting_probability == 0.0

    def test_multiple_keywords_boost_probability(self):
        clf = self._make_clf()
        # Four distinct keywords
        result = clf.classify("casino jackpot gambling sportsbook bet")
        # More keywords should yield higher probability
        assert result.betting_probability >= 0.5

    def test_case_insensitive_matching(self):
        clf = self._make_clf()
        result = clf.classify("BET365 JACKPOT FREE SPINS")
        assert len(result.matched_keywords) > 0

    def test_keyword_deduplication(self):
        clf = self._make_clf()
        result = clf.classify("bet bet bet bet")
        # Should not return duplicate keywords
        assert len(result.matched_keywords) == len(set(result.matched_keywords))


# ---------------------------------------------------------------------------
# Tests for TF-IDF strategy
# ---------------------------------------------------------------------------
class TestTFIDFClassifier:
    def test_tfidf_strategy_used_when_model_present(self, tmp_path):
        """TF-IDF pipeline should be used when a model file exists."""
        from sklearn.pipeline import Pipeline
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        import numpy as np

        # Build a tiny real sklearn pipeline (can be pickled)
        pipeline = Pipeline([
            ("tfidf", TfidfVectorizer()),
            ("clf", LogisticRegression()),
        ])
        pipeline.fit(["bet casino", "nice photo"], [1, 0])

        model_path = tmp_path / "tfidf_classifier.pkl"
        with open(model_path, "wb") as f:
            pickle.dump(pipeline, f)

        with patch("models.text_classifier.TFIDF_MODEL_PATH", model_path):
            with patch.object(TextClassifier, "_load_bert", return_value=None):
                clf = TextClassifier()

        result = clf.classify("some betting text")
        assert result.method == "tfidf"
        assert 0.0 <= result.betting_probability <= 1.0

    def test_tfidf_fallback_on_error(self):
        """Should fall back to keyword scoring if TF-IDF inference fails."""
        mock_pipeline = MagicMock()
        mock_pipeline.predict_proba.side_effect = RuntimeError("Model error")

        with patch.object(TextClassifier, "_load_models", return_value=None):
            clf = TextClassifier()
            clf._tfidf_pipeline = mock_pipeline
            clf._bert_pipeline = None

        result = clf.classify("bet365 gambling casino")
        # Fell back to keyword scoring — method will be keyword
        assert result.method == "keyword"


# ---------------------------------------------------------------------------
# Tests for BERT strategy
# ---------------------------------------------------------------------------
class TestBERTClassifier:
    def test_bert_strategy_dictionary_output(self):
        """Should successfully parse a single dictionary response from BERT pipeline."""
        mock_pipeline = MagicMock()
        mock_pipeline.return_value = [{"label": "POSITIVE", "score": 0.8}]

        with patch.object(TextClassifier, "_load_models", return_value=None):
            clf = TextClassifier()
            clf._bert_pipeline = mock_pipeline
            clf._tfidf_pipeline = None

        result = clf.classify("hello world")
        assert result.method == "bert"
        # betting_prob = 0.8 * 0.7 + keyword_boost (0.0) = 0.56
        assert result.betting_probability == 0.56

    def test_bert_strategy_list_output(self):
        """Should successfully parse a list of dicts response from BERT pipeline."""
        mock_pipeline = MagicMock()
        mock_pipeline.return_value = [[{"label": "NEGATIVE", "score": 0.2}, {"label": "POSITIVE", "score": 0.8}]]

        with patch.object(TextClassifier, "_load_models", return_value=None):
            clf = TextClassifier()
            clf._bert_pipeline = mock_pipeline
            clf._tfidf_pipeline = None

        result = clf.classify("hello world")
        assert result.method == "bert"
        assert result.betting_probability == 0.56

    def test_bert_strategy_label_1_fallback(self):
        """Should successfully fall back to LABEL_1 if POSITIVE label is not present."""
        mock_pipeline = MagicMock()
        mock_pipeline.return_value = [{"label": "LABEL_1", "score": 0.9}]

        with patch.object(TextClassifier, "_load_models", return_value=None):
            clf = TextClassifier()
            clf._bert_pipeline = mock_pipeline
            clf._tfidf_pipeline = None

        result = clf.classify("hello world")
        assert result.method == "bert"
        assert result.betting_probability == 0.63


# ---------------------------------------------------------------------------
# Keyword list sanity checks
# ---------------------------------------------------------------------------
class TestKeywordList:
    def test_keyword_list_not_empty(self):
        assert len(BETTING_KEYWORDS) > 10

    def test_core_keywords_present(self):
        core = {"betting", "gambling", "casino", "odds", "jackpot", "1xbet", "bet365"}
        kw_lower = {k.lower() for k in BETTING_KEYWORDS}
        missing = core - kw_lower
        assert not missing, f"Missing keywords: {missing}"
