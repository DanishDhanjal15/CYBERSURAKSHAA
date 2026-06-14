"""
tests/test_ocr.py
-----------------
Unit tests for the OCR extractor module.
"""

from __future__ import annotations

import io
from unittest.mock import MagicMock, patch

import numpy as np
import pytest
from PIL import Image

from ocr.extractor import OCRExtractor, OCRResult, WordResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _make_image_bytes(width: int = 100, height: int = 50) -> bytes:
    """Create a minimal PNG image as bytes."""
    img = Image.new("RGB", (width, height), color=(255, 255, 255))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _fake_predict_result(words: list[tuple[str, float]]):
    """Simulate PaddleOCR predict() output format."""
    texts = [w[0] for w in words]
    scores = [w[1] for w in words]
    polys = [np.array([[0, 0], [100, 0], [100, 20], [0, 20]]) for _ in words]
    return [{"rec_texts": texts, "rec_scores": scores, "dt_polys": polys}]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
class TestWordResult:
    def test_to_dict(self):
        word = WordResult(text="bet365", confidence=0.95, bbox=[[0, 0], [50, 20]])
        d = word.to_dict()
        assert d["text"] == "bet365"
        assert d["confidence"] == 0.95
        assert "bbox" in d


class TestOCRResult:
    def test_extracted_text_joins_words(self):
        words = [
            WordResult("bet365", 0.9, []),
            WordResult("bonus", 0.8, []),
        ]
        result = OCRResult(words=words)
        assert result.extracted_text == "bet365 bonus"

    def test_confidence_mean(self):
        words = [
            WordResult("bet", 0.8, []),
            WordResult("now", 0.6, []),
        ]
        result = OCRResult(words=words)
        assert abs(result.confidence - 0.7) < 0.01

    def test_empty_result(self):
        result = OCRResult(words=[])
        assert result.extracted_text == ""
        assert result.confidence == 0.0

    def test_to_dict_keys(self):
        result = OCRResult(words=[WordResult("test", 0.9, [])])
        d = result.to_dict()
        assert all(k in d for k in ["extracted_text", "confidence", "word_count", "words"])


class TestOCRExtractor:
    def test_requires_image_input(self):
        """Should raise ValueError when no input is provided."""
        with patch("ocr.extractor._get_ocr") as mock_get:
            mock_get.return_value = MagicMock()
            extractor = OCRExtractor()
            with pytest.raises(ValueError, match="image_path.*image_bytes"):
                extractor.extract()

    def test_extract_from_bytes(self):
        """Should call PaddleOCR and parse results from image bytes."""
        fake_ocr = MagicMock()
        fake_ocr.predict.return_value = _fake_predict_result([("1xbet", 0.92), ("odds", 0.85)])

        with patch("ocr.extractor._get_ocr", return_value=fake_ocr):
            extractor = OCRExtractor()
            result = extractor.extract(image_bytes=_make_image_bytes())

        assert result.extracted_text == "1xbet odds"
        assert result.word_count == 2
        assert result.confidence > 0

    def test_extract_empty_response(self):
        """Should return empty OCRResult when PaddleOCR returns nothing."""
        fake_ocr = MagicMock()
        fake_ocr.predict.return_value = []

        with patch("ocr.extractor._get_ocr", return_value=fake_ocr):
            extractor = OCRExtractor()
            result = extractor.extract(image_bytes=_make_image_bytes())

        assert result.extracted_text == ""
        assert result.confidence == 0.0

    def test_paddle_inference_error_returns_empty(self):
        """Should return empty result gracefully when PaddleOCR raises an exception."""
        fake_ocr = MagicMock()
        fake_ocr.predict.side_effect = RuntimeError("GPU OOM")

        with patch("ocr.extractor._get_ocr", return_value=fake_ocr):
            extractor = OCRExtractor()
            result = extractor.extract(image_bytes=_make_image_bytes())

        assert result.extracted_text == ""
