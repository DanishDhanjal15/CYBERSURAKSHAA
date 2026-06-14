"""
tests/test_detector.py
----------------------
Unit tests for the YOLO detector module.
"""

from __future__ import annotations

import io
from unittest.mock import MagicMock, patch

import pytest
from PIL import Image

from detector.yolo_detector import DetectedObject, YOLODetector, YOLOResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _make_image_bytes(width: int = 200, height: int = 200) -> bytes:
    img = Image.new("RGB", (width, height), color=(128, 128, 128))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
class TestDetectedObject:
    def test_to_dict(self):
        obj = DetectedObject(label="bet365", confidence=0.92, bbox=[0.1, 0.2, 0.5, 0.6])
        d = obj.to_dict()
        assert d["label"] == "bet365"
        assert d["confidence"] == 0.92
        assert len(d["bbox"]) == 4


class TestYOLOResult:
    def test_empty_result(self):
        result = YOLOResult()
        assert result.confidence == 0.0
        assert result.detected_objects == []

    def test_to_dict(self):
        obj = DetectedObject(label="casino_chips", confidence=0.75, bbox=[0.0, 0.0, 1.0, 1.0])
        result = YOLOResult(detected_objects=[obj], confidence=0.75, mode="custom")
        d = result.to_dict()
        assert d["confidence"] == 0.75
        assert "casino_chips" in d["object_labels"]


class TestYOLODetector:
    def test_requires_input(self):
        with patch.object(YOLODetector, "_load_model", return_value=None):
            detector = YOLODetector()
            detector._model = None
            detector._mode = "stub"
            with pytest.raises(ValueError):
                detector.detect()

    def test_stub_mode_returns_empty_detections(self):
        """Stub mode (no YOLO installed) should return empty detections."""
        with patch.object(YOLODetector, "_load_model", return_value=None):
            detector = YOLODetector()
            detector._model = None
            detector._mode = "stub"

        result = detector.detect(image_bytes=_make_image_bytes())
        assert result.mode == "stub"
        assert result.detected_objects == []
        assert result.confidence == 0.0
        assert result.annotated_image is not None  # still returns image bytes

    def test_annotated_image_is_png_bytes(self):
        """Stub mode should still return valid PNG bytes."""
        with patch.object(YOLODetector, "_load_model", return_value=None):
            detector = YOLODetector()
            detector._model = None
            detector._mode = "stub"

        result = detector.detect(image_bytes=_make_image_bytes())
        # Verify it's a valid image
        img = Image.open(io.BytesIO(result.annotated_image))
        assert img.size == (200, 200)

    def test_yolo_detect_parses_boxes(self):
        """Mock YOLO model output should be parsed into DetectedObject list."""
        # Build mock box
        mock_box = MagicMock()
        mock_box.conf = [0.88]
        mock_box.cls = [0]   # index 0 → "1xbet" in CUSTOM_CLASSES
        mock_box.xyxy = [MagicMock()]
        mock_box.xyxy[0].tolist.return_value = [10.0, 10.0, 90.0, 90.0]

        mock_result = MagicMock()
        mock_result.boxes = [mock_box]

        mock_model = MagicMock()
        mock_model.predict.return_value = [mock_result]

        with patch.object(YOLODetector, "_load_model", return_value=None):
            detector = YOLODetector()
            detector._model = mock_model
            detector._mode = "custom"

        result = detector.detect(image_bytes=_make_image_bytes())
        assert len(result.detected_objects) == 1
        assert result.detected_objects[0].label == "1xbet"
        assert abs(result.detected_objects[0].confidence - 0.88) < 0.01
        assert result.confidence == pytest.approx(0.88, abs=0.01)
