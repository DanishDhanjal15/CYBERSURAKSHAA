"""
tests/test_api.py
-----------------
Integration tests for the FastAPI endpoints.

Uses httpx.AsyncClient with the FastAPI test client (no running server needed).
"""

from __future__ import annotations

import io
from unittest.mock import MagicMock, patch

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from httpx import AsyncClient
from PIL import Image

# Patch heavy ML dependencies before importing the app
import sys
sys.modules.setdefault("paddleocr", MagicMock())
sys.modules.setdefault("paddlepaddle", MagicMock())
sys.modules.setdefault("ultralytics", MagicMock())

# Patch database URL to use a test database file so we don't touch/drop the dev db
import os
os.environ["DATABASE_URL"] = "sqlite:///./test_betting_detector.db"

from app import app  # noqa: E402
from database.db import Base, engine  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def setup_test_db():
    """Create fresh tables before each test and drop them after."""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client():
    """Synchronous TestClient."""
    return TestClient(app)


def _make_image_bytes() -> bytes:
    img = Image.new("RGB", (100, 100), color=(200, 200, 200))
    buf = io.BytesIO()
    img.save(buf, format="JPEG")
    return buf.getvalue()


def _mock_pipeline_result(classification="BETTING", confidence=0.85):
    """Build consistent mock return values for the full pipeline."""
    ocr_result = MagicMock()
    ocr_result.extracted_text = "bet365 bonus offer"
    ocr_result.word_count = 3
    ocr_result.confidence = 0.9

    text_result = MagicMock()
    text_result.betting_probability = 0.88
    text_result.matched_keywords = ["bet365"]

    yolo_result = MagicMock()
    yolo_result.detected_objects = []
    yolo_result.confidence = 0.0

    fusion_result = MagicMock()
    fusion_result.classification = classification
    fusion_result.final_score = confidence
    fusion_result.text_probability = 0.88
    fusion_result.vision_probability = 0.0
    fusion_result.matched_keywords = ["bet365"]
    fusion_result.reasons = ["High text betting probability (88%)"]

    return ocr_result, text_result, yolo_result, fusion_result


# ---------------------------------------------------------------------------
# Health endpoint
# ---------------------------------------------------------------------------
class TestHealthEndpoint:
    def test_health_returns_ok(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"

    def test_health_lists_components(self, client):
        resp = client.get("/api/health")
        data = resp.json()
        assert "components" in data


# ---------------------------------------------------------------------------
# Detect endpoint
# ---------------------------------------------------------------------------
class TestDetectEndpoint:
    def test_detect_requires_image(self, client):
        """POST /api/detect without a file should return 422."""
        resp = client.post("/api/detect")
        assert resp.status_code == 422

    def test_detect_valid_image(self, client):
        """POST /api/detect with a valid image should return classification."""
        ocr_r, text_r, yolo_r, fusion_r = _mock_pipeline_result()

        with (
            patch("api.routes._get_ocr") as mock_ocr,
            patch("api.routes._get_classifier") as mock_clf,
            patch("api.routes._get_detector") as mock_det,
            patch("api.routes._fusion_engine") as mock_fusion,
        ):
            mock_ocr.return_value.extract.return_value = ocr_r
            mock_clf.return_value.classify.return_value = text_r
            mock_det.return_value.detect.return_value = yolo_r
            mock_fusion.fuse.return_value = fusion_r

            resp = client.post(
                "/api/detect",
                files={"image": ("test.jpg", _make_image_bytes(), "image/jpeg")},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["classification"] == "BETTING"
        assert 0.0 <= data["confidence"] <= 1.0
        assert "ocr_text" in data
        assert "matched_keywords" in data

    def test_detect_persists_result(self, client):
        """After detection, result should appear in GET /api/results."""
        ocr_r, text_r, yolo_r, fusion_r = _mock_pipeline_result()

        with (
            patch("api.routes._get_ocr") as mock_ocr,
            patch("api.routes._get_classifier") as mock_clf,
            patch("api.routes._get_detector") as mock_det,
            patch("api.routes._fusion_engine") as mock_fusion,
        ):
            mock_ocr.return_value.extract.return_value = ocr_r
            mock_clf.return_value.classify.return_value = text_r
            mock_det.return_value.detect.return_value = yolo_r
            mock_fusion.fuse.return_value = fusion_r

            client.post(
                "/api/detect",
                files={"image": ("test.jpg", _make_image_bytes(), "image/jpeg")},
            )

        results = client.get("/api/results").json()
        assert results["stats"]["total"] == 1


# ---------------------------------------------------------------------------
# Results endpoints
# ---------------------------------------------------------------------------
class TestResultsEndpoints:
    def test_results_empty_initially(self, client):
        resp = client.get("/api/results")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 0
        assert data["stats"]["total"] == 0

    def test_get_nonexistent_result_returns_404(self, client):
        resp = client.get("/api/results/9999")
        assert resp.status_code == 404

    def test_delete_nonexistent_result_returns_404(self, client):
        resp = client.delete("/api/results/9999")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Export endpoints
# ---------------------------------------------------------------------------
class TestExportEndpoints:
    def test_export_json_returns_json(self, client):
        resp = client.get("/api/export/json")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("application/json")

    def test_export_csv_returns_csv(self, client):
        resp = client.get("/api/export/csv")
        assert resp.status_code == 200
        assert "text/csv" in resp.headers["content-type"]
