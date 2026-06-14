"""
ocr/extractor.py
----------------
PaddleOCR-based text extraction module.

Provides a singleton OCRExtractor that:
  - Initialises PaddleOCR once and caches the instance
  - Handles rotated/skewed text via angle classification
  - Returns extracted text, per-word confidence, and bounding boxes
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import TYPE_CHECKING

import numpy as np
from loguru import logger
from PIL import Image

if TYPE_CHECKING:
    pass

# ---------------------------------------------------------------------------
# Module-level singleton so PaddleOCR is loaded only once per process
# ---------------------------------------------------------------------------
_ocr_instance = None


def _get_ocr():
    """Lazily initialise PaddleOCR and return the singleton."""
    global _ocr_instance  # noqa: PLW0603
    if _ocr_instance is None:
        try:
            import os
            os.environ["PADDLE_PDX_DISABLE_MODEL_SOURCE_CHECK"] = "True"
            from paddleocr import PaddleOCR  # type: ignore[import-untyped]

            logger.info("Initialising PaddleOCR (GitHub source, PP-OCRv5)…")
            _ocr_instance = PaddleOCR(
                lang="en",
                use_textline_orientation=False,  # faster; set True for rotated text
                use_doc_orientation_classify=False,
                use_doc_unwarping=False,
                device="cpu",
                text_det_limit_side_len=960,
                ocr_version="PP-OCRv4",
                enable_mkldnn=False,
            )
            logger.info("PaddleOCR ready.")
        except ImportError as exc:
            raise RuntimeError(
                "PaddleOCR is not installed. "
                "Run: pip install -e PaddleOCR/ from the project root."
            ) from exc
    return _ocr_instance


# ---------------------------------------------------------------------------
# Helper types
# ---------------------------------------------------------------------------
class WordResult:
    """Represents a single detected word with its bounding box and confidence."""

    def __init__(self, text: str, confidence: float, bbox: list[list[float]]):
        self.text = text
        self.confidence = confidence
        self.bbox = bbox  # [[x1,y1],[x2,y2],[x3,y3],[x4,y4]]

    def to_dict(self) -> dict:
        return {
            "text": self.text,
            "confidence": round(self.confidence, 4),
            "bbox": self.bbox,
        }


class OCRResult:
    """Aggregated result for an entire image."""

    def __init__(self, words: list[WordResult]):
        self.words = words

    @property
    def extracted_text(self) -> str:
        """All detected words joined into a single string."""
        return " ".join(w.text for w in self.words)

    @property
    def word_count(self) -> int:
        """Number of detected words."""
        return len(self.words)

    @property
    def confidence(self) -> float:
        """Mean confidence across all detected words (0.0 if no words)."""
        if not self.words:
            return 0.0
        return round(sum(w.confidence for w in self.words) / len(self.words), 4)

    def to_dict(self) -> dict:
        return {
            "extracted_text": self.extracted_text,
            "confidence": self.confidence,
            "word_count": len(self.words),
            "words": [w.to_dict() for w in self.words],
        }


# ---------------------------------------------------------------------------
# Main extractor class
# ---------------------------------------------------------------------------
class OCRExtractor:
    """
    Wraps PaddleOCR to provide a clean interface for the betting detector.

    Usage::

        extractor = OCRExtractor()
        result = extractor.extract(image_path="path/to/image.jpg")
        print(result.extracted_text)
        print(result.confidence)
    """

    def __init__(self):
        # Trigger lazy load at instantiation time so startup is explicit.
        self._ocr = _get_ocr()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract(self, image_path: str | Path | None = None, image_bytes: bytes | None = None) -> OCRResult:
        """
        Run OCR on an image supplied either as a file path or raw bytes.

        Parameters
        ----------
        image_path : str | Path | None
            Path to an image file on disk.
        image_bytes : bytes | None
            Raw image bytes (e.g. from an HTTP upload).

        Returns
        -------
        OCRResult
            Contains ``extracted_text``, mean ``confidence``, and per-word data.

        Raises
        ------
        ValueError
            If neither ``image_path`` nor ``image_bytes`` is provided.
        """
        if image_path is None and image_bytes is None:
            raise ValueError("Provide either `image_path` or `image_bytes`.")

        img_array = self._load_image(image_path, image_bytes)

        try:
            results = self._ocr.predict(img_array)
        except Exception as exc:
            logger.error(f"PaddleOCR inference failed: {exc}")
            return OCRResult(words=[])

        return self._parse_results(results)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _load_image(image_path, image_bytes) -> np.ndarray:
        """Convert the input to a BGR numpy array for PaddleOCR."""
        if image_bytes is not None:
            pil_img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        else:
            pil_img = Image.open(image_path).convert("RGB")

        return np.array(pil_img)

    @staticmethod
    def _parse_results(results) -> OCRResult:
        """
        Parse PaddleOCR GitHub v3 pipeline output.

        Each element in ``results`` is a dict-like object with keys:
          - ``rec_texts``  : list[str]   — recognised text per box
          - ``rec_scores`` : list[float] — confidence per box  
          - ``dt_polys``   : list        — bounding polygons (4 points each)
        """
        words: list[WordResult] = []

        if not results:
            return OCRResult(words=[])

        for page_result in results:
            if not page_result:
                continue

            try:
                texts  = page_result["rec_texts"]  or []
                scores = page_result["rec_scores"] or []
                polys  = page_result["dt_polys"]   or []
            except (KeyError, TypeError) as exc:
                logger.warning(f"Could not parse OCR result: {exc}")
                continue

            for text, score, poly in zip(texts, scores, polys):
                if text and text.strip():
                    words.append(WordResult(
                        text=text,
                        confidence=float(score),
                        bbox=poly.tolist() if hasattr(poly, "tolist") else list(poly),
                    ))

        return OCRResult(words=words)
