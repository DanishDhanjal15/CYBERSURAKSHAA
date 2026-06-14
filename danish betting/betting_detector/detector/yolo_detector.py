"""
detector/yolo_detector.py
-------------------------
YOLOv8-based betting logo and visual pattern detector.

Strategy
--------
1. If a custom-trained model file exists at ``detector/saved/betting_yolo.pt``,
   it is loaded and used for inference.
2. Otherwise, a YOLOv8n (nano) pretrained on COCO is used.  Since COCO does
   not include betting logos, this mode performs a best-effort OCR-assisted
   logo text scan in addition to generic object detection (useful for
   detecting laptops/phones showing betting UIs etc.).

Custom model training: run ``train_yolo.py`` once you have labelled data
in the ``datasets/`` directory.
"""

from __future__ import annotations

import io
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
from loguru import logger
from PIL import Image, ImageDraw, ImageFont

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SAVED_MODEL_DIR = Path(__file__).parent / "saved"
CUSTOM_MODEL_PATH = SAVED_MODEL_DIR / "betting_yolo.pt"
DEFAULT_YOLO_MODEL = "yolov8n.pt"  # downloaded automatically by ultralytics

# ---------------------------------------------------------------------------
# Betting class labels for the custom model
# ---------------------------------------------------------------------------
CUSTOM_CLASSES: list[str] = [
    "1xbet",
    "bet365",
    "parimatch",
    "stake",
    "dafabet",
    "melbet",
    "betting_slip",
    "odds_table",
    "casino_chips",
    "roulette_table",
]

# ---------------------------------------------------------------------------
# Logo text patterns that PaddleOCR might miss but we can still text-match
# (used in stub mode when no custom model is available)
# ---------------------------------------------------------------------------
LOGO_TEXT_PATTERNS: list[str] = [
    "1xbet", "bet365", "parimatch", "stake.com", "dafabet",
    "melbet", "betway", "unibet", "william hill", "betfair",
]


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------
@dataclass
class DetectedObject:
    label: str
    confidence: float
    bbox: list[float]  # [x1, y1, x2, y2] normalised 0-1

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "confidence": round(self.confidence, 4),
            "bbox": [round(v, 4) for v in self.bbox],
        }


@dataclass
class YOLOResult:
    detected_objects: list[DetectedObject] = field(default_factory=list)
    confidence: float = 0.0          # max object confidence
    annotated_image: bytes | None = None   # PNG bytes of image with boxes drawn
    mode: str = "pretrained"         # "custom" | "pretrained" | "stub"

    def to_dict(self) -> dict:
        return {
            "detected_objects": [o.to_dict() for o in self.detected_objects],
            "confidence": round(self.confidence, 4),
            "mode": self.mode,
            "object_labels": [o.label for o in self.detected_objects],
        }


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------
class YOLODetector:
    """
    Wraps YOLOv8 for betting-related visual detection.

    If a custom model file is present at ``detector/saved/betting_yolo.pt``
    it is used; otherwise falls back to the pretrained COCO model.

    Usage::

        detector = YOLODetector()
        result = detector.detect(image_bytes=raw_bytes)
        print(result.detected_objects)
        print(result.confidence)
    """

    def __init__(self, confidence_threshold: float = 0.35) -> None:
        self.confidence_threshold = confidence_threshold
        self._model: Any = None
        self._mode: str = "stub"
        self._load_model()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect(
        self,
        image_path: str | Path | None = None,
        image_bytes: bytes | None = None,
        ocr_words: list[Any] | None = None,
    ) -> YOLOResult:
        """
        Run YOLO detection on an image.

        Parameters
        ----------
        image_path : str | Path | None
            Path to image file on disk.
        image_bytes : bytes | None
            Raw image bytes (e.g. from HTTP upload).
        ocr_words : list[Any] | None
            Pre-extracted words from PaddleOCR.

        Returns
        -------
        YOLOResult
        """
        if image_path is None and image_bytes is None:
            raise ValueError("Provide either `image_path` or `image_bytes`.")

        pil_image = self._load_image(image_path, image_bytes)

        if self._model is None:
            return self._stub_detect(pil_image, image_path, image_bytes, ocr_words)

        return self._yolo_detect(pil_image, image_path, image_bytes, ocr_words)

    # ------------------------------------------------------------------
    # Model loading
    # ------------------------------------------------------------------

    def _load_model(self) -> None:
        try:
            from ultralytics import YOLO  # type: ignore[import-untyped]

            if CUSTOM_MODEL_PATH.exists():
                logger.info(f"Loading custom betting YOLO model from {CUSTOM_MODEL_PATH}")
                self._model = YOLO(str(CUSTOM_MODEL_PATH))
                self._mode = "custom"
            else:
                logger.warning(
                    f"No custom model at {CUSTOM_MODEL_PATH}. "
                    f"Using pretrained YOLOv8n (COCO). "
                    "Run train_yolo.py to train a custom model."
                )
                self._model = YOLO(DEFAULT_YOLO_MODEL)
                self._mode = "pretrained"

            logger.info(f"YOLO detector ready (mode={self._mode}).")
        except ImportError:
            logger.warning(
                "ultralytics not installed — YOLO detector running in stub mode. "
                "Install with: pip install ultralytics"
            )
            self._mode = "stub"

    # ------------------------------------------------------------------
    # Detection strategies
    # ------------------------------------------------------------------

    def _yolo_detect(
        self,
        pil_image: Image.Image,
        image_path=None,
        image_bytes=None,
        ocr_words: list[Any] | None = None,
    ) -> YOLOResult:
        """Run actual YOLO inference."""
        img_array = np.array(pil_image)
        try:
            results = self._model.predict(
                img_array,
                conf=self.confidence_threshold,
                verbose=False,
                device="cpu",
            )
        except Exception as exc:
            logger.error(f"YOLO inference failed: {exc}")
            return YOLOResult(mode=self._mode)

        detected: list[DetectedObject] = []
        w, h = pil_image.size

        for result in results:
            for box in result.boxes:
                conf = float(box.conf[0])
                cls_id = int(box.cls[0])

                # Resolve label
                if self._mode == "custom":
                    label = CUSTOM_CLASSES[cls_id] if cls_id < len(CUSTOM_CLASSES) else f"class_{cls_id}"
                else:
                    label = self._model.names.get(cls_id, f"class_{cls_id}")

                # Normalise bbox
                x1, y1, x2, y2 = box.xyxy[0].tolist()
                detected.append(DetectedObject(
                    label=label,
                    confidence=conf,
                    bbox=[x1 / w, y1 / h, x2 / w, y2 / h],
                ))

        # Best-effort OCR-assisted logo text scan fallback for pretrained mode
        if self._mode == "pretrained":
            if ocr_words is None:
                try:
                    from ocr.extractor import OCRExtractor
                    ocr = OCRExtractor()
                    ocr_result = ocr.extract(image_path=image_path, image_bytes=image_bytes)
                    ocr_words = ocr_result.words
                except Exception as e:
                    logger.warning(f"OCR-assisted logo text scan failed: {e}")
                    ocr_words = []

            if ocr_words:
                for word in ocr_words:
                    word_text_clean = word.text.lower().strip()
                    for pattern in LOGO_TEXT_PATTERNS:
                        if pattern in word_text_clean:
                            # We found a matching logo name in the OCR text. Add it as a detected object!
                            poly = word.bbox
                            xs = [pt[0] for pt in poly]
                            ys = [pt[1] for pt in poly]
                            x1, y1, x2, y2 = min(xs), min(ys), max(xs), max(ys)
                            # Verify if it's already bounded to avoid duplicate detections
                            already_detected = False
                            for det in detected:
                                if det.label == pattern and abs(det.bbox[0] - x1/w) < 0.1 and abs(det.bbox[1] - y1/h) < 0.1:
                                    already_detected = True
                                    break
                            if not already_detected:
                                detected.append(DetectedObject(
                                    label=pattern,
                                    confidence=word.confidence,
                                    bbox=[x1 / w, y1 / h, x2 / w, y2 / h],
                                ))

        # Annotate image
        annotated_bytes = self._draw_boxes(pil_image, detected)
        max_conf = max((d.confidence for d in detected), default=0.0)

        return YOLOResult(
            detected_objects=detected,
            confidence=round(max_conf, 4),
            annotated_image=annotated_bytes,
            mode=self._mode,
        )

    def _stub_detect(
        self,
        pil_image: Image.Image,
        image_path=None,
        image_bytes=None,
        ocr_words: list[Any] | None = None,
    ) -> YOLOResult:
        """
        Stub detector — no YOLO model available.
        Runs OCR-assisted text-matching fallback to locate logo coordinates.
        """
        logger.debug("YOLO stub mode — performing OCR-assisted logo text scan.")
        detected: list[DetectedObject] = []
        w, h = pil_image.size

        if ocr_words is None:
            try:
                from ocr.extractor import OCRExtractor
                ocr = OCRExtractor()
                ocr_result = ocr.extract(image_path=image_path, image_bytes=image_bytes)
                ocr_words = ocr_result.words
            except Exception as e:
                logger.warning(f"OCR-assisted logo text scan failed in stub mode: {e}")
                ocr_words = []

        if ocr_words:
            for word in ocr_words:
                word_text_clean = word.text.lower().strip()
                for pattern in LOGO_TEXT_PATTERNS:
                    if pattern in word_text_clean:
                        poly = word.bbox
                        xs = [pt[0] for pt in poly]
                        ys = [pt[1] for pt in poly]
                        x1, y1, x2, y2 = min(xs), min(ys), max(xs), max(ys)
                        detected.append(DetectedObject(
                            label=pattern,
                            confidence=word.confidence,
                            bbox=[x1 / w, y1 / h, x2 / w, y2 / h],
                        ))

        annotated_bytes = self._draw_boxes(pil_image, detected)
        max_conf = max((d.confidence for d in detected), default=0.0)

        return YOLOResult(
            detected_objects=detected,
            confidence=round(max_conf, 4),
            annotated_image=annotated_bytes,
            mode="stub",
        )

    # ------------------------------------------------------------------
    # Image utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _load_image(image_path, image_bytes) -> Image.Image:
        if image_bytes is not None:
            return Image.open(io.BytesIO(image_bytes)).convert("RGB")
        return Image.open(image_path).convert("RGB")

    @staticmethod
    def _draw_boxes(image: Image.Image, objects: list[DetectedObject]) -> bytes:
        """Draw bounding boxes on the image and return as PNG bytes."""
        draw = ImageDraw.Draw(image)
        w, h = image.size
        colour_map = {
            "1xbet": "#FF4444", "bet365": "#00A550", "parimatch": "#FFD700",
            "stake": "#5A2D82", "dafabet": "#E60026", "melbet": "#FF6600",
        }

        for obj in objects:
            x1, y1, x2, y2 = obj.bbox
            # Denormalise
            x1, x2 = x1 * w, x2 * w
            y1, y2 = y1 * h, y2 * h
            colour = colour_map.get(obj.label, "#FF0000")
            draw.rectangle([x1, y1, x2, y2], outline=colour, width=3)
            label_text = f"{obj.label} {obj.confidence:.0%}"
            draw.text((x1 + 4, y1 + 4), label_text, fill=colour)

        return YOLODetector._image_to_bytes(image)

    @staticmethod
    def _image_to_bytes(image: Image.Image) -> bytes:
        buf = io.BytesIO()
        image.save(buf, format="PNG")
        return buf.getvalue()
