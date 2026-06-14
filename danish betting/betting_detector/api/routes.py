"""
api/routes.py
-------------
FastAPI router with all endpoints:

  POST /api/detect          — analyse an uploaded image
  GET  /api/results         — list stored results with stats
  GET  /api/results/{id}    — single result detail
  DELETE /api/results/{id}  — delete a result
  GET  /api/export/json     — download all results as JSON
  GET  /api/export/csv      — download all results as CSV
  GET  /health              — health check
"""

from __future__ import annotations

import io
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.responses import Response, StreamingResponse
from loguru import logger
from sqlalchemy.orm import Session

from api.schemas import (
    DetectionResponse,
    HealthResponse,
    ResultListResponse,
    ResultStats,
    ResultSummary,
)
from database.crud import (
    count_results,
    delete_result,
    export_to_csv,
    export_to_json,
    get_all_results,
    get_result,
    save_result,
)
from database.db import get_db
from detector.yolo_detector import YOLODetector
from fusion.engine import FusionEngine
from models.text_classifier import TextClassifier
from ocr.extractor import OCRExtractor

router = APIRouter()

# ---------------------------------------------------------------------------
# Shared component instances (loaded once at module level)
# ---------------------------------------------------------------------------
_ocr_extractor: OCRExtractor | None = None
_text_classifier: TextClassifier | None = None
_yolo_detector: YOLODetector | None = None
_fusion_engine: FusionEngine = FusionEngine()


def _get_ocr() -> OCRExtractor:
    global _ocr_extractor  # noqa: PLW0603
    if _ocr_extractor is None:
        _ocr_extractor = OCRExtractor()
    return _ocr_extractor


def _get_classifier() -> TextClassifier:
    global _text_classifier  # noqa: PLW0603
    if _text_classifier is None:
        _text_classifier = TextClassifier()
    return _text_classifier


def _get_detector() -> YOLODetector:
    global _yolo_detector  # noqa: PLW0603
    if _yolo_detector is None:
        _yolo_detector = YOLODetector()
    return _yolo_detector


# ---------------------------------------------------------------------------
# POST /api/detect
# ---------------------------------------------------------------------------
@router.post("/detect", response_model=DetectionResponse, summary="Detect betting content in an image")
async def detect(
    image: UploadFile = File(..., description="Image file to analyse (.jpg, .png, .webp)"),
    db: Session = Depends(get_db),
) -> DetectionResponse:
    """
    Full pipeline: OCR → Text Classification → YOLO → Fusion → Store → Return.

    Accepts a multipart image upload and returns a full detection result
    including classification, confidence, extracted text, matched keywords,
    and detected visual objects.
    """
    # Validate file type
    if image.content_type and not image.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="Uploaded file must be an image.")

    image_bytes = await image.read()
    if len(image_bytes) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    logger.info(f"Processing image: {image.filename} ({len(image_bytes):,} bytes)")

    # 1. OCR
    ocr = _get_ocr()
    ocr_result = ocr.extract(image_bytes=image_bytes)
    logger.debug(f"OCR → {ocr_result.word_count} words, confidence={ocr_result.confidence:.2f}")

    # 2. Text classification
    clf = _get_classifier()
    text_result = clf.classify(ocr_result.extracted_text)
    logger.debug(f"Text → prob={text_result.betting_probability:.2f}, keywords={text_result.matched_keywords}")

    # 3. YOLO detection
    detector = _get_detector()
    yolo_result = detector.detect(image_bytes=image_bytes, ocr_words=ocr_result.words)
    logger.debug(f"YOLO → {len(yolo_result.detected_objects)} objects, conf={yolo_result.confidence:.2f}")

    # 4. Fusion
    fusion_result = _fusion_engine.fuse(
        text_probability=text_result.betting_probability,
        vision_probability=yolo_result.confidence,
        matched_keywords=text_result.matched_keywords,
        detected_objects=[o.label for o in yolo_result.detected_objects],
    )
    logger.info(f"Result: {fusion_result.classification} (score={fusion_result.final_score:.3f})")

    # 5. Persist to DB
    record = save_result(
        db,
        image_name=image.filename or "unknown",
        extracted_text=ocr_result.extracted_text,
        prediction=fusion_result.classification,
        confidence=fusion_result.final_score,
        text_prob=text_result.betting_probability,
        vision_prob=yolo_result.confidence,
        matched_keywords=text_result.matched_keywords,
        detected_objects=[o.label for o in yolo_result.detected_objects],
        reasons=fusion_result.reasons,
    )

    import base64
    annotated_base64 = None
    if yolo_result.annotated_image:
        annotated_base64 = base64.b64encode(yolo_result.annotated_image).decode('utf-8')

    return DetectionResponse(
        id=record.id,
        image_name=image.filename or "unknown",
        classification=fusion_result.classification,
        confidence=fusion_result.final_score,
        text_probability=text_result.betting_probability,
        vision_probability=yolo_result.confidence,
        ocr_text=ocr_result.extracted_text,
        matched_keywords=text_result.matched_keywords,
        detected_logos=[o.label for o in yolo_result.detected_objects],
        detected_objects=[o.to_dict() for o in yolo_result.detected_objects],
        reasons=fusion_result.reasons,
        annotated_image=annotated_base64,
        timestamp=datetime.now(timezone.utc),
    )


# ---------------------------------------------------------------------------
# GET /api/results
# ---------------------------------------------------------------------------
@router.get("/results", response_model=ResultListResponse, summary="List all detection results")
def list_results(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    prediction: str | None = Query(None, description="Filter by prediction: BETTING|SUSPICIOUS|SAFE"),
    db: Session = Depends(get_db),
) -> ResultListResponse:
    """Return stored detection results with pagination and optional prediction filter."""
    records = get_all_results(db, skip=skip, limit=limit, prediction_filter=prediction)
    stats = count_results(db)

    return ResultListResponse(
        results=[
            ResultSummary(
                id=r.id,
                image_name=r.image_name,
                classification=r.prediction,
                confidence=r.confidence,
                timestamp=r.timestamp,
            )
            for r in records
        ],
        stats=ResultStats(**stats),
        count=len(records),
    )


# ---------------------------------------------------------------------------
# GET /api/results/{id}
# ---------------------------------------------------------------------------
@router.get("/results/{result_id}", response_model=DetectionResponse, summary="Get a single result")
def get_single_result(result_id: int, db: Session = Depends(get_db)) -> DetectionResponse:
    record = get_result(db, result_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Result {result_id} not found.")
    return DetectionResponse(
        id=record.id,
        image_name=record.image_name,
        classification=record.prediction,
        confidence=record.confidence,
        text_probability=record.text_prob,
        vision_probability=record.vision_prob,
        ocr_text=record.extracted_text,
        matched_keywords=record.matched_keywords_list,
        detected_logos=record.detected_objects_list,
        detected_objects=[],
        reasons=record.reasons_list,
        timestamp=record.timestamp,
    )


# ---------------------------------------------------------------------------
# DELETE /api/results/{id}
# ---------------------------------------------------------------------------
@router.delete("/results/{result_id}", summary="Delete a result")
def remove_result(result_id: int, db: Session = Depends(get_db)) -> dict:
    if not delete_result(db, result_id):
        raise HTTPException(status_code=404, detail=f"Result {result_id} not found.")
    return {"deleted": result_id}


# ---------------------------------------------------------------------------
# GET /api/export/json
# ---------------------------------------------------------------------------
@router.get("/export/json", summary="Export all results as JSON")
def export_json(db: Session = Depends(get_db)) -> Response:
    json_str = export_to_json(db)
    return Response(
        content=json_str,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=betting_results.json"},
    )


# ---------------------------------------------------------------------------
# GET /api/export/csv
# ---------------------------------------------------------------------------
@router.get("/export/csv", summary="Export all results as CSV")
def export_csv(db: Session = Depends(get_db)) -> Response:
    csv_str = export_to_csv(db)
    return Response(
        content=csv_str,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=betting_results.csv"},
    )


# ---------------------------------------------------------------------------
# GET /health
# ---------------------------------------------------------------------------
@router.get("/health", response_model=HealthResponse, summary="Health check")
def health_check() -> HealthResponse:
    components: dict[str, str] = {}

    # Check OCR
    try:
        import paddleocr  # noqa: F401
        components["paddleocr"] = "available"
    except ImportError:
        components["paddleocr"] = "not installed"

    # Check YOLO
    try:
        import ultralytics  # noqa: F401
        components["yolo"] = "available"
    except ImportError:
        components["yolo"] = "not installed"

    # Check BERT
    try:
        import transformers  # noqa: F401
        components["bert"] = "available"
    except ImportError:
        components["bert"] = "not installed"

    return HealthResponse(status="ok", components=components)
