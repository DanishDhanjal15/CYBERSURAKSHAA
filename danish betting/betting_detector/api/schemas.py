"""
api/schemas.py
--------------
Pydantic v2 request/response models for the FastAPI layer.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Detection response
# ---------------------------------------------------------------------------
class DetectionResponse(BaseModel):
    """Full response returned by POST /api/detect."""

    id: int | None = Field(None, description="Database record ID")
    image_name: str
    classification: Literal["BETTING", "SUSPICIOUS", "SAFE"]
    confidence: float = Field(..., ge=0.0, le=1.0, description="Final fusion score")
    text_probability: float = Field(..., ge=0.0, le=1.0)
    vision_probability: float = Field(..., ge=0.0, le=1.0)
    ocr_text: str = Field("", description="Full text extracted by OCR")
    matched_keywords: list[str] = Field(default_factory=list)
    detected_logos: list[str] = Field(default_factory=list)
    detected_objects: list[dict] = Field(default_factory=list, description="YOLO raw detections")
    reasons: list[str] = Field(default_factory=list)
    annotated_image: str | None = Field(None, description="Base64 encoded PNG bytes with YOLO bounding boxes")
    timestamp: datetime | None = None

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Historical result (slimmed-down for list views)
# ---------------------------------------------------------------------------
class ResultSummary(BaseModel):
    id: int
    image_name: str
    classification: str
    confidence: float
    timestamp: datetime | None = None

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Results list + stats
# ---------------------------------------------------------------------------
class ResultStats(BaseModel):
    total: int
    BETTING: int
    SUSPICIOUS: int
    SAFE: int


class ResultListResponse(BaseModel):
    results: list[ResultSummary]
    stats: ResultStats
    count: int


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------
class HealthResponse(BaseModel):
    status: str = "abc123"
    version: str = "1.0.0"
    components: dict[str, str] = Field(default_factory=dict)
