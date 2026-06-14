"""
database/models.py
------------------
SQLAlchemy ORM model for storing detection results.

Table: detection_results
  id             INTEGER  PRIMARY KEY AUTOINCREMENT
  image_name     TEXT     filename of the submitted image
  timestamp      DATETIME when the analysis was performed (UTC)
  extracted_text TEXT     full OCR text extracted from the image
  prediction     TEXT     "BETTING" | "SUSPICIOUS" | "SAFE"
  confidence     REAL     final fusion score (0.0 – 1.0)
  text_prob      REAL     text classifier probability
  vision_prob    REAL     YOLO vision probability
  matched_keywords TEXT   JSON-encoded list of matched keywords
  detected_objects TEXT   JSON-encoded list of detected YOLO objects
  reasons        TEXT     JSON-encoded list of explanation strings
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Float, Integer, Text

from database.db import Base


class DetectionResult(Base):
    """Persists a single image analysis result."""

    __tablename__ = "detection_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    image_name = Column(Text, nullable=False)
    timestamp = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    extracted_text = Column(Text, default="")
    prediction = Column(Text, nullable=False)           # "BETTING" | "SUSPICIOUS" | "SAFE"
    confidence = Column(Float, nullable=False)
    text_prob = Column(Float, default=0.0)
    vision_prob = Column(Float, default=0.0)
    # Store JSON-encoded lists as TEXT
    matched_keywords = Column(Text, default="[]")
    detected_objects = Column(Text, default="[]")
    reasons = Column(Text, default="[]")

    # ------------------------------------------------------------------
    # Convenience properties
    # ------------------------------------------------------------------

    @property
    def matched_keywords_list(self) -> list[str]:
        return json.loads(self.matched_keywords or "[]")

    @matched_keywords_list.setter
    def matched_keywords_list(self, value: list[str]) -> None:
        self.matched_keywords = json.dumps(value)

    @property
    def detected_objects_list(self) -> list[str]:
        return json.loads(self.detected_objects or "[]")

    @detected_objects_list.setter
    def detected_objects_list(self, value: list[str]) -> None:
        self.detected_objects = json.dumps(value)

    @property
    def reasons_list(self) -> list[str]:
        return json.loads(self.reasons or "[]")

    @reasons_list.setter
    def reasons_list(self, value: list[str]) -> None:
        self.reasons = json.dumps(value)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "image_name": self.image_name,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "extracted_text": self.extracted_text,
            "prediction": self.prediction,
            "confidence": self.confidence,
            "text_prob": self.text_prob,
            "vision_prob": self.vision_prob,
            "matched_keywords": self.matched_keywords_list,
            "detected_objects": self.detected_objects_list,
            "reasons": self.reasons_list,
        }

    def __repr__(self) -> str:
        return (
            f"<DetectionResult id={self.id} image={self.image_name!r} "
            f"prediction={self.prediction!r} confidence={self.confidence:.2f}>"
        )
