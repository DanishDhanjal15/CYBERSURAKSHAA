"""
database/crud.py
----------------
CRUD helpers for the DetectionResult table.

All functions accept a SQLAlchemy Session so they are easily testable
and compatible with FastAPI's dependency injection.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone

from loguru import logger
from sqlalchemy.orm import Session

from database.models import DetectionResult


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------

def save_result(
    db: Session,
    *,
    image_name: str,
    extracted_text: str,
    prediction: str,
    confidence: float,
    text_prob: float = 0.0,
    vision_prob: float = 0.0,
    matched_keywords: list[str] | None = None,
    detected_objects: list[str] | None = None,
    reasons: list[str] | None = None,
) -> DetectionResult:
    """
    Persist a detection result to the database.

    Returns
    -------
    DetectionResult
        The newly created ORM object (with ``id`` populated after commit).
    """
    record = DetectionResult(
        image_name=image_name,
        timestamp=datetime.now(timezone.utc),
        extracted_text=extracted_text,
        prediction=prediction,
        confidence=confidence,
        text_prob=text_prob,
        vision_prob=vision_prob,
        matched_keywords=json.dumps(matched_keywords or []),
        detected_objects=json.dumps(detected_objects or []),
        reasons=json.dumps(reasons or []),
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    logger.info(f"Saved result id={record.id} prediction={record.prediction}")
    return record


# ---------------------------------------------------------------------------
# Read
# ---------------------------------------------------------------------------

def get_result(db: Session, result_id: int) -> DetectionResult | None:
    """Fetch a single result by primary key."""
    return db.get(DetectionResult, result_id)


def get_all_results(
    db: Session,
    *,
    skip: int = 0,
    limit: int = 200,
    prediction_filter: str | None = None,
) -> list[DetectionResult]:
    """
    Return all stored results, newest first.

    Parameters
    ----------
    skip : int
        Number of records to skip (for pagination).
    limit : int
        Maximum records to return.
    prediction_filter : str | None
        If provided, only return results matching this classification
        (e.g. ``"BETTING"``).
    """
    q = db.query(DetectionResult).order_by(DetectionResult.timestamp.desc())
    if prediction_filter:
        q = q.filter(DetectionResult.prediction == prediction_filter.upper())
    return q.offset(skip).limit(limit).all()


def count_results(db: Session) -> dict[str, int]:
    """Return a summary count by classification."""
    results = db.query(DetectionResult.prediction).all()
    counts: dict[str, int] = {"BETTING": 0, "SUSPICIOUS": 0, "SAFE": 0, "total": 0}
    for (pred,) in results:
        counts["total"] += 1
        if pred in counts:
            counts[pred] += 1
    return counts


# ---------------------------------------------------------------------------
# Delete
# ---------------------------------------------------------------------------

def delete_result(db: Session, result_id: int) -> bool:
    """Delete a result by ID. Returns True if deleted, False if not found."""
    record = db.get(DetectionResult, result_id)
    if record is None:
        return False
    db.delete(record)
    db.commit()
    return True


# ---------------------------------------------------------------------------
# Export helpers
# ---------------------------------------------------------------------------

def export_to_json(db: Session) -> str:
    """Return all results as a JSON string."""
    results = get_all_results(db, limit=10_000)
    data = [r.to_dict() for r in results]
    return json.dumps(data, indent=2, default=str)


def export_to_csv(db: Session) -> str:
    """Return all results as a CSV string."""
    results = get_all_results(db, limit=10_000)
    output = io.StringIO()
    fieldnames = [
        "id", "image_name", "timestamp", "prediction", "confidence",
        "text_prob", "vision_prob", "matched_keywords", "detected_objects",
        "reasons", "extracted_text",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for r in results:
        row = r.to_dict()
        # Flatten list fields to semicolon-separated strings for CSV
        row["matched_keywords"] = "; ".join(row["matched_keywords"])
        row["detected_objects"] = "; ".join(row["detected_objects"])
        row["reasons"] = "; ".join(row["reasons"])
        writer.writerow(row)
    return output.getvalue()
