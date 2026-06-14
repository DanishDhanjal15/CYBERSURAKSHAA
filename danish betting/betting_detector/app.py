"""
app.py
------
Main entry point for the Betting Detector FastAPI application.

Run with:
    python app.py
    # or
    uvicorn app:app --host 0.0.0.0 --port 8000 --reload
"""

from __future__ import annotations

import sys
from contextlib import asynccontextmanager

import uvicorn
from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger

from api.routes import router as api_router
from database.db import init_db

# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------
logger.remove()
logger.add(
    sys.stdout,
    format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{line}</cyan> — <level>{message}</level>",
    level="INFO",
    colorize=True,
)
logger.add(
    "logs/betting_detector.log",
    rotation="10 MB",
    retention="14 days",
    level="DEBUG",
)


# ---------------------------------------------------------------------------
# Application lifespan (startup / shutdown)
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise resources on startup and clean up on shutdown."""
    logger.info("Starting Betting Detector API…")
    init_db()
    logger.info("Database ready.")

    # ── Pre-warm all ML models at startup ──────────────────────────────
    # This prevents the first /api/detect request from timing out while
    # PaddleOCR / YOLO download and load their weights (can take 60-120s).
    import asyncio, concurrent.futures

    def _warm_models():
        from api.routes import _get_ocr, _get_classifier, _get_detector
        logger.info("Pre-warming OCR extractor…")
        _get_ocr()
        logger.info("OCR extractor ready.")
        logger.info("Pre-warming text classifier…")
        _get_classifier()
        logger.info("Text classifier ready.")
        logger.info("Pre-warming YOLO detector…")
        _get_detector()
        logger.info("YOLO detector ready.")

    loop = asyncio.get_event_loop()
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    try:
        await loop.run_in_executor(executor, _warm_models)
    except Exception as exc:
        logger.warning(f"Model pre-warm failed (will retry on first request): {exc}")
    finally:
        executor.shutdown(wait=False)

    logger.info("🚀 All components ready — Betting Detector API is live.")
    yield
    logger.info("Shutting down Betting Detector API.")


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Betting Detector API",
    description=(
        "Detect betting and gambling content in Instagram post images "
        "using a hybrid OCR + Computer Vision pipeline."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# CORS — allow Streamlit dashboard and local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # Restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount all API routes under /api prefix
app.include_router(api_router, prefix="/api", tags=["Detection"])


# ---------------------------------------------------------------------------
# Root redirect
# ---------------------------------------------------------------------------
@app.get("/", include_in_schema=False)
def root():
    return {
        "message": "Betting Detector API",
        "docs": "/docs",
        "health": "/api/health",
    }


# ---------------------------------------------------------------------------
# Dev runner
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )
