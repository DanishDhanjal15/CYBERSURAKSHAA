# ─────────────────────────────────────────────────────────────────────────────
# Betting Detector — Dockerfile
# ─────────────────────────────────────────────────────────────────────────────
# Multi-stage build:
#   Stage 1 (base)     — Python + system deps
#   Stage 2 (api)      — FastAPI application
#   Stage 3 (dashboard)— Streamlit dashboard (uses same base)
#
# GPU support: replace base image with nvidia/cuda:12.1.0-runtime-ubuntu22.04
# and change paddlepaddle → paddlepaddle-gpu in requirements.txt
# ─────────────────────────────────────────────────────────────────────────────

FROM python:3.11-slim AS base

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgl1-mesa-glx \
    libglib2.0-0 \
    libgomp1 \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy all source code
COPY . .

# Create necessary directories
RUN mkdir -p logs detector/saved models/saved

# ─────────────────────────────────────────────────────────────────────────────
# API stage
# ─────────────────────────────────────────────────────────────────────────────
FROM base AS api

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]

# ─────────────────────────────────────────────────────────────────────────────
# Dashboard stage
# ─────────────────────────────────────────────────────────────────────────────
FROM base AS dashboard

EXPOSE 8501

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8501/_stcore/health || exit 1

CMD ["streamlit", "run", "dashboard/app.py", \
     "--server.port=8501", \
     "--server.address=0.0.0.0", \
     "--server.headless=true", \
     "--browser.gatherUsageStats=false"]
