# ═══════════════════════════════════════════════════════════════
# CYBERSURAKSHAA — All-in-One Detection Suite
#
# CPU-only image. Four ML stacks share one process (PaddleOCR, YOLO,
# EfficientNet-B4 + MTCNN, XGBoost/XLM-RoBERTa), so expect ~4-5 GB built and a
# long first build while the wheels download.
#
#   docker compose up --build          # recommended — see docker-compose.yml
#   docker build -t cybersurakshaa .   # image only
# ═══════════════════════════════════════════════════════════════

FROM python:3.11-slim

# ── System libraries ─────────────────────────────────────────
# libgl1 + libglib2.0-0 : OpenCV (requirements pins opencv-python, not the
#                         headless build, so it links against libGL)
# libgomp1              : OpenMP runtime used by PaddlePaddle, XGBoost, torch
# curl                  : HEALTHCHECK below
#
# Note this is `libgl1`, not the `libgl1-mesa-glx` used by the older
# betting-detector Dockerfile — that package no longer exists on Debian
# bookworm, which is what python:3.11-slim is built on.
# libzbar0               : pyzbar (QR decoding for the QR/UPI scanner)
RUN apt-get update && apt-get install -y --no-install-recommends \
        libgl1 \
        libglib2.0-0 \
        libgomp1 \
        libzbar0 \
        curl \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# ── PyTorch (CPU build) ──────────────────────────────────────
# Installed first, from the CPU index. The default PyPI wheels bundle the CUDA
# runtime — about 2.5 GB of libraries that cannot be used in a CPU container.
# Because this satisfies the `torch>=2.0.0` line below, the requirements
# install leaves it alone.
#
# The cache mount matters here and below: these downloads are multi-gigabyte,
# and a build interrupted partway through otherwise discards everything and
# starts the downloads again from zero. The cache lives in the builder, not in
# an image layer, so it costs nothing in the final image.
#
# Pinned to the versions requirements.txt declares. Unpinned, this step
# installed whatever CPU build was current and the requirements pass then
# replaced it — pulling the CUDA wheel back in and undoing the point of the
# step. The two must agree.
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --upgrade pip && \
    pip install --index-url https://download.pytorch.org/whl/cpu \
        torch==2.13.0 torchvision==0.28.0

# ── Application dependencies ─────────────────────────────────
COPY requirements.txt .
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install -r requirements.txt

# ── Make sure the contrib build of OpenCV is the one that wins ──
# opencv-python and opencv-contrib-python both install a module called `cv2`,
# and paddleocr pulls the plain build in transitively. Whichever pip writes
# last is the one that gets imported — a coin flip decided by resolution
# order, not by us.
#
# It matters because services/qr_analysis.py calls
# cv2.wechat_qrcode_WeChatQRCode(), which exists only in contrib. When the
# plain build wins, that call raises AttributeError, the guard around it
# swallows the error, and QR codes with a logo in the middle — every real UPI
# payment sticker — silently stop decoding. Nothing crashes; the scanner just
# quietly gets worse.
#
# So: remove the plain builds, reinstall contrib last, and assert the symbol
# is actually there. The assertion is the point — without it this whole step
# could no-op and the build would still be green.
RUN --mount=type=cache,target=/root/.cache/pip \
    pip uninstall -y opencv-python opencv-python-headless 2>/dev/null || true; \
    pip install --no-deps --force-reinstall opencv-contrib-python==4.10.0.84 && \
    python -c "import cv2; cv2.wechat_qrcode_WeChatQRCode; print('OpenCV contrib active:', cv2.__version__)"

# spaCy's English model is a separate download, not a requirements entry.
# 'fake customer carer/detector.py' needs it for brand NER and degrades to
# keyword-only matching without it. The trailing import is the real gate:
# without it, a run where every attempt failed would still produce a green
# build and an image that silently falls back to keyword-only detection.
#
# Installed from the release wheel URL rather than via `python -m spacy
# download`. That command first fetches a compatibility table from
# raw.githubusercontent.com, and that host is the part that fails: three
# consecutive builds here died on
#
#   SSLError: ... raw.githubusercontent.com ... UNEXPECTED_EOF_WHILE_READING
#
# while github.com itself was reachable throughout. Naming the wheel skips the
# lookup entirely — one fewer host that has to be up for the image to build.
#
# The version is pinned to match spacy==3.8.15 in requirements.txt. If you
# upgrade spacy, upgrade this URL in the same commit or the model will be
# rejected as incompatible at import.
ARG SPACY_MODEL_URL=https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl
RUN --mount=type=cache,target=/root/.cache/pip \
    for i in 1 2 3; do \
        pip install --no-deps "$SPACY_MODEL_URL" && break; \
        echo "spaCy model install failed (attempt $i of 3); retrying..."; \
        sleep 15; \
    done; \
    python -c "import en_core_web_sm"

# ── Application source ───────────────────────────────────────
COPY . .

# Data directory for the two SQLite databases and saved scan media. Mounted as
# volumes in docker-compose.yml — anything written elsewhere in /app is part of
# the image layer and disappears on redeploy.
# The model-cache directories are created here, before the volumes are mounted
# over them, and are owned by appuser. Docker creates a missing mount point as
# root, and the app does not run as root — so with these absent, the first
# download into either cache failed with:
#
#   [Error] Error loading Engine B: PermissionError at
#   /home/appuser/.cache/huggingface/hub ... Check cache directory permissions
#
# which the investment detector reports as engine_b_online=false rather than as
# an error. PaddleOCR fetches into ~/.paddlex and would fail the same way on
# the first customer-care scan.
# UID 1000, not an arbitrary high number: Hugging Face Spaces runs containers
# as uid 1000 and several managed platforms assume the same. A mismatch shows
# up as a permission error on the first model download, which reads like a
# broken detector rather than a filesystem problem.
#
# The writable directories are also group-writable so the image still works on
# a host that overrides the user entirely.
RUN useradd --create-home --uid 1000 appuser && \
    mkdir -p /app/data /app/static/uploads/scans \
             /home/appuser/.cache/huggingface \
             /home/appuser/.paddlex \
             /home/appuser/.config/Ultralytics && \
    chown -R appuser:appuser /app /home/appuser && \
    chmod -R g+rwX /app/data /app/static/uploads /home/appuser
USER appuser
ENV HOME=/home/appuser \
    XDG_CACHE_HOME=/home/appuser/.cache

ENV DB_PATH=/app/data/cybersurakshaa.db \
    SHIELD_DB_PATH=/app/data/shield.db \
    FLASK_ENV=production \
    PORT=5000 \
    GUNICORN_TIMEOUT=120

EXPOSE 5000

# start-period is generous: the app boots quickly, but the first request to a
# detector pulls a model into memory and can take a minute.
HEALTHCHECK --interval=30s --timeout=10s --start-period=90s --retries=3 \
    CMD curl -fsS http://localhost:5000/auth/login || exit 1

# One worker: each worker would load its own copy of every model, several GB
# apiece. See docker-compose.yml before raising it.
#
# The timeout is a variable because models load lazily on first use and a cold
# load can far exceed a normal request. The default 120s killed the worker
# partway through Engine B's first download, and the caller saw a bare 500:
#   [CRITICAL] WORKER TIMEOUT (pid:3248)
CMD ["sh", "-c", "gunicorn app:app --bind 0.0.0.0:${PORT:-5000} --timeout ${GUNICORN_TIMEOUT:-120} --workers 1"]
