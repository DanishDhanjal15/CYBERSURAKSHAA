# 🎰 Betting Detector

A production-ready Python application that detects betting/gambling-related Instagram posts using a **hybrid OCR + Computer Vision pipeline**.

## Architecture

```
Instagram Image
    │
    ├── PaddleOCR ──────────► Text Extraction
    │                              │
    │                         NLP Classifier ──► Betting Text Score
    │
    ├── YOLOv8 ─────────────► Logo/Object Detection ──► Vision Score
    │
    └── Fusion Engine ──────► final = 0.6×text + 0.4×vision
                                   │
                              ┌────┴────┐
                           BETTING  SUSPICIOUS  SAFE
```

## Classification Rules

| Score | Label |
|-------|-------|
| > 0.70 | 🔴 **BETTING** |
| > 0.40 | 🟡 **SUSPICIOUS** |
| ≤ 0.40 | 🟢 **SAFE** |

---

## Quick Start

### 1. Install dependencies

```bash
cd betting_detector
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Train the text classifier (optional but recommended)

```bash
python train_text_classifier.py
# With your own labelled CSV:
python train_text_classifier.py --data datasets/text_labels.csv
```

### 3. Start the API

```bash
python app.py
# API will be at http://localhost:8000
# Swagger docs at http://localhost:8000/docs
```

### 4. Start the Streamlit Dashboard

```bash
streamlit run dashboard/app.py
# Dashboard will be at http://localhost:8501
```

---

## Docker

### Quick start with docker-compose

```bash
# Build and start both API + Dashboard
docker-compose up --build

# API:       http://localhost:8000
# Dashboard: http://localhost:8501
# API Docs:  http://localhost:8000/docs
```

### GPU support

1. Install [NVIDIA Container Toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/install-guide.html)
2. In `requirements.txt` replace `paddlepaddle` with `paddlepaddle-gpu`
3. In `Dockerfile` change the base image to `nvidia/cuda:12.1.0-runtime-ubuntu22.04`
4. In `docker-compose.yml` add to the `api` service:
   ```yaml
   deploy:
     resources:
       reservations:
         devices:
           - driver: nvidia
             count: 1
             capabilities: [gpu]
   ```
5. Rebuild: `docker-compose up --build`

---

## API Reference

### `POST /api/detect`

Upload an image to run the full detection pipeline.

```bash
curl -X POST http://localhost:8000/api/detect \
  -F "image=@/path/to/instagram_post.jpg"
```

**Response:**
```json
{
  "id": 1,
  "image_name": "instagram_post.jpg",
  "classification": "BETTING",
  "confidence": 0.89,
  "text_probability": 0.94,
  "vision_probability": 0.81,
  "ocr_text": "bet365 free bonus offer today only",
  "matched_keywords": ["bet365", "bonus"],
  "detected_logos": ["bet365"],
  "reasons": [
    "Text classifier detected betting-related keywords: bet365, bonus",
    "High text betting probability (94%)"
  ],
  "timestamp": "2025-01-01T12:00:00Z"
}
```

### `GET /api/results`

List stored results with stats.

```bash
curl http://localhost:8000/api/results?limit=50&prediction=BETTING
```

### `GET /api/export/json`

Download all results as JSON.

### `GET /api/export/csv`

Download all results as CSV.

### `GET /health`

Health check.

---

## Training a Custom YOLO Model

To detect specific betting logos (1xbet, Bet365, etc.), you need labelled training images.

### 1. Prepare dataset

Follow `datasets/README.md` for the expected directory structure.

### 2. Train

```bash
python train_yolo.py --epochs 100 --batch 16 --device 0  # GPU
python train_yolo.py --epochs 50 --batch 8 --device cpu   # CPU
```

### 3. Result

The best model weights are saved to `detector/saved/betting_yolo.pt` and will be automatically used on next startup.

---

## Project Structure

```
betting_detector/
│
├── api/
│   ├── __init__.py
│   ├── routes.py           ← FastAPI endpoints
│   └── schemas.py          ← Pydantic models
│
├── models/
│   ├── __init__.py
│   ├── text_classifier.py  ← TF-IDF + optional BERT
│   └── saved/              ← trained model files
│
├── ocr/
│   ├── __init__.py
│   └── extractor.py        ← PaddleOCR wrapper
│
├── detector/
│   ├── __init__.py
│   ├── yolo_detector.py    ← YOLOv8 wrapper
│   └── saved/              ← custom YOLO weights
│
├── fusion/
│   ├── __init__.py
│   └── engine.py           ← score fusion logic
│
├── database/
│   ├── __init__.py
│   ├── db.py               ← SQLAlchemy engine
│   ├── models.py           ← ORM models
│   └── crud.py             ← CRUD + export helpers
│
├── dashboard/
│   ├── __init__.py
│   └── app.py              ← Streamlit UI
│
├── datasets/               ← YOLO training data goes here
├── tests/                  ← pytest test suite
│
├── app.py                  ← FastAPI application entry point
├── train_text_classifier.py
├── train_yolo.py
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
└── pytest.ini
```

---

## Running Tests

```bash
cd betting_detector
pytest tests/ -v
```

Tests are fully isolated — no running server or GPU required. All ML components are mocked.

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `sqlite:///./betting_detector.db` | SQLAlchemy database URL |
| `USE_BERT` | `false` | Enable BERT classifier (`true`/`false`) |
| `API_BASE_URL` | `http://localhost:8000` | API URL used by the dashboard |

---

## Batch Processing

```python
import requests, os

image_dir = "path/to/images"
for fname in os.listdir(image_dir):
    with open(os.path.join(image_dir, fname), "rb") as f:
        resp = requests.post(
            "http://localhost:8000/api/detect",
            files={"image": (fname, f, "image/jpeg")},
        )
        print(fname, resp.json()["classification"])
```

---

## Confidence Calibration

The fusion weights can be tuned after collecting ground-truth labels:

```python
from fusion.engine import FusionEngine

# Custom weights — e.g. if your OCR is less reliable
engine = FusionEngine(text_weight=0.4, vision_weight=0.6)
```

---

## Requirements

- Python 3.11+
- 4 GB RAM minimum (8 GB recommended for BERT)
- GPU optional (CUDA 12.x for full speed)
