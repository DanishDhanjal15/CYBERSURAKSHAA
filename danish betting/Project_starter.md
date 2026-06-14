You can give Antigravity (or another coding agent) a detailed implementation prompt like this:


---

Prompt:

Build a production-ready Python application that detects betting/gambling-related Instagram posts using a hybrid OCR + Computer Vision pipeline.

Objective

Classify an Instagram post image as:

Betting/Gambling Content

Non-Betting Content


System Architecture

Instagram Image
    │
    ├── PaddleOCR → Text Extraction
    │
    ├── NLP Classifier → Betting Text Detection
    │
    ├── YOLO → Betting Logo/Object Detection
    │
    ├── Score Fusion Engine
    │
    └── Final Prediction

Technical Requirements

OCR Module

Use PaddleOCR.

Extract all visible text from the image.

Handle rotated text.

Return:

extracted_text

confidence score



Text Classification Module

Create a betting text classifier.

Detect:

betting

gambling

sportsbook

odds

jackpot

casino

stake

telegram betting groups

fixed match scams

betting promotions


Implement:

TF-IDF + Logistic Regression baseline

Optional BERT classifier


Output:

{
    "betting_probability": 0.85,
    "matched_keywords": [...]
}

YOLO Detection Module

Use YOLOv8.

Detect:

Betting logos:

1xbet

Bet365

Parimatch

Stake

Dafabet

Melbet


Visual patterns:

betting slips

odds tables

sportsbook interfaces

casino chips

roulette tables


Output:

{
    "detected_objects": [...],
    "confidence": 0.92
}

Fusion Engine

Combine OCR and YOLO scores.

Example:

final_score =
0.6 * text_probability +
0.4 * vision_probability

Classification Rules:

if final_score > 0.7:
    return "BETTING"

if final_score > 0.4:
    return "SUSPICIOUS"

else:
    return "SAFE"

API Layer

Create FastAPI endpoints.

POST:

/api/detect

Input:

{
    "image": "uploaded_file"
}

Response:

{
    "classification": "BETTING",
    "confidence": 0.89,
    "ocr_text": "...",
    "detected_logos": [...],
    "reasons": [...]
}

Database

Use SQLite.

Store:

image_name

timestamp

extracted_text

prediction

confidence


Dashboard

Build a Streamlit dashboard.

Features:

Upload image

View OCR text

View detected betting logos

View confidence score

View annotated image with bounding boxes


Project Structure

betting_detector/
│
├── api/
├── models/
├── ocr/
├── detector/
├── fusion/
├── database/
├── dashboard/
├── datasets/
├── tests/
├── app.py
├── train_yolo.py
├── train_text_classifier.py
└── requirements.txt

Additional Requirements

Python 3.11+

Type hints

Logging

Unit tests

Docker support

README with setup instructions

GPU acceleration if CUDA available

Batch image processing support

Confidence calibration

Export results to JSON and CSV


Generate complete production-ready code with modular architecture, comments, and setup instructions.


