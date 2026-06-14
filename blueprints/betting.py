"""
blueprints/betting.py
---------------------
Flask Blueprint for the Betting Content Detector.
Wraps the existing betting_detector pipeline (OCR → NLP → YOLO → Fusion).
"""

import os
import sys
from flask import Blueprint, request, jsonify, render_template
from blueprints.auth import login_required

bp = Blueprint('betting', __name__, url_prefix='/betting')

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BETTING_DIR = os.path.join(BASE_DIR, 'danish betting', 'betting_detector')

# ── Lazy-loaded engine instances ─────────────────────────────
_ocr = None
_classifier = None
_detector = None
_fusion = None


def _ensure_path():
    """Add the betting_detector directory to sys.path for module imports."""
    if BETTING_DIR not in sys.path:
        sys.path.insert(0, BETTING_DIR)


def _get_ocr():
    global _ocr
    if _ocr is None:
        _ensure_path()
        from ocr.extractor import OCRExtractor
        _ocr = OCRExtractor()
    return _ocr


def _get_classifier():
    global _classifier
    if _classifier is None:
        _ensure_path()
        from models.text_classifier import TextClassifier
        _classifier = TextClassifier()
    return _classifier


def _get_detector():
    global _detector
    if _detector is None:
        _ensure_path()
        # Change CWD temporarily so YOLO can find yolov8n.pt
        old_cwd = os.getcwd()
        os.chdir(BETTING_DIR)
        try:
            from detector.yolo_detector import YOLODetector
            _detector = YOLODetector()
        finally:
            os.chdir(old_cwd)
    return _detector


def _get_fusion():
    global _fusion
    if _fusion is None:
        _ensure_path()
        from fusion.engine import FusionEngine
        _fusion = FusionEngine()
    return _fusion


# ── Routes ───────────────────────────────────────────────────
@bp.route('/')
@login_required
def index():
    return render_template('betting/index.html', active_page='betting')


@bp.route('/detect', methods=['POST'])
@login_required
def detect():
    """Accept an image upload, run the full detection pipeline, return JSON."""
    if 'image' not in request.files:
        return jsonify({'error': 'No image uploaded'}), 400

    file = request.files['image']
    if not file.filename:
        return jsonify({'error': 'Empty filename'}), 400

    image_bytes = file.read()
    if len(image_bytes) == 0:
        return jsonify({'error': 'Uploaded file is empty'}), 400

    try:
        # 1. OCR
        ocr = _get_ocr()
        ocr_result = ocr.extract(image_bytes=image_bytes)

        # 2. Text Classification
        clf = _get_classifier()
        text_result = clf.classify(ocr_result.extracted_text)

        # 3. YOLO Detection
        det = _get_detector()
        yolo_result = det.detect(image_bytes=image_bytes, ocr_words=ocr_result.words)

        # 4. Fusion
        fusion = _get_fusion()
        fusion_result = fusion.fuse(
            text_probability=text_result.betting_probability,
            vision_probability=yolo_result.confidence,
            matched_keywords=text_result.matched_keywords,
            detected_objects=[o.label for o in yolo_result.detected_objects],
        )

        import base64
        import hashlib
        file_hash = hashlib.sha256(image_bytes).hexdigest()

        # Save media permanently for CTI reports
        from services.report_generator import save_scanned_media
        save_scanned_media(file_hash, file_bytes=image_bytes)

        if fusion_result.classification == 'BETTING':
            recommendation = (
                "RECOMMENDATION: Flagged betting content detected. In compliance with national advisory guidelines, "
                "access to unregistered betting and gambling platforms should be restricted. Analysts should report the "
                "hosting URL/domain to the Ministry of Electronics and Information Technology (MeitY) for content filtering and DNS blocking."
            )
        else:
            recommendation = (
                "RECOMMENDATION: No betting or gambling patterns detected. Content appears benign. "
                "Standard periodic monitoring is recommended."
            )

        annotated_base64 = None
        if yolo_result.annotated_image:
            annotated_base64 = base64.b64encode(yolo_result.annotated_image).decode('utf-8')

        return jsonify({
            'classification': fusion_result.classification,
            'confidence': round(fusion_result.final_score * 100, 1),
            'text_probability': round(text_result.betting_probability * 100, 1),
            'vision_probability': round(yolo_result.confidence * 100, 1),
            'ocr_text': ocr_result.extracted_text,
            'matched_keywords': text_result.matched_keywords,
            'detected_logos': [o.label for o in yolo_result.detected_objects],
            'reasons': fusion_result.reasons,
            'annotated_image': annotated_base64,
            'file_hash': file_hash,
            'recommendation': recommendation
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
