"""
blueprints/betting.py
---------------------
Flask Blueprint for the Betting Content Detector.
Wraps the existing betting_detector pipeline (OCR → NLP → YOLO → Fusion).
"""

import os
import sys
import threading
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

# Guards the lazy loaders below. Without it two concurrent first-requests both
# see the global as None and each loads its own copy of PaddleOCR / YOLO —
# doubling memory and racing on shared model state.
_load_lock = threading.Lock()


def _ensure_path():
    """Add the betting_detector directory to sys.path for module imports."""
    if BETTING_DIR not in sys.path:
        sys.path.insert(0, BETTING_DIR)


def _get_ocr():
    global _ocr
    if _ocr is None:
        with _load_lock:
            if _ocr is None:
                _ensure_path()
                from ocr.extractor import OCRExtractor
                _ocr = OCRExtractor()
    return _ocr


def _get_classifier():
    global _classifier
    if _classifier is None:
        with _load_lock:
            if _classifier is None:
                _ensure_path()
                from models.text_classifier import TextClassifier
                _classifier = TextClassifier()
    return _classifier


def _get_detector():
    global _detector
    if _detector is not None:
        return _detector
    with _load_lock:
        if _detector is not None:
            return _detector
        _ensure_path()
        from detector import yolo_detector as _yd

        # Point the loader at an absolute weights path instead of chdir-ing.
        # os.chdir mutates process-global state, so a concurrent request could
        # resolve its own paths against the wrong directory during the window
        # the model was loading.
        if not os.path.isabs(str(_yd.DEFAULT_YOLO_MODEL)):
            for candidate in (
                os.path.join(BETTING_DIR, 'yolov8n.pt'),
                os.path.join(BASE_DIR, 'yolov8n.pt'),
            ):
                if os.path.exists(candidate):
                    _yd.DEFAULT_YOLO_MODEL = candidate
                    break

        _detector = _yd.YOLODetector()
    return _detector


def _get_fusion():
    global _fusion
    if _fusion is None:
        with _load_lock:
            if _fusion is None:
                _ensure_path()
                from fusion.engine import FusionEngine
                _fusion = FusionEngine()
    return _fusion


# ── Evidence highlighting ────────────────────────────────────
# The classifier reports WHICH keywords fired and the OCR reports WHERE every
# word sits, but the two were never joined: the analyst saw a keyword list and
# had to hunt for it in the poster themselves. These helpers mark each OCR
# word that carried signal and paint the boxes back onto the image, giving the
# text pipeline the same visual explainability Grad-CAM gives the deepfake one.

def _match_ocr_words(words, matched_keywords):
    """Tag every OCR word with the signal it carried: 'logo', 'keyword' or None."""
    _ensure_path()
    from detector.yolo_detector import _ocr_fold, _FOLDED_LOGO_PATTERNS

    keyword_tokens = set()
    for kw in matched_keywords or []:
        for token in str(kw).lower().split():
            if len(token) >= 3:
                keyword_tokens.add(_ocr_fold(token))

    tagged = []
    for w in words:
        text_lower = w.text.lower()
        folded = _ocr_fold(w.text)
        match = None
        for pattern, pattern_folded in _FOLDED_LOGO_PATTERNS:
            if pattern in text_lower or pattern_folded in folded:
                match = 'logo'
                break
        if match is None:
            for token in keyword_tokens:
                if token and token in folded:
                    match = 'keyword'
                    break
        tagged.append({
            'text': w.text,
            'confidence': round(float(w.confidence), 3),
            'bbox': w.bbox,
            'match': match,
        })
    return tagged


def _draw_highlights(image_bytes, tagged_words):
    """
    Paint translucent boxes over the words that scored: red for classifier
    keywords, amber for brand/logo text. Returns base64 JPEG, or None when
    nothing matched — the UI hides the panel rather than showing an unchanged
    image dressed up as evidence.
    """
    matched = [t for t in tagged_words if t['match']]
    if not matched:
        return None
    try:
        import io
        import base64
        from PIL import Image, ImageDraw

        img = Image.open(io.BytesIO(image_bytes)).convert('RGBA')
        overlay = Image.new('RGBA', img.size, (0, 0, 0, 0))
        draw = ImageDraw.Draw(overlay)
        colors = {'keyword': (239, 68, 68), 'logo': (245, 158, 11)}

        for t in matched:
            xs = [float(p[0]) for p in t['bbox']]
            ys = [float(p[1]) for p in t['bbox']]
            c = colors[t['match']]
            draw.rectangle(
                [min(xs) - 3, min(ys) - 3, max(xs) + 3, max(ys) + 3],
                fill=c + (58,), outline=c + (255,), width=3,
            )

        out = Image.alpha_composite(img, overlay).convert('RGB')
        buf = io.BytesIO()
        out.save(buf, format='JPEG', quality=88)
        return base64.b64encode(buf.getvalue()).decode('utf-8')
    except Exception:
        # Explainability must never take down the scan itself.
        return None


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

        # ── Intelligence layer ────────────────────────────────────────
        # Indicators printed on the creative (the deposit UPI ID, the Telegram
        # channel, the app domain) are what actually identifies the operator.
        # Previously they were rendered once and discarded.
        from services.intel import graph, evidence, calibration
        from blueprints.auth import current_username

        graph_summary = graph.ingest(
            ocr_result.extracted_text,
            module='Betting Content',
            verdict=fusion_result.classification,
            score=int(fusion_result.final_score * 100),
            source='betting',
        )

        assessment = calibration.assess(
            fusion_result.final_score * 100, module='betting'
        )

        evidence.append_event(
            evidence.EV_SCAN, actor=current_username(),
            subject_type='scan', subject_id=file_hash[:16],
            artefact_hash=file_hash,
            payload={
                'module': 'Betting Content',
                'verdict': fusion_result.classification,
                'score': round(fusion_result.final_score * 100, 1),
            },
        )

        tagged_words = _match_ocr_words(ocr_result.words,
                                        text_result.matched_keywords)
        highlight_base64 = _draw_highlights(image_bytes, tagged_words)

        return jsonify({
            'classification': fusion_result.classification,
            'confidence': round(fusion_result.final_score * 100, 1),
            'assessment': assessment,
            'graph': graph_summary,
            'indicators_extracted': graph_summary.get('indicators', []),
            'text_probability': round(text_result.betting_probability * 100, 1),
            'vision_probability': round(yolo_result.confidence * 100, 1),
            'ocr_text': ocr_result.extracted_text,
            'matched_keywords': text_result.matched_keywords,
            'detected_logos': [o.label for o in yolo_result.detected_objects],
            # Generic scene objects (COCO classes). Reported separately so the
            # UI never presents "person" or "laptop" as a betting logo.
            'context_objects': [o.label for o in getattr(yolo_result, 'context_objects', [])],
            'reasons': fusion_result.reasons,
            'annotated_image': annotated_base64,
            # Word-level evidence: which OCR words carried signal, and the
            # image with those words boxed. Null when nothing matched.
            'highlight_image': highlight_base64,
            'ocr_words': tagged_words,
            'file_hash': file_hash,
            'recommendation': recommendation
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
