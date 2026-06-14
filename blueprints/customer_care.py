"""
blueprints/customer_care.py
---------------------------
Flask Blueprint for the Fake Customer Care Scam Detector.
Imports detector, scoring, and database modules from the original
'fake customer carer' directory using importlib for isolation.
"""

import os
import secrets
import importlib.util
from flask import Blueprint, request, jsonify, render_template
from werkzeug.utils import secure_filename
from blueprints.auth import login_required

bp = Blueprint('customer_care', __name__, url_prefix='/customer-care')

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CC_DIR = os.path.join(BASE_DIR, 'fake customer carer')
UPLOAD_DIR = os.path.join(BASE_DIR, 'static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp'}


# ── Isolated module imports via importlib ────────────────────
def _import_module(name, filepath):
    """Import a Python module from an absolute file path with a unique name."""
    spec = importlib.util.spec_from_file_location(name, filepath)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Lazy-loaded modules
_detector_mod = None
_scoring_mod = None
_database_mod = None


def _get_detector():
    global _detector_mod
    if _detector_mod is None:
        _detector_mod = _import_module('cc_detector', os.path.join(CC_DIR, 'detector.py'))
    return _detector_mod


def _get_scoring():
    global _scoring_mod
    if _scoring_mod is None:
        _scoring_mod = _import_module('cc_scoring', os.path.join(CC_DIR, 'scoring.py'))
    return _scoring_mod


def _get_database():
    global _database_mod
    if _database_mod is None:
        _database_mod = _import_module('cc_database', os.path.join(CC_DIR, 'database.py'))
        _database_mod.init_db()
    return _database_mod


def _allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# ── Routes ───────────────────────────────────────────────────
@bp.route('/')
@login_required
def index():
    return render_template('customer_care/index.html', active_page='custcare')


@bp.route('/analyze', methods=['POST'])
@login_required
def analyze():
    """Handle image upload, URL, or text input — run detection, return JSON."""
    input_type = request.form.get('input_type')
    extracted_text = ""
    ocr_confidence = None
    image_url = None

    det = _get_detector()
    scoring = _get_scoring()
    database = _get_database()

    os.makedirs(UPLOAD_DIR, exist_ok=True)

    # ── Input: Image Upload ──────────────────────────────────
    if input_type == 'image':
        if 'image_file' not in request.files:
            return jsonify({'error': 'No image file uploaded'}), 400
        file = request.files['image_file']
        if file.filename == '':
            return jsonify({'error': 'No image file selected'}), 400
        if not file or not _allowed_file(file.filename):
            return jsonify({'error': 'Invalid file type. Use PNG, JPG, JPEG, or WEBP.'}), 400

        filename = secure_filename(file.filename)
        unique_filename = f"{secrets.token_hex(4)}_{filename}"
        filepath = os.path.join(UPLOAD_DIR, unique_filename)
        file.save(filepath)

        extracted_text, ocr_confidence = det.extract_text_from_image(filepath)

    # ── Input: URL ───────────────────────────────────────────
    elif input_type == 'url':
        image_url_input = request.form.get('image_url', '').strip()
        if not image_url_input:
            return jsonify({'error': 'Please enter an image URL'}), 400

        try:
            import requests as req
            import re
            headers = {'User-Agent': 'Mozilla/5.0'}
            target_url = image_url_input
            resp = req.get(image_url_input, headers=headers, timeout=15, stream=True)
            resp.raise_for_status()

            content_type = resp.headers.get('Content-Type', '')

            # If HTML page, extract og:image
            if 'text/html' in content_type:
                full_resp = req.get(image_url_input, headers=headers, timeout=15)
                patterns = [
                    r'<meta\s+[^>]*property=["\']og:image["\']\s+[^>]*content=["\']([^"\']+)["\']',
                    r'<meta\s+[^>]*content=["\']([^"\']+)["\']\s+[^>]*property=["\']og:image["\']',
                ]
                resolved_url = None
                for pattern in patterns:
                    match = re.search(pattern, full_resp.text, re.IGNORECASE)
                    if match:
                        resolved_url = match.group(1)
                        break

                if resolved_url:
                    target_url = resolved_url
                    resp = req.get(target_url, headers=headers, timeout=15, stream=True)
                    resp.raise_for_status()
                else:
                    return jsonify({'error': 'No preview image found on this webpage.'}), 400

            ext = 'jpg'
            unique_filename = f"{secrets.token_hex(4)}_url_image.{ext}"
            filepath = os.path.join(UPLOAD_DIR, unique_filename)
            with open(filepath, 'wb') as f:
                for chunk in resp.iter_content(chunk_size=8192):
                    f.write(chunk)

            extracted_text, ocr_confidence = det.extract_text_from_image(filepath)

        except Exception as e:
            return jsonify({'error': f'Failed to download image: {e}'}), 500

    # ── Input: Pasted Text ───────────────────────────────────
    else:
        extracted_text = request.form.get('pasted_text', '').strip()
        if not extracted_text:
            return jsonify({'error': 'Please enter text to analyze'}), 400

    # ── Run detection pipeline ───────────────────────────────
    brand, brand_method, brand_conf = det.detect_brand(extracted_text)
    phones = det.extract_phone_numbers(extracted_text)

    # Calculate extra scam heuristics
    import re
    extracted_text_lower = extracted_text.lower()
    
    # 1. Urgency & Fear Inducement Index
    urgency_kws = ['immediately', 'urgent', 'blocked', 'suspended', 'cancelled', 'unauthorized', 'police', 
                   'investigation', 'arrest', 'warning', 'action required', 'now', 'quickly', 'expire', 
                   'security alert', 'deactivated', 'cancel', 'disable', 'restrict', 'resolve']
    urg_matches = sum(1 for kw in urgency_kws if kw in extracted_text_lower)
    urgency_score = min(15 + urg_matches * 25, 99) if urg_matches > 0 else 8
    
    # 2. Authority Impersonation / Coercion rating
    coercion_kws = ['officer', 'support', 'helpdesk', 'representative', 'agent', 'department', 'card', 'bank', 
                    'verification', 'kyc', 'rbi', 'sbi', 'cbi', 'police', 'court', 'threat', 'penalty', 
                    'jail', 'prosecution', 'legal', 'government', 'complaint', 'manager', 'executive']
    coer_matches = sum(1 for kw in coercion_kws if kw in extracted_text_lower)
    coercion_score = min(10 + coer_matches * 20, 99) if coer_matches > 0 else 12
    
    # 3. Call-to-Action density
    links = re.findall(r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}', extracted_text_lower)
    cta_verbs = ['call', 'dial', 'click', 'visit', 'pay', 'transfer', 'send', 'verify', 'update', 'contact']
    cta_verb_count = sum(1 for v in cta_verbs if v in extracted_text_lower)
    cta_count = len(phones) + len(links) + cta_verb_count
    cta_density = min(15 + cta_count * 15, 100) if cta_count > 0 else 10
    
    # 4. Telecom trust & label (default for no-phone case)
    telecom_trust = 95
    telecom_label = 'No Indicators Detected'
        
    # 5. Linguistic anomalies
    anomaly_score = 5
    # Check for visual spaces between letters like H E L P or C u s t o m e r
    if re.search(r'\b[a-zA-Z]\s+[a-zA-Z]\s+[a-zA-Z]\b', extracted_text):
        anomaly_score += 45
    # Check for repetitive symbols
    if re.search(r'[!@#$%\^&*()\-+=\[\]{}|;:\'",.<>?]{3,}', extracted_text):
        anomaly_score += 30
    # Check for all caps words
    caps_words = re.findall(r'\b[A-Z]{4,}\b', extracted_text)
    if len(caps_words) >= 2:
        anomaly_score += 15
    anomaly_score = min(anomaly_score, 95)

    # Compute SHA256 hash of input target
    import hashlib
    file_hash = None
    if input_type in ('image', 'url'):
        try:
            with open(filepath, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
        except Exception:
            pass
            
    # Save media permanently for CTI reports
    if input_type in ('image', 'url') and file_hash:
        from services.report_generator import save_scanned_media
        save_scanned_media(file_hash, file_path=filepath)

    if not file_hash:
        file_hash = hashlib.sha256(extracted_text.encode('utf-8')).hexdigest()

    if not phones:
        return jsonify({
            'has_phone': False,
            'text': extracted_text,
            'brand': brand,
            'risk_score': 0,
            'confidence': 0,
            'severity': 'Safe',
            'reasons': ['No phone numbers detected in the scanned text/image.'],
            'recommendation': 'No customer care numbers were found. Verification is not applicable.',
            'official_phone': None,
            'detected_phone': None,
            'previous_reports': 0,
            'urgency_score': urgency_score,
            'coercion_score': coercion_score,
            'cta_density': cta_density,
            'telecom_trust': telecom_trust,
            'telecom_label': telecom_label,
            'anomaly_score': anomaly_score,
            'file_hash': file_hash
        })

    primary_phone = phones[0]

    # Official verification
    official_contact = database.get_official_contact(brand)

    # Threat intelligence
    threat_intel = database.lookup_indicator(primary_phone['normalized'])
    is_threat = threat_intel is not None
    previous_reports = threat_intel['reports'] if is_threat else 0

    # Risk scoring
    risk_score, severity, reasons, recommendation = scoring.calculate_risk_score(
        brand, primary_phone, official_contact, is_threat, previous_reports
    )

    # Confidence scoring
    verified = official_contact is not None
    confidence = scoring.calculate_confidence_score(
        ocr_conf=ocr_confidence,
        brand_conf=brand_conf,
        phone_found=True,
        verified_against_db=verified,
        threat_intel_matched=is_threat,
        is_image=(input_type == 'image'),
    )

    # Re-evaluate telecom trust based on calculations done
    if verified:
        telecom_trust = 95
        telecom_label = 'Verified Enterprise Line'
    elif is_threat:
        telecom_trust = 12
        telecom_label = 'Flagged / Suspicious VoIP'
    else:
        telecom_trust = 40
        telecom_label = 'Unverified VoIP / Virtual Carrier'

    return jsonify({
        'has_phone': True,
        'text': extracted_text,
        'brand': brand,
        'detected_phone': primary_phone['original'],
        'normalized_phone': primary_phone['normalized'],
        'all_detected_phones': [p['original'] for p in phones],
        'official_phone': official_contact['official_phone'] if official_contact else 'Not Available',
        'official_website': official_contact['official_website'] if official_contact else 'Not Available',
        'risk_score': risk_score,
        'confidence': confidence,
        'severity': severity,
        'reasons': reasons,
        'recommendation': recommendation,
        'previous_reports': previous_reports,
        'urgency_score': urgency_score,
        'coercion_score': coercion_score,
        'cta_density': cta_density,
        'telecom_trust': telecom_trust,
        'telecom_label': telecom_label,
        'anomaly_score': anomaly_score,
        'file_hash': file_hash
    })


@bp.route('/report', methods=['POST'])
@login_required
def report_scam():
    """AJAX endpoint for marking a phone number as a scam indicator."""
    data = request.get_json()
    if not data or 'phone' not in data:
        return jsonify({'success': False, 'error': 'Missing phone number'}), 400

    database = _get_database()
    new_reports = database.add_or_increment_indicator(data['phone'])
    return jsonify({'success': True, 'reports': new_reports})


@bp.route('/api/stats')
@login_required
def get_stats():
    """Endpoint for returning threat indicators and reports database count."""
    try:
        database = _get_database()
        conn = database.get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM indicators")
        scam_count = cursor.fetchone()[0]
        cursor.execute("SELECT SUM(reports) FROM indicators")
        reports_sum = cursor.fetchone()[0] or 0
        conn.close()
        return jsonify({
            'scam_numbers_count': scam_count,
            'reports_count': reports_sum
        })
    except Exception as e:
        return jsonify({'scam_numbers_count': 0, 'reports_count': 0})

