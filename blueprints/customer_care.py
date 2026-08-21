"""
blueprints/customer_care.py
---------------------------
Flask Blueprint for the Fake Customer Care Scam Detector.
Imports detector, scoring, and database modules from the original
'fake customer carer' directory using importlib for isolation.
"""

import os
import ipaddress
import secrets
import socket
import threading
import importlib.util
from urllib.parse import urlparse
from flask import Blueprint, request, jsonify, render_template
from werkzeug.utils import secure_filename
from blueprints.auth import login_required

bp = Blueprint('customer_care', __name__, url_prefix='/customer-care')

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CC_DIR = os.path.join(BASE_DIR, 'fake customer carer')
UPLOAD_DIR = os.path.join(BASE_DIR, 'static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp'}

# Cap on server-side image downloads (the "analyse a URL" input).
MAX_DOWNLOAD_BYTES = 10 * 1024 * 1024   # 10 MB


class UnsafeURLError(ValueError):
    """Raised when a user-supplied URL must not be fetched server-side."""


def _assert_url_is_safe(url):
    """
    Validate a user-supplied URL before the server fetches it.

    Without this the endpoint is a server-side request forgery primitive: the
    caller picks any address the server can reach — cloud metadata services,
    internal admin ports, other hosts on the private network — and the OCR text
    of the response is handed straight back in the JSON reply.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        raise UnsafeURLError('Only http:// and https:// URLs are supported.')
    if not parsed.hostname:
        raise UnsafeURLError('URL has no host.')

    try:
        infos = socket.getaddrinfo(parsed.hostname, None)
    except socket.gaierror:
        raise UnsafeURLError(f'Could not resolve host: {parsed.hostname}')

    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            raise UnsafeURLError(
                'That URL resolves to an internal address and cannot be fetched.'
            )
    return parsed


def _download_capped(resp, filepath):
    """Stream a response to disk, aborting past MAX_DOWNLOAD_BYTES."""
    written = 0
    with open(filepath, 'wb') as f:
        for chunk in resp.iter_content(chunk_size=8192):
            if not chunk:
                continue
            written += len(chunk)
            if written > MAX_DOWNLOAD_BYTES:
                raise UnsafeURLError(
                    f'Image exceeds the {MAX_DOWNLOAD_BYTES // (1024 * 1024)} MB limit.'
                )
            f.write(chunk)


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

# Serialises first-use imports. Without it two concurrent requests can both
# execute the module (and init_db) at once, racing on the globals.
_module_lock = threading.Lock()


def _get_detector():
    global _detector_mod
    if _detector_mod is None:
        with _module_lock:
            if _detector_mod is None:
                _detector_mod = _import_module('cc_detector', os.path.join(CC_DIR, 'detector.py'))
    return _detector_mod


def _get_scoring():
    global _scoring_mod
    if _scoring_mod is None:
        with _module_lock:
            if _scoring_mod is None:
                _scoring_mod = _import_module('cc_scoring', os.path.join(CC_DIR, 'scoring.py'))
    return _scoring_mod


def _get_database():
    global _database_mod
    if _database_mod is None:
        with _module_lock:
            if _database_mod is None:
                mod = _import_module('cc_database', os.path.join(CC_DIR, 'database.py'))
                mod.init_db()
                _database_mod = mod   # publish only after init_db() succeeds
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

            _assert_url_is_safe(target_url)
            # allow_redirects=False so a redirect cannot bounce the request to
            # an internal address that the up-front check already rejected.
            resp = req.get(target_url, headers=headers, timeout=15,
                           stream=True, allow_redirects=False)
            while resp.is_redirect or resp.is_permanent_redirect:
                target_url = req.compat.urljoin(target_url, resp.headers['Location'])
                _assert_url_is_safe(target_url)
                resp.close()
                resp = req.get(target_url, headers=headers, timeout=15,
                               stream=True, allow_redirects=False)
            resp.raise_for_status()

            content_type = resp.headers.get('Content-Type', '')

            # If HTML page, extract og:image
            if 'text/html' in content_type:
                full_resp = req.get(target_url, headers=headers, timeout=15)
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
                    target_url = req.compat.urljoin(target_url, resolved_url)
                    _assert_url_is_safe(target_url)
                    resp = req.get(target_url, headers=headers, timeout=15, stream=True)
                    resp.raise_for_status()
                    content_type = resp.headers.get('Content-Type', '')
                else:
                    return jsonify({'error': 'No preview image found on this webpage.'}), 400

            if content_type and not content_type.lower().startswith('image/'):
                return jsonify({
                    'error': f'That URL returned "{content_type}", not an image.'
                }), 400

            # Extension follows the served Content-Type rather than a hardcoded
            # ".jpg" — saving a PNG/WebP under a .jpg name broke the OCR
            # pre-resize step, which then silently fell back to the slow path.
            ext = {
                'image/png': 'png', 'image/jpeg': 'jpg', 'image/jpg': 'jpg',
                'image/webp': 'webp', 'image/gif': 'gif', 'image/bmp': 'bmp',
            }.get(content_type.split(';')[0].strip().lower(), 'jpg')

            unique_filename = f"{secrets.token_hex(4)}_url_image.{ext}"
            filepath = os.path.join(UPLOAD_DIR, unique_filename)
            _download_capped(resp, filepath)

            extracted_text, ocr_confidence = det.extract_text_from_image(filepath)

        except UnsafeURLError as e:
            return jsonify({'error': str(e)}), 400
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

    # ── Intelligence layer ───────────────────────────────────
    # Push every indicator on the artefact into the entity graph, and score the
    # Hinglish/Devanagari forms the English-only banks below cannot see.
    from services.intel import graph as _graph, multilingual as _ml
    _hinglish_score, _hinglish_reasons = _ml.score_hinglish(extracted_text)
    _lang = _ml.normalise(extracted_text)

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

    # The Hinglish bank raises the urgency and coercion indices rather than
    # replacing them: a poster reading "khata band ho jayega, turant call
    # karein" carries exactly the pressure the English lists above measure,
    # and previously scored the 8/12 floor because none of their terms matched.
    if _hinglish_score > 0:
        urgency_score = max(urgency_score, min(99, _hinglish_score))
        coercion_score = max(coercion_score, min(99, int(_hinglish_score * 0.9)))

    # Feed the graph once, from a single place, so both response paths below
    # contribute their indicators.
    graph_summary = _graph.ingest(
        extracted_text, module='Customer Care',
        verdict='PENDING', score=0, source=input_type or 'text',
    )
    intel_extras = {
        'graph': graph_summary,
        'indicators_extracted': graph_summary.get('indicators', []),
        'language': _lang['scripts'],
        'multilingual': _lang['multilingual'],
        'hinglish_score': _hinglish_score,
        'hinglish_reasons': _hinglish_reasons,
    }

    if not phones:
        # Delegate to the scoring engine rather than hardcoding "Safe". It
        # treats a recognised brand with no readable number as Suspicious —
        # OCR routinely misses numbers printed over styled backgrounds, and a
        # branded customer-care poster with no verifiable number is itself a
        # known scam pattern. Returning a flat 0/Safe here discarded that.
        risk_score, severity, reasons, recommendation = scoring.calculate_risk_score(
            brand, None, None, False, 0
        )
        return jsonify({
            'has_phone': False,
            'text': extracted_text,
            'brand': brand,
            'risk_score': risk_score,
            'confidence': 0,
            'severity': severity,
            'reasons': reasons,
            'recommendation': recommendation,
            'official_phone': None,
            'detected_phone': None,
            'previous_reports': 0,
            'urgency_score': urgency_score,
            'coercion_score': coercion_score,
            'cta_density': cta_density,
            'telecom_trust': telecom_trust,
            'telecom_label': telecom_label,
            'anomaly_score': anomaly_score,
            'file_hash': file_hash,
            **intel_extras,
        })

    # Official verification
    official_contact = database.get_official_contact(brand)

    # Score every detected number and report the worst one. Scoring only
    # phones[0] let a scam poster hide behind a legitimate number printed
    # first — a standard trick to borrow credibility.
    scored = []
    for candidate in phones:
        intel = database.lookup_indicator(candidate['normalized'])
        c_is_threat = intel is not None
        c_reports = intel['reports'] if c_is_threat else 0
        c_score, c_severity, c_reasons, c_recommendation = scoring.calculate_risk_score(
            brand, candidate, official_contact, c_is_threat, c_reports
        )
        scored.append({
            'phone': candidate, 'score': c_score, 'severity': c_severity,
            'reasons': c_reasons, 'recommendation': c_recommendation,
            'is_threat': c_is_threat, 'reports': c_reports,
        })

    worst = max(scored, key=lambda s: s['score'])
    primary_phone = worst['phone']
    risk_score = worst['score']
    severity = worst['severity']
    reasons = list(worst['reasons'])
    recommendation = worst['recommendation']
    is_threat = worst['is_threat']
    previous_reports = worst['reports']

    if len(scored) > 1:
        reasons.append(
            f"{len(scored)} numbers were detected; the highest-risk one is shown above."
        )

    # Confidence scoring.
    # "Verified" must mean *this number* matches the brand's official record —
    # not merely that the brand has a record on file. The looser test labelled
    # a confirmed mismatch as a "Verified Enterprise Line" in the UI.
    verified = bool(official_contact) and scoring.phone_matches_official(
        primary_phone['normalized'], official_contact.get('official_phone', '')
    )
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

    from services.intel import calibration as _cal, evidence as _ev
    from blueprints.auth import current_username as _who
    _assessment = _cal.assess(risk_score, module='customer_care')
    _ev.append_event(
        _ev.EV_SCAN, actor=_who(), subject_type='scan',
        subject_id=file_hash[:16], artefact_hash=file_hash,
        payload={'module': 'Customer Care', 'severity': severity,
                 'score': risk_score, 'brand': brand},
    )

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
        'file_hash': file_hash,
        'assessment': _assessment,
        **intel_extras,
    })


@bp.route('/report', methods=['POST'])
@login_required
def report_scam():
    """AJAX endpoint for marking a phone number as a scam indicator."""
    data = request.get_json(silent=True)
    if not data or 'phone' not in data:
        return jsonify({'success': False, 'error': 'Missing phone number'}), 400

    database = _get_database()
    new_reports = database.add_or_increment_indicator(str(data['phone']))
    # add_or_increment_indicator() returns None for anything under
    # MIN_INDICATOR_DIGITS instead of recording it. Reporting success anyway
    # left the UI showing "Reported successfully! Reports: null" for a number
    # that was never written.
    if new_reports is None:
        return jsonify({
            'success': False,
            'error': 'That number is too short to record as a threat indicator.'
        }), 400
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

