"""
blueprints/citizen.py
---------------------
Public citizen quick-check page. No sign-in required, by design.

The analyst console is gated because its writes carry authority — scans feed
the entity graph and the evidence chain. A citizen asking "is this message a
scam?" needs neither of those things: they need an answer, in plain words,
right now. This page gives them the same text engine the Telegram bot uses
and a QR decoder, with the same containment rules the public API applies:

  * Submissions are quarantined (public_submissions table), never written to
    the entity graph. The graph is only *read*, to warn when an identifier is
    already known.
  * Verdicts are bands (SAFE / UNSURE / LIKELY SCAM) with advice, not raw
    percentages.
  * Rate limits are per-IP and tight — this is a citizen service, not a free
    classification oracle an operator can tune a creative against.

CSRF is exempted for the two JSON endpoints (see app.py): there is no session
cookie to ride, so there is nothing for CSRF protection to protect.
"""

from __future__ import annotations

from flask import Blueprint, request, jsonify, render_template

from extensions import limiter

bp = Blueprint('citizen', __name__, url_prefix='/check')

TEXT_RATE_LIMIT = "30 per hour"
QR_RATE_LIMIT = "20 per hour"
MAX_QR_IMAGE_BYTES = 4 * 1024 * 1024


@bp.route('/')
@limiter.limit("120 per hour")
def index():
    return render_template('citizen/index.html')


@bp.route('/api/text', methods=['POST'])
@limiter.limit(TEXT_RATE_LIMIT)
def check_text():
    from blueprints.public_api import run_text_check, MAX_TEXT_LENGTH

    data = request.get_json(silent=True) or {}
    text = (data.get('text') or '').strip()
    if not text:
        return jsonify({'error': 'Paste the message you want checked.'}), 400
    if len(text) > MAX_TEXT_LENGTH:
        text = text[:MAX_TEXT_LENGTH]

    return jsonify(run_text_check(text, 'web'))


@bp.route('/api/qr', methods=['POST'])
@limiter.limit(QR_RATE_LIMIT)
def check_qr():
    if 'image' not in request.files:
        return jsonify({'error': 'No image uploaded.'}), 400
    file = request.files['image']
    image_bytes = file.read()
    if not image_bytes:
        return jsonify({'error': 'Uploaded file is empty.'}), 400
    if len(image_bytes) > MAX_QR_IMAGE_BYTES:
        return jsonify({'error': 'Image too large (max 4 MB).'}), 413

    from services import qr_analysis
    try:
        analysis = qr_analysis.analyze_image(image_bytes)
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    except RuntimeError:
        return jsonify({'error': 'QR scanning is not available right now.'}), 503

    # Quarantine the decoded payloads exactly like a pasted message — the
    # graph is never written from an anonymous submission.
    if analysis['qr_count']:
        from blueprints.public_api import _quarantine
        from services.intel.indicators import extract_all
        joined = '\n'.join(r['payload'] for r in analysis['results'])
        band = ('LIKELY_SCAM' if analysis['max_score'] >= 60
                else 'UNSURE' if analysis['max_score'] >= 30 else 'SAFE')
        _quarantine('web-qr', joined, band, analysis['max_score'],
                    extract_all(joined))

    score = analysis['max_score']
    if analysis['qr_count'] == 0:
        band = 'NO_QR'
    elif score >= 60:
        band = 'LIKELY_SCAM'
    elif score >= 30:
        band = 'UNSURE'
    else:
        band = 'SAFE'

    return jsonify({
        'band': band,
        'score': score,
        'qr_count': analysis['qr_count'],
        'results': analysis['results'],
        'disclaimer': (
            'This is an automated assessment of the QR contents alone. If '
            'money has already been sent, call 1930 immediately — the first '
            'few hours are when a transfer can still be held.'
        ),
    })
