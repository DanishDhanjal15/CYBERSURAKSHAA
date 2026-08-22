"""
blueprints/qr_scan.py
---------------------
Analyst-facing QR / UPI payment fraud scanner.

Wraps services/qr_analysis.py: decode every QR in an uploaded image, apply the
UPI heuristics, cross-reference the entity graph, and record the scan in the
evidence chain like every other module.
"""

import hashlib

from flask import Blueprint, request, jsonify, render_template

from blueprints.auth import login_required, current_username
from extensions import limiter

bp = Blueprint('qr_scan', __name__, url_prefix='/qr')

MAX_IMAGE_BYTES = 8 * 1024 * 1024   # a QR photo has no business being larger


@bp.route('/')
@login_required
def index():
    return render_template('qr/index.html', active_page='qr')


@bp.route('/scan', methods=['POST'])
@limiter.limit("120 per hour")
@login_required
def scan():
    if 'image' not in request.files:
        return jsonify({'error': 'No image uploaded'}), 400
    file = request.files['image']
    if not file.filename:
        return jsonify({'error': 'Empty filename'}), 400

    image_bytes = file.read()
    if not image_bytes:
        return jsonify({'error': 'Uploaded file is empty'}), 400
    if len(image_bytes) > MAX_IMAGE_BYTES:
        return jsonify({'error': 'Image too large for QR scanning (max 8 MB).'}), 413

    from services import qr_analysis
    try:
        analysis = qr_analysis.analyze_image(image_bytes)
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    except RuntimeError as exc:
        return jsonify({'error': str(exc)}), 503

    from services.intel import calibration, evidence, graph

    score = analysis['max_score']
    assessment = calibration.assess(score, module='qr_scan')

    if analysis['qr_count'] == 0:
        classification = 'NO_QR'
    elif assessment['band'] == calibration.BAND_THREAT:
        classification = 'HIGH_RISK'
    elif assessment['band'] == calibration.BAND_ABSTAIN:
        classification = 'SUSPICIOUS'
    else:
        classification = 'CLEAN'

    file_hash = hashlib.sha256(image_bytes).hexdigest()

    graph_summary = None
    if analysis['qr_count']:
        # Decoded payloads carry the identifiers (VPA, URL, phone) — ingest
        # them so the next scan that meets this operator links to this one.
        joined = "\n".join(r['payload'] for r in analysis['results'])
        graph_summary = graph.ingest(
            joined,
            module='QR Scan',
            verdict=classification,
            score=int(score),
            source='qr_scan',
        )

    evidence.append_event(
        evidence.EV_SCAN, actor=current_username(),
        subject_type='scan', subject_id=file_hash[:16],
        artefact_hash=file_hash,
        payload={
            'module': 'QR Scan',
            'verdict': classification,
            'score': score,
            'qr_count': analysis['qr_count'],
        },
    )

    return jsonify({
        'classification': classification,
        'score': score,
        'qr_count': analysis['qr_count'],
        'results': analysis['results'],
        'assessment': assessment,
        'graph': graph_summary,
        'file_hash': file_hash,
    })
