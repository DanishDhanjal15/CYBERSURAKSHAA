"""
blueprints/nfc_scan.py
---------------------
Analyst-facing NFC tag threat scanner.

Decodes and scans NFC NDEF records (live Web NFC scan or manually entered / dumped records),
analyzes URI, phone, SMS, and text payloads, cross-references with the entity graph,
and records the activity in the evidence chain ledger.
"""

import hashlib
from flask import Blueprint, request, jsonify, render_template
from blueprints.auth import login_required, current_username
from extensions import limiter

bp = Blueprint('nfc_scan', __name__, url_prefix='/nfc')

@bp.route('/')
@login_required
def index():
    return render_template('nfc/index.html', active_page='nfc')


@bp.route('/scan', methods=['POST'])
@limiter.limit("120 per hour")
@login_required
def scan():
    data = request.get_json(silent=True) or {}
    records = data.get('records', [])
    # The tag's hardware serial number, when Web NFC supplied one. It is the
    # only identity a *physical* tag has: the same serial surfacing at two
    # locations is one tag travelling, not two deployments.
    serial = str(data.get('serial') or '').strip()[:64]

    if not records:
        return jsonify({'error': 'No NFC records provided'}), 400

    from services import nfc_analysis
    try:
        analysis = nfc_analysis.analyze_nfc_tag(records)
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    except RuntimeError as exc:
        return jsonify({'error': str(exc)}), 503

    from services.intel import calibration, evidence, graph

    score = analysis['max_score']
    assessment = analysis['assessment']

    if analysis['record_count'] == 0:
        classification = 'NO_DATA'
    elif assessment['band'] == calibration.BAND_THREAT:
        classification = 'HIGH_RISK'
    elif assessment['band'] == calibration.BAND_ABSTAIN:
        classification = 'SUSPICIOUS'
    else:
        classification = 'CLEAN'

    # Compute a unique hash of the combined payload content
    combined_payloads = "||".join(f"{r.get('recordType')}:{r.get('data')}" for r in records)
    payload_hash = hashlib.sha256(combined_payloads.encode('utf-8')).hexdigest()

    graph_summary = None
    if analysis['record_count'] > 0:
        # Ingest the NDEF payloads into the entity correlation graph
        graph_summary = graph.ingest(
            combined_payloads,
            module='NFC Scan',
            verdict=classification,
            score=int(score),
            source='nfc_scan',
        )

    evidence.append_event(
        evidence.EV_SCAN, actor=current_username(),
        subject_type='scan', subject_id=payload_hash[:16],
        artefact_hash=payload_hash,
        payload={
            'module': 'NFC Scan',
            'verdict': classification,
            'score': score,
            'record_count': analysis['record_count'],
            **({'tag_serial': serial} if serial else {}),
        },
    )

    return jsonify({
        'classification': classification,
        'score': score,
        'record_count': analysis['record_count'],
        'results': analysis['results'],
        'assessment': assessment,
        'graph': graph_summary,
        'payload_hash': payload_hash,
        'serial': serial or None,
    })
