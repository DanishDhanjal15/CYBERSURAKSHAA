"""
blueprints/apk_scan.py
----------------------
Android package analysis routes.

Illegal betting and banking-fraud apps reach victims as sideloaded APKs. This
module inspects the uploaded package statically — manifest, permissions,
signing certificate, embedded endpoints — and pushes the results into the
entity graph, where the signing-certificate fingerprint links every reskinned
clone from the same operator.

Uploads are deleted after analysis. The platform keeps the extracted facts,
not the malware sample; retaining executable payloads on a web-facing host is a
liability with no analytical benefit here.
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path

from flask import Blueprint, request, jsonify, render_template

from blueprints.auth import login_required, current_username
from services.intel import apk as apk_service
from services.intel import graph, evidence
from services.intel.indicators import Indicator

bp = Blueprint('apk_scan', __name__, url_prefix='/apk')

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UPLOAD_DIR = os.path.join(BASE_DIR, 'static', 'uploads')

ALLOWED_SUFFIXES = {'.apk', '.xapk', '.apks'}
MAX_APK_BYTES = 200 * 1024 * 1024


@bp.route('/')
@login_required
def index():
    return render_template('apk/index.html', active_page='apk')


@bp.route('/analyze', methods=['POST'])
@login_required
def analyze():
    f = request.files.get('apk')
    if not f or not f.filename:
        return jsonify({'error': 'No APK uploaded.'}), 400

    suffix = Path(f.filename).suffix.lower()
    if suffix not in ALLOWED_SUFFIXES:
        return jsonify({'error': 'Expected an .apk file, got %s' % suffix}), 400

    os.makedirs(UPLOAD_DIR, exist_ok=True)
    tmp = Path(UPLOAD_DIR) / ("%s%s" % (uuid.uuid4(), suffix))

    try:
        f.save(tmp)

        size = tmp.stat().st_size
        if size > MAX_APK_BYTES:
            return jsonify({'error': 'APK exceeds the %d MB limit.'
                                     % (MAX_APK_BYTES // (1024 * 1024))}), 413

        result = apk_service.analyse(str(tmp))
        if result.get('error'):
            return jsonify(result), 400

        result['file_size'] = size

        # Push the extracted indicators into the graph. Building Indicator
        # objects from the analysis output keeps the certificate fingerprint,
        # which no text extractor could ever have produced, as a first-class
        # graph node.
        extra = []
        for i in result.get('indicators', []):
            extra.append(Indicator(
                kind=i['kind'], raw=i.get('raw', i['normalized']),
                normalized=i['normalized'], confidence=i.get('confidence', 1.0),
                context=i.get('context', ''), meta=i.get('meta', {}),
            ))

        graph_summary = graph.ingest(
            text=" ".join(sorted({i['normalized'] for i in result.get('indicators', [])})),
            module='Betting App (APK)',
            verdict=result.get('verdict'),
            score=result.get('risk_score', 0),
            source='apk',
            extra_indicators=extra,
        )
        result['graph'] = graph_summary

        evidence.append_event(
            evidence.EV_SCAN, actor=current_username(),
            subject_type='apk', subject_id=result.get('package') or 'unknown',
            artefact_hash=result.get('file_sha256'),
            payload={
                'module': 'Betting App (APK)',
                'package': result.get('package'),
                'verdict': result.get('verdict'),
                'risk_score': result.get('risk_score'),
                'certificates': [c['sha256'] for c in result.get('certificates', [])],
            },
        )

        return jsonify(result)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

    finally:
        try:
            Path(tmp).unlink(missing_ok=True)
        except Exception:
            pass
