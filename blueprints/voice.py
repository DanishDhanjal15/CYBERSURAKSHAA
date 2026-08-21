"""
blueprints/voice.py
-------------------
Voice-scam and synthetic-speech analysis routes.

Accepts either an audio upload or a pasted transcript. The transcript path
exists as a first-class input, not a fallback: speech recognition is the
slowest and least reliable part of the pipeline, and an analyst who already
has a transcript (or who needs to correct the machine one) should not be forced
through it.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from pathlib import Path

from flask import Blueprint, request, jsonify, render_template, session

from blueprints.auth import login_required, current_username
from services.intel import voice as voice_service
from services.intel import graph, evidence

bp = Blueprint('voice', __name__, url_prefix='/voice')

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UPLOAD_DIR = os.path.join(BASE_DIR, 'static', 'uploads')

MAX_TRANSCRIPT_CHARS = 50_000


@bp.route('/')
@login_required
def index():
    return render_template('voice/index.html', active_page='voice')


@bp.route('/analyze', methods=['POST'])
@login_required
def analyze():
    """
    Analyse a call recording or transcript.

    Accepts multipart with an `audio` file and/or a `transcript` field.
    """
    transcript = (request.form.get('transcript') or '').strip()
    if len(transcript) > MAX_TRANSCRIPT_CHARS:
        return jsonify({'error': 'Transcript exceeds %d characters.'
                                 % MAX_TRANSCRIPT_CHARS}), 413

    tmp_path = None
    file_hash = None

    audio = request.files.get('audio')
    if audio and audio.filename:
        suffix = Path(audio.filename).suffix.lower()
        if suffix not in voice_service.SUPPORTED_AUDIO:
            return jsonify({
                'error': 'Unsupported audio type: %s. Supported: %s'
                         % (suffix, ', '.join(sorted(voice_service.SUPPORTED_AUDIO)))
            }), 400

        os.makedirs(UPLOAD_DIR, exist_ok=True)
        tmp_path = Path(UPLOAD_DIR) / ("%s%s" % (uuid.uuid4(), suffix))
        audio.save(tmp_path)

        with open(tmp_path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()

    if not transcript and not tmp_path:
        return jsonify({'error': 'Provide an audio file or a transcript.'}), 400

    try:
        result = voice_service.analyse(
            path=str(tmp_path) if tmp_path else None,
            transcript=transcript or None,
            language=request.form.get('language') or None,
        )

        if not file_hash:
            file_hash = hashlib.sha256(
                (result.get('transcript') or '').encode('utf-8')
            ).hexdigest()
        result['file_hash'] = file_hash

        # Feed spoken indicators into the entity graph. A phone number or UPI
        # address read out on a call is the same node as one printed on a
        # poster, which is exactly the link this platform exists to make.
        if result.get('transcript'):
            result['graph'] = graph.ingest(
                result['transcript'], module='Voice Scam',
                verdict=result.get('verdict'), score=result.get('script_score', 0),
                source='voice',
            )

        evidence.append_event(
            evidence.EV_SCAN, actor=current_username(),
            subject_type='voice', subject_id=file_hash[:16],
            artefact_hash=file_hash,
            payload={
                'module': 'Voice Scam',
                'verdict': result.get('verdict'),
                'score': result.get('script_score'),
                'had_audio': bool(tmp_path),
            },
        )

        return jsonify(result)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

    finally:
        # The recording is evidence of a crime against the person who submitted
        # it, and the analysis does not need it retained. Delete unless the
        # deployment explicitly opts into retention.
        if tmp_path and os.environ.get('RETAIN_VOICE_UPLOADS', '0') != '1':
            try:
                Path(tmp_path).unlink(missing_ok=True)
            except Exception:
                pass


@bp.route('/api/backend')
@login_required
def api_backend():
    """Report which transcription backend, if any, is available."""
    model, backend = voice_service._load_whisper()
    return jsonify({
        'transcription_available': model is not None,
        'backend': backend,
        'note': ('Paste a transcript to analyse the call script without a '
                 'speech-recognition backend.') if model is None else None,
    })
