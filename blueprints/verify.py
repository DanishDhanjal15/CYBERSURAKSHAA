"""
blueprints/verify.py
--------------------
Public evidence verification.

Every CTI report and takedown notice the platform generates carries an evidence
hash and a QR code pointing here. Anyone holding one of those documents — a
recipient intermediary, a court, a journalist, the person it concerns — can
confirm that the hash corresponds to a real scan and that the audit chain
around it is intact, without an account.

That is the whole point: a verification endpoint that requires the operator's
credentials verifies nothing to anybody outside the operator.

Disclosure boundary
-------------------
The response states existence, timestamp, module, verdict and chain integrity.
It does NOT disclose the scanned content, the submitting user, extracted
personal data such as phone numbers, or anything else. Enumeration is bounded
by the endpoint being rate-limited and by requiring a full 64-character SHA-256
— guessing one is not feasible, and a partial hash is rejected rather than
matched as a prefix.
"""

from __future__ import annotations

import re

from flask import Blueprint, render_template, jsonify, request, url_for

from extensions import limiter
from services.intel import evidence

bp = Blueprint('verify', __name__)

VERIFY_RATE_LIMIT = "120 per hour"

_SHA256 = re.compile(r'^[a-fA-F0-9]{64}$')


@bp.route('/verify')
@limiter.limit(VERIFY_RATE_LIMIT)
def verify_index():
    """Landing page with a hash input box."""
    return render_template('verify.html', record=None, query=None,
                           chain_head=evidence.head())


@bp.route('/verify/<artefact_hash>')
@limiter.limit(VERIFY_RATE_LIMIT)
def verify_hash(artefact_hash):
    """
    Verify one artefact hash.

    Returns JSON for API callers and an HTML page for browsers, since the QR
    code on a printed report is scanned by a phone camera and lands here as a
    normal browser navigation.
    """
    wants_json = (
        request.args.get('format') == 'json'
        or request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        or (request.accept_mimetypes.accept_json
            and not request.accept_mimetypes.accept_html)
    )

    if not _SHA256.match(artefact_hash or ''):
        payload = {
            'valid': False,
            'error': 'Not a SHA-256 hash. A full 64-character hexadecimal '
                     'digest is required.',
        }
        if wants_json:
            return jsonify(payload), 400
        return render_template('verify.html', record=None,
                               query=artefact_hash, error=payload['error'],
                               chain_head=evidence.head()), 400

    record = evidence.lookup_artefact(artefact_hash)

    if wants_json:
        if not record:
            return jsonify({
                'artefact_hash': artefact_hash.lower(),
                'found': False,
                'message': 'No record of this artefact. Either it was never '
                           'processed by this system, or the document quoting '
                           'it is not genuine.',
            }), 404
        return jsonify(record)

    return render_template(
        'verify.html', record=record, query=artefact_hash.lower(),
        chain_head=evidence.head(),
    ), (200 if record else 404)
