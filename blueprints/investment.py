"""
blueprints/investment.py
------------------------
Flask Blueprint for the Investment Scam Detector (ScamGuard AI).
Dual-Engine analysis: XGBoost + XLM-RoBERTa with keyword fallback.
"""


from flask import Blueprint, request, jsonify, render_template
from blueprints.auth import login_required

bp = Blueprint('investment', __name__, url_prefix='/investment')

# ── Lazy-loaded services ─────────────────────────────────────
_services_loaded = False
_nlp_analyzer = None
_link_checker = None
_fraud_scorer = None


def _load_services():
    """Lazy-import the scam detector services on first request."""
    global _services_loaded, _nlp_analyzer, _link_checker, _fraud_scorer
    if _services_loaded:
        return
    from services.scam_detector import nlp_analyzer, link_checker, fraud_scorer
    _nlp_analyzer = nlp_analyzer
    _link_checker = link_checker
    _fraud_scorer = fraud_scorer
    _services_loaded = True


# ── Routes ───────────────────────────────────────────────────
@bp.route('/')
@login_required
def index():
    return render_template('investment/index.html', active_page='invest')


@bp.route('/analyze', methods=['POST'])
@login_required
def analyze():
    """
    Accept JSON { "message": "<text>" }, run the full scam detection pipeline:
      1. NLP keyword / ML analysis  → engine_a, engine_b scores
      2. URL / domain age check     → link_risk
      3. Weighted combination        → final_score, traffic_light colour
    Return JSON result for the frontend.
    """
    _load_services()

    data = request.get_json(silent=True)
    # Coerce before stripping: a non-string "message" (a number, a list, null)
    # previously raised AttributeError and surfaced as a 500 instead of a 422.
    text = str((data or {}).get('message') or '').strip()
    if not text:
        return jsonify({'error': 'Message cannot be empty.'}), 422

    try:
        # Step 1 — NLP analysis (Engines A and B)
        engine_a, engine_b, text_reasons, engine_status = _nlp_analyzer.analyze_text(text)

        # Step 1b — Hindi / Hinglish / obfuscation pass.
        # Both ML engines and the English keyword bank are blind to Hinglish,
        # which is what a large share of Indian investment-fraud copy is written
        # in, and to leetspeak evasion ("1nvestment", "p@ytm"). This scores the
        # normalised forms and raises the floor rather than replacing the
        # existing signal.
        from services.intel import multilingual
        hinglish_score, hinglish_reasons = multilingual.score_hinglish(text)
        if hinglish_score > 0:
            engine_a = max(engine_a, hinglish_score)
            text_reasons = list(text_reasons) + hinglish_reasons

        # Step 2 — Link / domain check
        link_risk, link_reasons = _link_checker.check_links(text)

        # Step 3 — Combine into final risk.
        # Engine A is trained on investment-fraud data; Engine B is a general
        # spam classifier standing in as a semantic proxy. max() let Engine B
        # alone decide the verdict, so a legitimate but promotional message
        # scoring high on "spamminess" came back as a confirmed scam. Weight
        # the fraud-specific engine higher, and only let Engine B push the
        # score up when Engine A also sees something.
        if engine_status.get('engine_b_online') and engine_b > 0:
            blended = 0.7 * engine_a + 0.3 * engine_b
            # Engine A stays the floor — it is the domain-specific signal.
            effective_nlp_score = int(round(max(engine_a, blended)))
        else:
            effective_nlp_score = engine_a

        final_score, colour = _fraud_scorer.compute_risk(effective_nlp_score, link_risk)

        # Merge reasons; add a summary line if completely clean
        all_reasons = text_reasons + link_reasons
        if not all_reasons:
            all_reasons = ["✅ No scam signals detected in this message."]

        import hashlib
        file_hash = hashlib.sha256(text.encode('utf-8')).hexdigest()

        if colour == 'red' or final_score > 70:
            recommendation = (
                "RECOMMENDATION: High investment fraud threat level detected. The message leverages psychological pressure "
                "(urgency, high return claims) and contains suspicious links. Analysts should report this offer "
                "to SEBI/RBI and flag related communication groups on social platforms (WhatsApp/Telegram) for takedown."
            )
        elif colour == 'yellow' or final_score > 30:
            recommendation = (
                "RECOMMENDATION: Moderate scam signals detected. Urgency and unverified investment opportunities observed. "
                "Verify the credentials of the offering agency before proceeding. Standard user diligence is advised."
            )
        else:
            recommendation = (
                "RECOMMENDATION: Safe content. No suspicious investment keywords or scam link indicators identified. "
                "Standard compliance guidelines apply."
            )

        # ── Intelligence layer ────────────────────────────────────────
        from services.intel import graph, evidence, calibration, multilingual as _ml
        from services.intel.explain import token_attributions, attribution_summary
        from blueprints.auth import current_username

        graph_summary = graph.ingest(
            text, module='Investment Scam', verdict=colour.upper(),
            score=final_score, source='investment',
        )
        assessment = calibration.assess(final_score, module='investment')

        # Which words drove the verdict, with character offsets so the UI can
        # highlight them in the original message.
        combined_bank = _ml.enrich_keyword_bank(_nlp_analyzer.SCAM_KEYWORDS)
        spans = token_attributions(text, combined_bank, normaliser=_ml.deobfuscate)

        evidence.append_event(
            evidence.EV_SCAN, actor=current_username(),
            subject_type='scan', subject_id=file_hash[:16],
            artefact_hash=file_hash,
            payload={'module': 'Investment Scam', 'verdict': colour,
                     'score': final_score},
        )

        return jsonify({
            'traffic_light': colour,
            'final_fraud_score': final_score,
            'assessment': assessment,
            'graph': graph_summary,
            'indicators_extracted': graph_summary.get('indicators', []),
            'attributions': spans,
            'attribution_summary': attribution_summary(spans),
            'language': _ml.normalise(text)['scripts'],
            'engine_breakdown': {
                'engine_a_xgboost': engine_a,
                'engine_b_xlm_roberta': engine_b,
            },
            'engine_status': {
                'engine_a_online': engine_status.get('engine_a_online', False),
                'engine_b_online': engine_status.get('engine_b_online', False),
            },
            'reasons': all_reasons,
            'file_hash': file_hash,
            'recommendation': recommendation
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
