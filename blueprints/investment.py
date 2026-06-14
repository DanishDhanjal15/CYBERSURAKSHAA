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
    if not data or not data.get('message', '').strip():
        return jsonify({'error': 'Message cannot be empty.'}), 422

    text = data['message'].strip()

    try:
        # Step 1 — NLP analysis (Engines A and B)
        engine_a, engine_b, text_reasons, engine_status = _nlp_analyzer.analyze_text(text)

        # Step 2 — Link / domain check
        link_risk, link_reasons = _link_checker.check_links(text)

        # Step 3 — Combine into final risk
        effective_nlp_score = max(engine_a, engine_b)
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

        return jsonify({
            'traffic_light': colour,
            'final_fraud_score': final_score,
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
