"""
blueprints/harm_report.py
-------------------------
Victim loss intake and the national money figures.

Access is split deliberately:

* **Recording a loss** is available to any signed-in user. An officer takes a
  report at a desk; a citizen-facing channel forwards one. Neither is an
  administrative act.
* **Confirming a recovery** is admin-only. It is the one field that turns a
  claim into a measured outcome, and the whole credibility of the recovery
  figure rests on it not being self-asserted.
* **National totals** are admin-only, because they aggregate across every
  user's reports.
"""

from __future__ import annotations

from flask import Blueprint, jsonify, render_template, request, session

from blueprints.auth import login_required, admin_required, current_username
from extensions import limiter, POLLING_RATE_LIMIT
from services.intel import harm, evidence, clocks, jurisdiction

bp = Blueprint('harm', __name__, url_prefix='/harm')

# Intake is a write endpoint reachable by any account, so it is limited well
# below the general allowance — a flood of fabricated reports would distort
# every national figure downstream.
INTAKE_RATE_LIMIT = "60 per hour"


# ── Pages ────────────────────────────────────────────────────────────────

@bp.route('/')
@login_required
def index():
    return render_template('harm/index.html', active_page='harm',
                           categories=harm.CATEGORIES,
                           payment_modes=harm.PAYMENT_MODES,
                           beneficiary_kinds=harm.BENEFICIARY_KINDS)


# ── Intake ───────────────────────────────────────────────────────────────

@bp.route('/api/report', methods=['POST'])
@login_required
@limiter.limit(INTAKE_RATE_LIMIT)
def api_record():
    """
    Record one reported loss.

    Deliberately accepts no victim name, phone number or address — see the
    module docstring in services/intel/harm.py. `reporter_ref` is an opaque
    handle the reporting channel chooses, so a follow-up can be matched
    without the platform holding anybody's identity.
    """
    data = request.get_json(silent=True) or {}

    report_id, err = harm.record_report(
        amount_rupees=data.get('amount'),
        category=data.get('category') or 'other',
        payment_mode=data.get('payment_mode'),
        beneficiary_kind=data.get('beneficiary_kind'),
        beneficiary_value=(data.get('beneficiary_value') or '').strip() or None,
        incident_at=data.get('incident_at'),
        transaction_ref=(data.get('transaction_ref') or '').strip() or None,
        state_code=data.get('state_code'),
        scan_id=data.get('scan_id'),
        case_id=data.get('case_id'),
        channel=data.get('channel') or 'web',
        reporter_ref=(data.get('reporter_ref') or '').strip() or None,
        note=(data.get('note') or '')[:1000] or None,
        recorded_by=current_username(),
    )
    if err:
        return jsonify({'error': err}), 400

    row = harm.get_report(report_id)

    evidence.append_event(
        evidence.EV_SCAN, actor=current_username(),
        subject_type='victim_report', subject_id=report_id,
        payload={'category': row['category'],
                 'amount_paise': row['amount_paise'],
                 'beneficiary_kind': row['beneficiary_kind']},
    )

    routing = jurisdiction.route(stated_state=data.get('state_code'),
                                 phone=data.get('victim_phone'),
                                 beneficiary_state=data.get('beneficiary_state'))

    return jsonify({
        'id': report_id,
        'report': row,
        'golden_hour': row['golden_hour'],
        # What to do next, not just what was stored. Somebody who has lost
        # money needs the deadline, the force, and the fact that they can file
        # anywhere — in that order.
        'clocks': clocks.for_victim_report(row),
        'routing': routing,
        'note': (
            'Recorded within the golden hour — the strongest window for a lien '
            'on the beneficiary account.'
            if row['golden_hour'] else
            'This amount is recorded as reported by the victim. It is not '
            'counted as verified until a bank confirms it.'
        ),
    })


@bp.route('/api/reports')
@login_required
@limiter.limit(POLLING_RATE_LIMIT)
def api_list():
    return jsonify({'reports': harm.list_reports(
        category=request.args.get('category') or None,
        state=request.args.get('state') or None,
        status=request.args.get('status') or None,
        limit=int(request.args.get('limit', 100)),
    )})


@bp.route('/api/report/<int:report_id>/recovery', methods=['POST'])
@admin_required
def api_confirm_recovery(report_id):
    """
    Record a confirmed lien or reversal.

    Admin-only and human-only. Nothing in the platform infers recovery — it
    cannot see a bank ledger, and a recovery figure derived from a takedown
    would be reporting success nobody observed.
    """
    data = request.get_json(silent=True) or {}
    ok, err = harm.confirm_recovery(
        report_id, data.get('amount'),
        status=data.get('status') or harm.ST_RECOVERED,
        confirmed_by=current_username(),
        note=(data.get('note') or '')[:500] or None,
    )
    if not ok:
        return jsonify({'error': err}), 400

    evidence.append_event(
        evidence.EV_ADMIN, actor=current_username(),
        subject_type='victim_report', subject_id=report_id,
        payload={'action': 'RECOVERY_CONFIRMED',
                 'amount': data.get('amount'),
                 'status': data.get('status')},
    )
    return jsonify({'id': report_id, 'report': harm.get_report(report_id)})


@bp.route('/api/report/<int:report_id>/bank-reported', methods=['POST'])
@login_required
def api_bank_reported(report_id):
    """
    Record when the victim told their bank.

    A separate clock from when they told us: RBI's limited-liability windows
    run from the customer's report to the bank, and that is what decides
    whether they bear the loss.
    """
    data = request.get_json(silent=True) or {}
    if not harm.mark_bank_reported(report_id, when=data.get('when')):
        return jsonify({'error': 'report not found'}), 404
    return jsonify({'id': report_id, 'report': harm.get_report(report_id)})


# ── Figures ──────────────────────────────────────────────────────────────

@bp.route('/api/totals')
@admin_required
@limiter.limit(POLLING_RATE_LIMIT)
def api_totals():
    days = request.args.get('days', type=int)
    return jsonify({
        'totals': harm.national_totals(days=days,
                                       state=request.args.get('state'),
                                       category=request.args.get('category')),
        'by_category': harm.by_category(days=days),
        'by_state': harm.by_state(days=days),
        'by_payment_mode': harm.by_payment_mode(days=days),
        'golden_hour': harm.golden_hour_stats(),
        'top_beneficiaries': harm.top_beneficiaries(limit=15),
    })


@bp.route('/api/entity/<int:entity_id>/exposure')
@login_required
def api_entity_exposure(entity_id):
    return jsonify(harm.entity_exposure(entity_id))


@bp.route('/api/campaign/<int:campaign_id>/exposure')
@login_required
def api_campaign_exposure(campaign_id):
    return jsonify(harm.campaign_exposure(campaign_id))


# ── Jurisdiction ─────────────────────────────────────────────────────────

@bp.route('/api/jurisdictions')
@login_required
def api_jurisdictions():
    """The 36 State and UT cyber jurisdictions, grouped by region."""
    return jsonify({
        'by_region': jurisdiction.by_region(),
        'summary': jurisdiction.summary(),
    })


@bp.route('/api/route', methods=['POST'])
@login_required
def api_route():
    """
    Work out which force to send a case to, and show the reasoning.

    Returns every candidate rather than one answer: cybercrime routinely spans
    the victim's State, the mule account's State and the infrastructure's, and
    collapsing that to a single name loses the part an investigator needs.
    """
    data = request.get_json(silent=True) or {}
    return jsonify(jurisdiction.route(
        stated_state=data.get('state_code'),
        phone=data.get('phone'),
        beneficiary_state=data.get('beneficiary_state'),
        infrastructure_state=data.get('infrastructure_state'),
    ))


@bp.route('/api/zero-fir')
@login_required
def api_zero_fir():
    """
    What to tell somebody being turned away at the wrong police station.

    Unauthenticated callers get this through the public API; here it is for
    officers to hand to a complainant.
    """
    return jsonify(jurisdiction.zero_fir_guidance())


@bp.route('/api/by-jurisdiction')
@admin_required
def api_by_jurisdiction():
    """Reported losses grouped by State/UT."""
    return jsonify(jurisdiction.loss_by_jurisdiction(
        days=request.args.get('days', type=int)))


# ── Conversation triage ──────────────────────────────────────────────────
#
# The long-form frauds — task scams, pig butchering, romance, predatory
# lending recovery — cannot be usefully answered with "is this a scam". The
# answer is the same at every stage of a trick that runs for weeks. What
# changes is what the person can still do about it.

@bp.route('/api/triage', methods=['POST'])
@login_required
@limiter.limit(INTAKE_RATE_LIMIT)
def api_triage():
    """
    Read a conversation and say where in the script it is.

    Returns the stage, the evidence for it, and advice specific to that stage.
    Advice for the extraction stage that talked about spotting warning signs
    would be three weeks too late; advice for first contact that talked about
    preserving evidence would frighten somebody who has lost nothing.
    """
    from services.intel import lifecycle, lending

    data = request.get_json(silent=True) or {}
    text = (data.get('text') or '').strip()
    if not text:
        return jsonify({'error': 'text is required'}), 400
    if len(text) > 20000:
        text = text[:20000]

    money_sent = data.get('money_already_sent')
    stage = lifecycle.classify(text, money_already_sent=money_sent)
    harassment = lending.score_harassment(text)

    response = {
        'stage': stage,
        'harassment': harassment,
        'summary': lifecycle.summarise(stage),
    }

    # Loan-app harassment is its own situation with its own guidance, and it
    # is not a stage of the investment script.
    if harassment['score'] >= 30:
        response['lending_harassment'] = {
            'score': harassment['score'],
            'matched': harassment['matched'],
            'guidance': lending.victim_guidance(),
        }

    # The clocks only matter once money has actually moved, and the golden
    # hour is usually long gone in these — saying so is more useful than a
    # countdown that already expired.
    if stage.get('money_moved') and data.get('incident_at'):
        from services.intel import clocks
        response['clocks'] = clocks.for_victim_report({
            'incident_at': data.get('incident_at'),
            'reported_at': None,
            'bank_reported_at': data.get('bank_reported_at'),
        })

    return jsonify(response)


@bp.route('/api/lending-guidance')
@login_required
def api_lending_guidance():
    """What to tell somebody a lending app is already harassing."""
    from services.intel import lending
    return jsonify(lending.victim_guidance())


@bp.route('/api/stage-advice/<stage>')
@login_required
def api_stage_advice(stage):
    """Advice for one named stage, for an officer briefing a caller."""
    from services.intel import lifecycle

    stage = (stage or '').upper()
    if stage not in lifecycle.STAGE_ORDER:
        return jsonify({'error': 'unknown stage: %s' % stage,
                        'stages': lifecycle.STAGE_ORDER}), 400
    return jsonify({
        'stage': stage,
        'label': lifecycle.STAGE_LABELS[stage],
        'index': lifecycle.STAGE_ORDER.index(stage) + 1,
        'of': len(lifecycle.STAGE_ORDER),
        'advice': lifecycle.advice_for(stage),
    })
