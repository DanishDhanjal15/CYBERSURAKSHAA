"""
blueprints/watchtower.py
------------------------
The lifecycle view: see it born, watch it die, catch it come back.

Three modules that only make sense together, so they get one surface:

    services/intel/ctlog.py         infrastructure appearing — certificate
                                    issuance, before the campaign launches
    services/intel/takedown.py      infrastructure disappearing — whether the
                                    notices actually achieved anything
    services/intel/resurrection.py  infrastructure returning — the operator
                                    rebuilding on the same payment rail

Every other module in this platform answers "is this artefact malicious?".
These answer "what is this operator doing over time?", which is the question an
investigator has and a classifier cannot address.

Access
======
Admin-only, with one deliberate exception. The observations here are global
across every user's scans, and the takedown metrics describe the operator's own
enforcement effectiveness — neither is a standard user's data. The exception is
`/watchtower/api/health`, which reports whether the upstream feeds are
reachable and carries no threat data at all.
"""

from __future__ import annotations

from flask import Blueprint, jsonify, render_template, request, session

from blueprints.auth import login_required, admin_required, current_username
from extensions import limiter, POLLING_RATE_LIMIT
from services.intel import ctlog, takedown, resurrection, evidence

bp = Blueprint('watchtower', __name__, url_prefix='/watchtower')

# Polling crt.sh on demand makes outbound requests to a free community
# service, so the manual trigger is limited well below the page's own refresh.
POLL_RATE_LIMIT = "10 per hour"
SWEEP_RATE_LIMIT = "20 per hour"


# ── Pages ─────────────────────────────────────────────────────────────────

@bp.route('/')
@admin_required
def index():
    return render_template('watchtower/index.html', active_page='watchtower')


# ── Feed health ───────────────────────────────────────────────────────────

@bp.route('/api/health')
@login_required
@limiter.limit(POLLING_RATE_LIMIT)
def api_health():
    """
    Whether the upstream feeds are reachable.

    Separate from the observation endpoints and deliberately available to any
    logged-in user, because the most dangerous failure mode here is an outage
    that reads as a quiet day. Anything rendering CT results must render this
    beside them.
    """
    return jsonify({
        'ct': ctlog.source_health(),
        'ct_poller': ctlog.poller_status(),
        'takedown_sweeper': takedown.sweeper_status(),
    })


# ── Certificate Transparency ──────────────────────────────────────────────

@bp.route('/api/ct/observations')
@admin_required
@limiter.limit(POLLING_RATE_LIMIT)
def api_ct_observations():
    return jsonify({
        'observations': ctlog.recent_observations(
            limit=int(request.args.get('limit', 60)),
            min_score=int(request.args.get('min_score', 0)),
            brand=request.args.get('brand') or None,
            resolving_only=request.args.get('live') == '1',
        ),
        'stats': ctlog.stats(),
    })


@bp.route('/api/ct/watchlist', methods=['GET'])
@admin_required
def api_ct_watchlist():
    return jsonify({'brands': ctlog.watchlist(active_only=False)})


@bp.route('/api/ct/watchlist', methods=['POST'])
@admin_required
def api_ct_add_brand():
    data = request.get_json(silent=True) or {}
    domain = (data.get('domain') or '').strip().lower()
    if not domain or '.' not in domain:
        return jsonify({'error': 'a domain is required, e.g. sbi.co.in'}), 400
    ctlog.add_brand(domain)
    evidence.append_event(evidence.EV_ADMIN, actor=current_username(),
                          subject_type='ct_watchlist', subject_id=domain,
                          payload={'action': 'ADD_BRAND'})
    return jsonify({'domain': domain, 'watching': True})


@bp.route('/api/ct/watchlist/<path:domain>', methods=['DELETE'])
@admin_required
def api_ct_remove_brand(domain):
    ctlog.remove_brand(domain)
    evidence.append_event(evidence.EV_ADMIN, actor=current_username(),
                          subject_type='ct_watchlist', subject_id=domain,
                          payload={'action': 'REMOVE_BRAND'})
    return jsonify({'domain': domain, 'watching': False})


@bp.route('/api/ct/poll', methods=['POST'])
@admin_required
@limiter.limit(POLL_RATE_LIMIT)
def api_ct_poll():
    """
    Poll one brand on demand.

    Bounded to a single brand per call: a full cycle takes minutes and would
    hold a request open past any sensible timeout. The background poller does
    the whole watchlist.
    """
    data = request.get_json(silent=True) or {}
    brand = (data.get('brand') or '').strip().lower()
    if not brand:
        return jsonify({'error': 'brand is required'}), 400

    result = ctlog.poll_brand(brand, since_hours=data.get('since_hours'))
    try:
        result['namespace'] = ctlog.poll_namespace(brand)
    except Exception as e:
        result['namespace'] = {'error': str(e)}
    result['health'] = ctlog.source_health()
    return jsonify(result)


@bp.route('/api/ct/resolve', methods=['POST'])
@admin_required
@limiter.limit(POLL_RATE_LIMIT)
def api_ct_resolve():
    """DNS-resolve stored observations to see which are live right now."""
    data = request.get_json(silent=True) or {}
    return jsonify(ctlog.resolve_observations(
        limit=int(data.get('limit', 40)),
        only_unresolved=bool(data.get('only_unresolved', True)),
    ))


@bp.route('/api/ct/observation/<int:obs_id>/review', methods=['POST'])
@admin_required
def api_ct_review(obs_id):
    data = request.get_json(silent=True) or {}
    ok, err = ctlog.mark_reviewed(obs_id, data.get('verdict'))
    if not ok:
        return jsonify({'error': err or 'observation not found'}), 400
    evidence.append_event(evidence.EV_ADMIN, actor=current_username(),
                          subject_type='ct_observation', subject_id=obs_id,
                          payload={'verdict': data.get('verdict')})
    return jsonify({'id': obs_id, 'verdict': data.get('verdict')})


@bp.route('/api/ct/namespace')
@admin_required
def api_ct_namespace():
    """Certificates inside a watched brand's own namespace."""
    return jsonify({
        'findings': ctlog.namespace_findings(
            brand=request.args.get('brand') or None,
            unexpected_only=request.args.get('unexpected') == '1',
        ),
    })


# ── Takedown outcomes ─────────────────────────────────────────────────────

@bp.route('/api/takedown/effectiveness')
@admin_required
@limiter.limit(POLLING_RATE_LIMIT)
def api_effectiveness():
    return jsonify({
        'effectiveness': takedown.effectiveness(request.args.get('channel') or None),
        'survival': takedown.survival_curve(days=int(request.args.get('days', 30))),
    })


@bp.route('/api/takedown/targets')
@admin_required
def api_targets():
    return jsonify({'targets': takedown.list_targets(
        state=request.args.get('state') or None,
        channel=request.args.get('channel') or None,
    )})


@bp.route('/api/takedown/target/<int:target_id>')
@admin_required
def api_target_history(target_id):
    history = takedown.target_history(target_id)
    if not history:
        return jsonify({'error': 'target not found'}), 404
    return jsonify(history)


@bp.route('/api/takedown/register', methods=['POST'])
@admin_required
def api_register_target():
    """Register a target manually, for a notice filed outside the platform."""
    data = request.get_json(silent=True) or {}
    tid, err = takedown.register_target(
        kind=data.get('kind'), value=data.get('value'),
        channel=data.get('channel') or 'MANUAL',
        scan_id=data.get('scan_id'), case_id=data.get('case_id'),
        filed_by=current_username(),
    )
    if err:
        return jsonify({'error': err}), 400

    evidence.append_event(evidence.EV_TAKEDOWN, actor=current_username(),
                          subject_type='enforcement_target', subject_id=tid,
                          payload={'kind': data.get('kind'),
                                   'channel': data.get('channel')})
    return jsonify({
        'id': tid,
        'probeable': (data.get('kind') or '').lower() in takedown.PROBEABLE_KINDS,
        'note': (
            'Payment rails, phone numbers and platform accounts cannot be '
            'probed from outside. This target stays UNKNOWN until an analyst '
            'records the outcome.'
            if (data.get('kind') or '').lower() in takedown.MANUAL_KINDS else
            'This target will be probed automatically.'
        ),
    })


@bp.route('/api/takedown/target/<int:target_id>/outcome', methods=['POST'])
@admin_required
def api_record_outcome(target_id):
    """
    Record an outcome a machine cannot observe.

    The only route by which a UPI freeze or a disconnected number ever leaves
    UNKNOWN — and payment-rail action is the most effective enforcement
    available, so leaving it unrecordable would make the best channel look
    like the least effective one.
    """
    data = request.get_json(silent=True) or {}
    ok, err = takedown.record_outcome(
        target_id, data.get('state'), note=data.get('note'),
        recorded_by=current_username())
    if not ok:
        return jsonify({'error': err or 'target not found'}), 400

    evidence.append_event(evidence.EV_TAKEDOWN, actor=current_username(),
                          subject_type='enforcement_target', subject_id=target_id,
                          payload={'outcome': data.get('state'),
                                   'note': data.get('note')})
    return jsonify({'id': target_id, 'state': data.get('state').upper()})


@bp.route('/api/takedown/sweep', methods=['POST'])
@admin_required
@limiter.limit(SWEEP_RATE_LIMIT)
def api_sweep():
    return jsonify(takedown.sweep(limit=int((request.get_json(silent=True) or {})
                                            .get('limit', 60))))


# ── Resurrection ──────────────────────────────────────────────────────────

@bp.route('/api/resurrection/events')
@admin_required
@limiter.limit(POLLING_RATE_LIMIT)
def api_resurrection_events():
    return jsonify({
        'events': resurrection.recent_events(
            unacknowledged_only=request.args.get('unacknowledged') == '1',
            min_confidence=float(request.args.get('min_confidence', 0)),
        ),
        'stats': resurrection.stats(),
        'dormant_campaigns': resurrection.dormant_campaigns(),
    })


@bp.route('/api/resurrection/detect', methods=['POST'])
@admin_required
def api_detect_resurrections():
    data = request.get_json(silent=True) or {}
    events = resurrection.detect(
        dormancy_days=int(data.get('dormancy_days', resurrection.DORMANCY_DAYS)))
    return jsonify({
        'detected': len(events),
        'events': events,
        'stats': resurrection.stats(),
    })


@bp.route('/api/resurrection/event/<int:event_id>/acknowledge', methods=['POST'])
@admin_required
def api_acknowledge(event_id):
    data = request.get_json(silent=True) or {}
    if not resurrection.acknowledge(event_id, note=data.get('note')):
        return jsonify({'error': 'event not found'}), 404
    evidence.append_event(evidence.EV_ADMIN, actor=current_username(),
                          subject_type='resurrection_event', subject_id=event_id,
                          payload={'action': 'ACKNOWLEDGED'})
    return jsonify({'id': event_id, 'acknowledged': True})


@bp.route('/api/resurrection/churn')
@admin_required
def api_churn():
    """Which infrastructure an operation replaces, and which it cannot."""
    campaign_id = request.args.get('campaign_id', type=int)
    anchor_id = request.args.get('anchor_id', type=int)
    if not campaign_id and not anchor_id:
        return jsonify({'error': 'campaign_id or anchor_id is required'}), 400
    return jsonify(resurrection.churn_profile(campaign_id=campaign_id,
                                              anchor_id=anchor_id))


@bp.route('/api/resurrection/timeline/<int:campaign_id>')
@admin_required
def api_campaign_timeline(campaign_id):
    return jsonify(resurrection.campaign_timeline(campaign_id))


# ── Combined lifecycle summary ────────────────────────────────────────────

@bp.route('/api/summary')
@admin_required
@limiter.limit(POLLING_RATE_LIMIT)
def api_summary():
    """
    The three stages in one payload, for the dashboard header.

    Carries feed health alongside the counts, so a zero cannot be read as
    "nothing happening" when it actually means "the feed is down".
    """
    ct = ctlog.stats()
    return jsonify({
        'appearing': {
            'observations': ct['observations'],
            'actionable': ct['actionable'],
            'resolving': ct['resolving'],
            'today': ct['today'],
            'brands': ct['brands_watched'],
            'degraded': ct['health']['discovery_degraded'],
            'health_note': ct['health']['note'],
        },
        'disappearing': takedown.effectiveness(),
        'returning': resurrection.stats(),
    })
