"""
blueprints/intel.py
-------------------
Routes for the intelligence layer: entity graph, case files, campaigns,
enforcement action packs, lookalike-domain monitoring and public evidence
verification.

Access model
------------
Everything under /intel requires a session. The entity graph aggregates data
from every user's scans, so with one exception it is admin-only: a standard
user seeing the full graph would see indicators extracted from other users'
submissions, which is the same leak that /geo/api/map-data was fixed for.

Standard users get the subgraph reachable from their own scans, computed by
filtering sightings to their own scan ids.

The single unauthenticated route is /verify/<hash>, which is deliberately
public — a report is only verifiable if the person holding it can check it
without an account. It discloses existence, integrity and classification, and
nothing else.
"""

from __future__ import annotations

from flask import (
    Blueprint, request, jsonify, render_template, session, Response, url_for
)

from blueprints.auth import login_required, admin_required, current_username
from extensions import limiter, POLLING_RATE_LIMIT
from services.intel import (graph, campaigns, actions, lookalike, evidence,
                            feedback, notifications)
from services.intel.indicators import extract_all, KIND_LABELS
from services.auth_db import get_scan, get_user_scans

bp = Blueprint('intel', __name__, url_prefix='/intel')

# Lookalike sweeps make outbound DNS queries, so they are rate-limited well
# below the general polling allowance.
LOOKALIKE_RATE_LIMIT = "30 per hour"


def _is_admin():
    return session.get('user_role') == 'admin'


def _user_scan_ids():
    """Scan ids belonging to the current user, for subgraph scoping."""
    scans = get_user_scans(session.get('user_id'), 'user', 'all')
    return {s['id'] for s in scans}


def _visible_entity(entity_id):
    """
    Whether the current user may see this entity.

    Admins see everything. A standard user sees an entity only if at least one
    of its sightings came from one of their own scans.
    """
    if _is_admin():
        return True
    own = _user_scan_ids()
    if not own:
        return False
    for s in graph.entity_sightings(entity_id, limit=500):
        if s.get('scan_id') in own:
            return True
    return False


# -- Pages -----------------------------------------------------------------

@bp.route('/')
@login_required
def index():
    """Intelligence overview: graph stats, top entities, campaigns."""
    return render_template('intel/index.html', active_page='intel')


@bp.route('/graph')
@login_required
def graph_page():
    return render_template('intel/graph.html', active_page='intel')


@bp.route('/cases')
@login_required
def cases_page():
    return render_template('intel/cases.html', active_page='intel')


@bp.route('/campaigns')
@login_required
def campaigns_page():
    return render_template('intel/campaigns.html', active_page='intel')


@bp.route('/lookalike')
@login_required
def lookalike_page():
    return render_template('intel/lookalike.html', active_page='intel',
                           watchlist=lookalike.DEFAULT_WATCHLIST)


# -- Graph API -------------------------------------------------------------

@bp.route('/api/stats')
@limiter.limit(POLLING_RATE_LIMIT)
@login_required
def api_stats():
    try:
        stats = graph.graph_stats()
        stats['scoped'] = 'global' if _is_admin() else 'own'
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e), 'entities': 0, 'edges': 0}), 200


@bp.route('/api/search')
@login_required
def api_search():
    query = (request.args.get('q') or '').strip()
    if len(query) < 2:
        return jsonify({'results': [], 'error': 'Query must be at least 2 characters.'}), 400

    results = graph.search_entities(query, limit=40)
    if not _is_admin():
        results = [r for r in results if _visible_entity(r['id'])]
    return jsonify({'results': results, 'count': len(results)})


@bp.route('/api/entity/<int:entity_id>')
@login_required
def api_entity(entity_id):
    entity = graph.get_entity_by_id(entity_id)
    if not entity:
        return jsonify({'error': 'Entity not found.'}), 404
    if not _visible_entity(entity_id):
        return jsonify({'error': 'Not authorised to view this entity.'}), 403

    entity['sightings_detail'] = graph.entity_sightings(entity_id, limit=50)
    entity['campaign'] = campaigns.campaign_for_entity(entity_id)
    return jsonify(entity)


@bp.route('/api/entity/<int:entity_id>/graph')
@login_required
def api_entity_graph(entity_id):
    if not _visible_entity(entity_id):
        return jsonify({'error': 'Not authorised to view this entity.'}), 403

    try:
        depth = max(1, min(3, int(request.args.get('depth', 2))))
    except (TypeError, ValueError):
        depth = 2

    data = graph.neighbourhood(entity_id, depth=depth)
    if not data.get('root'):
        return jsonify({'error': 'Entity not found.'}), 404

    data['kind_labels'] = KIND_LABELS
    return jsonify(data)


@bp.route('/api/top')
@login_required
@admin_required
def api_top():
    kind = request.args.get('kind') or None
    return jsonify({'entities': graph.top_entities(kind=kind, limit=25)})


@bp.route('/api/extract', methods=['POST'])
@login_required
def api_extract():
    """
    Extract indicators from arbitrary text without storing anything.

    Used by the paste-and-inspect box in the UI and by the browser extension.
    Deliberately does not write to the graph: a user pasting text to check it
    should not silently create entities.
    """
    data = request.get_json(silent=True) or {}
    text = str(data.get('text') or '')
    if not text.strip():
        return jsonify({'error': 'text is required'}), 400
    if len(text) > 100_000:
        return jsonify({'error': 'text exceeds 100,000 characters'}), 413

    indicators = [i.to_dict() for i in extract_all(text)]
    return jsonify({
        'indicators': indicators,
        'count': len(indicators),
        'stored': False,
    })


# -- Cases -----------------------------------------------------------------

@bp.route('/api/cases', methods=['GET'])
@login_required
def api_list_cases():
    status = request.args.get('status') or None
    return jsonify({'cases': graph.list_cases(status=status)})


@bp.route('/api/cases', methods=['POST'])
@login_required
def api_create_case():
    data = request.get_json(silent=True) or {}
    title = str(data.get('title') or '').strip()
    if not title:
        return jsonify({'error': 'title is required'}), 400

    entity_ids = data.get('entity_ids') or []
    scan_ids = data.get('scan_ids') or []
    if not isinstance(entity_ids, list) or not isinstance(scan_ids, list):
        return jsonify({'error': 'entity_ids and scan_ids must be arrays'}), 400

    # A standard user may only file entities they can already see.
    if not _is_admin():
        entity_ids = [e for e in entity_ids if _visible_entity(e)]

    result = graph.create_case(
        title=title,
        created_by=session.get('user_id'),
        created_by_name=current_username(),
        severity=str(data.get('severity') or 'MEDIUM'),
        summary=data.get('summary'),
        entity_ids=entity_ids,
        scan_ids=scan_ids,
    )

    evidence.append_event(
        evidence.EV_CASE_CREATE, actor=current_username(),
        subject_type='case', subject_id=result['id'],
        payload={'title': title, 'entities': len(entity_ids), 'scans': len(scan_ids)},
    )
    return jsonify({'success': True, **result})


@bp.route('/api/cases/<int:case_id>', methods=['GET'])
@login_required
def api_get_case(case_id):
    case = graph.get_case(case_id)
    if not case:
        return jsonify({'error': 'Case not found.'}), 404
    return jsonify(case)


@bp.route('/api/cases/<int:case_id>', methods=['PATCH'])
@login_required
def api_update_case(case_id):
    data = request.get_json(silent=True) or {}
    status = data.get('status')
    if status and status not in ('OPEN', 'IN_PROGRESS', 'ESCALATED', 'CLOSED'):
        return jsonify({'error': 'invalid status'}), 400
    severity = data.get('severity')
    if severity and severity not in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'):
        return jsonify({'error': 'invalid severity'}), 400

    changed = graph.update_case(
        case_id, status=status, severity=severity,
        assigned_to=data.get('assigned_to'), summary=data.get('summary'),
    )
    if not changed:
        return jsonify({'error': 'Nothing to update or case not found.'}), 400

    evidence.append_event(
        evidence.EV_CASE_UPDATE, actor=current_username(),
        subject_type='case', subject_id=case_id,
        payload={k: v for k, v in data.items() if v is not None},
    )
    return jsonify({'success': True})


@bp.route('/api/cases/<int:case_id>/entities', methods=['POST'])
@login_required
def api_add_case_entities(case_id):
    data = request.get_json(silent=True) or {}
    entity_ids = data.get('entity_ids') or []
    scan_ids = data.get('scan_ids') or []
    if not isinstance(entity_ids, list) or not isinstance(scan_ids, list):
        return jsonify({'error': 'entity_ids and scan_ids must be arrays'}), 400
    if not _is_admin():
        entity_ids = [e for e in entity_ids if _visible_entity(e)]

    added = graph.add_to_case(case_id, entity_ids=entity_ids, scan_ids=scan_ids,
                              added_by=current_username())
    return jsonify({'success': True, 'added': added})


# -- Campaigns -------------------------------------------------------------

def _with_exposure(campaigns_list):
    """
    Attach reported loss to each campaign.

    Campaigns were ranked by indicator count, so thirty cheap posters
    outranked one operation draining lakhs. Money is the ordering an
    investigator actually needs.
    """
    try:
        from services.intel import harm
        for c in campaigns_list:
            c['exposure'] = harm.campaign_exposure(c['id'])
    except Exception as e:
        # Exposure is an enrichment; a campaign list must still render if the
        # harm tables are absent on an older database.
        print("[INTEL] campaign exposure unavailable: %s" % e)
    return campaigns_list


@bp.route('/api/campaigns')
@login_required
def api_campaigns():
    return jsonify({'campaigns': _with_exposure(campaigns.list_campaigns(limit=50))})


@bp.route('/api/campaigns/<int:campaign_id>')
@login_required
def api_campaign(campaign_id):
    camp = campaigns.get_campaign(campaign_id)
    if not camp:
        return jsonify({'error': 'Campaign not found.'}), 404
    return jsonify(camp)


@bp.route('/api/campaigns/rebuild', methods=['POST'])
@admin_required
def api_rebuild_campaigns():
    """
    Recompute all campaigns. Admin-only: it is a full-table operation and it
    replaces every existing cluster.
    """
    result = campaigns.rebuild_campaigns()
    evidence.append_event(
        evidence.EV_ADMIN, actor=current_username(),
        subject_type='campaigns', subject_id='rebuild', payload=result,
    )
    return jsonify({'success': True, **result})


@bp.route('/api/campaigns/duplicates')
@login_required
@admin_required
def api_duplicates():
    """Near-duplicate creative clusters across recent scans."""
    return jsonify({'groups': campaigns.find_near_duplicate_scans()})


# -- Enforcement action pack ----------------------------------------------

def _pack_for_scan(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        return None, None

    # Prefer indicators extracted at scan time; fall back to re-extracting from
    # the stored summary so older scans, written before the intelligence layer
    # existed, still produce an action pack.
    stored = scan.get('indicators') or {}
    indicators = []
    if isinstance(stored, dict) and stored.get('extracted'):
        indicators = stored['extracted']
    else:
        indicators = [i.to_dict() for i in extract_all(scan.get('input_summary') or '')]

    context = {
        'scan_id': scan_id,
        'module': scan.get('module'),
        'verdict': scan.get('verdict'),
        'score': scan.get('score'),
        'file_hash': scan.get('file_hash'),
    }
    return actions.build_action_pack(indicators, context), context


@bp.route('/api/scan/<int:scan_id>/actions')
@login_required
def api_scan_actions(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({'error': 'Scan not found.'}), 404
    if not _is_admin() and scan.get('user_id') != session.get('user_id'):
        return jsonify({'error': 'Not authorised to view this scan.'}), 403

    pack, context = _pack_for_scan(scan_id)
    if pack is None:
        return jsonify({'error': 'Scan not found.'}), 404

    evidence.append_event(
        evidence.EV_ACTION_PACK, actor=current_username(),
        subject_type='scan', subject_id=scan_id,
        artefact_hash=scan.get('file_hash'),
        payload={'channels': pack['summary']['channels']},
    )
    return jsonify({'pack': pack, 'context': context})


@bp.route('/api/scan/<int:scan_id>/actions/dispatch', methods=['POST'])
@login_required
def api_dispatch_actions(scan_id):
    """
    Record that an action pack has been filed, and start the outcome clock.

    Deliberately separate from GET .../actions, which only renders the drafts.
    Generating a notice and filing one are different acts, and conflating them
    would start a takedown timer every time an analyst previewed a pack —
    producing a median-time-to-takedown measured from the wrong moment and an
    enforcement record full of notices nobody sent.

    This does not transmit anything. The platform produces drafts an authorised
    officer signs and sends through the proper channel; this records that they
    did, so the outcome can be measured.
    """
    from services.intel import takedown

    scan = get_scan(scan_id)
    if not scan:
        return jsonify({'error': 'Scan not found.'}), 404
    if not _is_admin() and scan.get('user_id') != session.get('user_id'):
        return jsonify({'error': 'Not authorised to view this scan.'}), 403

    pack, context = _pack_for_scan(scan_id)
    if pack is None:
        return jsonify({'error': 'Scan not found.'}), 404

    data = request.get_json(silent=True) or {}
    only = {c.upper() for c in (data.get('channels') or [])}
    if only:
        pack = dict(pack, actions=[a for a in pack['actions']
                                   if (a.get('channel') or '').upper() in only])

    registered = takedown.register_action_pack(
        pack, scan_id=scan_id, case_id=data.get('case_id'),
        filed_by=current_username())

    probeable = [r for r in registered if r['probeable']]
    manual = [r for r in registered if not r['probeable']]

    evidence.append_event(
        evidence.EV_TAKEDOWN, actor=current_username(),
        subject_type='scan', subject_id=scan_id,
        artefact_hash=scan.get('file_hash'),
        payload={'action': 'DISPATCHED',
                 'channels': [a['channel'] for a in pack['actions']],
                 'targets': len(registered)},
    )

    return jsonify({
        'scan_id': scan_id,
        'registered': registered,
        'tracked_automatically': len(probeable),
        'awaiting_manual_outcome': len(manual),
        'note': (
            '%d target(s) will be probed automatically. %d cannot be checked '
            'from outside — payment rails, phone numbers and platform accounts '
            'have no public liveness endpoint — and stay UNKNOWN until an '
            'analyst records what the authority did.'
            % (len(probeable), len(manual))
        ),
    })
@bp.route('/api/scan/<int:scan_id>/actions/html')
@login_required
def api_scan_actions_html(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({'error': 'Scan not found.'}), 404
    if not _is_admin() and scan.get('user_id') != session.get('user_id'):
        return jsonify({'error': 'Not authorised to view this scan.'}), 403

    pack, context = _pack_for_scan(scan_id)
    html = actions.render_pack_html(pack, context)
    return Response(html, mimetype='text/html')


@bp.route('/api/scan/<int:scan_id>/actions/<channel>.txt')
@login_required
def api_scan_action_text(scan_id, channel):
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({'error': 'Scan not found.'}), 404
    if not _is_admin() and scan.get('user_id') != session.get('user_id'):
        return jsonify({'error': 'Not authorised to view this scan.'}), 403

    pack, context = _pack_for_scan(scan_id)
    for action in pack['actions']:
        if action['channel'].lower() == channel.lower():
            body = actions.render_action_text(action, context)
            return Response(body, mimetype='text/plain; charset=utf-8')
    return jsonify({'error': 'No such channel in this action pack.'}), 404


# -- Lookalike domains -----------------------------------------------------

@bp.route('/api/lookalike', methods=['POST'])
@limiter.limit(LOOKALIKE_RATE_LIMIT)
@login_required
def api_lookalike():
    data = request.get_json(silent=True) or {}
    domain = str(data.get('domain') or '').strip().lower()
    if not domain or '.' not in domain:
        return jsonify({'error': 'A valid domain is required.'}), 400
    if len(domain) > 253:
        return jsonify({'error': 'Domain is too long.'}), 400

    live_check = bool(data.get('check_live', True))
    if not live_check:
        candidates = lookalike.generate(domain)
        return jsonify({
            'brand_domain': domain, 'generated': len(candidates),
            'candidates': candidates, 'live': [], 'live_count': 0,
            'checked': 0,
        })

    result = lookalike.scan_brand(domain, resolve_limit=120)
    return jsonify(result)


# -- Evidence chain --------------------------------------------------------

@bp.route('/api/evidence/head')
@login_required
def api_evidence_head():
    return jsonify(evidence.head())


@bp.route('/api/evidence/verify')
@admin_required
def api_evidence_verify():
    return jsonify(evidence.verify_chain())


@bp.route('/api/evidence/recent')
@admin_required
def api_evidence_recent():
    return jsonify({'entries': evidence.recent_entries(limit=100)})


# ── My Work ───────────────────────────────────────────────────────────────
#
# `cases.assigned_to` existed in the schema and update_case() accepted it, but
# nothing ever wrote it and nothing ever read it. A case system where work
# cannot be handed to a person is a filing cabinet, not a workflow.

@bp.route('/my-work')
@login_required
def my_work_page():
    return render_template('intel/my_work.html', active_page='intel')


@bp.route('/api/my-work')
@login_required
@limiter.limit(POLLING_RATE_LIMIT)
def api_my_work():
    """
    Everything currently sitting with the caller.

    Deliberately one endpoint rather than four: the question a person opens
    this page to answer is "what do I need to do", and splitting that across
    separate requests makes the page assemble the answer instead of receiving
    it.
    """
    me = current_username()
    my_id = session.get('user_id')

    assigned = [c for c in graph.list_cases(limit=500)
                if c.get('assigned_to') == me and c.get('status') != 'CLOSED']
    created = [c for c in graph.list_cases(limit=500)
               if c.get('created_by') == my_id
               and c.get('assigned_to') != me
               and c.get('status') != 'CLOSED']

    # Corrections this analyst filed that a second reviewer has not yet
    # adjudicated. Their own opinion is not a label until somebody else agrees.
    pending_feedback = [f for f in feedback.queue(status=feedback.STATUS_PENDING,
                                                  limit=200)
                        if f.get('reviewer') == me]

    # Enforcement this analyst filed that is still reachable, or has no
    # recorded outcome. The unprobeable ones are the actionable list: nobody
    # else is going to record what the bank did.
    try:
        from services.intel import takedown
        mine = [t for t in takedown.list_targets(limit=500)
                if t.get('filed_by') == me]
        awaiting = [t for t in mine if t.get('state') in ('UNKNOWN', 'FILED')
                    and not t.get('probeable')]
        still_live = [t for t in mine if t.get('state') == 'LIVE']
        resurfaced = [t for t in mine if t.get('state') == 'RESURFACED']
    except Exception:
        awaiting, still_live, resurfaced = [], [], []

    return jsonify({
        'assigned_cases': assigned,
        'my_cases': created,
        'pending_feedback': pending_feedback,
        'awaiting_outcome': awaiting,
        'still_live': still_live,
        'resurfaced': resurfaced,
        'counts': {
            'assigned': len(assigned),
            'created': len(created),
            'feedback': len(pending_feedback),
            'awaiting_outcome': len(awaiting),
            'still_live': len(still_live),
            'resurfaced': len(resurfaced),
        },
    })


@bp.route('/api/assignees')
@login_required
def api_assignees():
    """
    Who a case can be handed to.

    Usernames only. This is a picker, not a directory — it deliberately does
    not expose roles, creation dates or anything else about other accounts.
    """
    from services.auth_db import get_all_users
    return jsonify({'assignees': sorted(u['username'] for u in get_all_users())})


@bp.route('/api/cases/<int:case_id>/assign', methods=['POST'])
@login_required
def api_assign_case(case_id):
    """
    Hand a case to somebody, or take it yourself.

    Assigning notifies the recipient — a handoff nobody is told about is not a
    handoff. Assigning to yourself does not, because you already know.
    """
    data = request.get_json(silent=True) or {}
    assignee = (data.get('assignee') or '').strip() or None

    case = graph.get_case(case_id)
    if not case:
        return jsonify({'error': 'case not found'}), 404

    if assignee:
        from services.auth_db import get_all_users
        if assignee not in {u['username'] for u in get_all_users()}:
            return jsonify({'error': 'no such user'}), 400

    graph.update_case(case_id, assigned_to=assignee)

    if assignee:
        notifications.case_assigned(case, assignee, current_username())

    evidence.append_event(
        evidence.EV_CASE_UPDATE, actor=current_username(),
        subject_type='case', subject_id=case_id,
        payload={'action': 'ASSIGNED', 'assignee': assignee},
    )
    return jsonify({
        'case_id': case_id,
        'assigned_to': assignee,
        'message': ('Assigned to %s.' % assignee) if assignee else 'Assignment cleared.',
    })
# -- Analyst feedback loop -------------------------------------------------
#
# The one place in the platform where a human tells the system it was wrong.
# Everything downstream -- the confusion matrix on the admin dashboard, the
# calibration sets that eventually make `calibrated: true` honest, the
# retraining corpus -- is built from these rows.

@bp.route('/api/feedback', methods=['POST'])
@login_required
def api_submit_feedback():
    """Record the current analyst's assessment of a verdict."""
    data = request.get_json(silent=True) or {}

    scan_id = data.get('scan_id')
    label = (data.get('label') or '').upper().strip()
    module = (data.get('module') or '').strip()

    if not module:
        return jsonify({'error': 'module is required'}), 400
    if label not in feedback.VALID_LABELS:
        return jsonify({
            'error': 'label must be one of: %s' % ', '.join(sorted(feedback.VALID_LABELS))
        }), 400

    # A user may only give feedback on a scan they can see. Without this check
    # the endpoint would let any account attribute an opinion to any other
    # account's scan, which poisons every metric computed from these rows.
    scan = get_scan(scan_id) if scan_id else None
    if scan_id and not scan:
        return jsonify({'error': 'scan not found'}), 404
    if scan and not _is_admin() and scan.get('user_id') != session.get('user_id'):
        return jsonify({'error': 'not your scan'}), 403

    fb_id, err = feedback.submit(
        scan_id=scan_id,
        module=module,
        label=label,
        system_verdict=data.get('system_verdict') or (scan or {}).get('verdict'),
        system_score=(data.get('system_score')
                      if data.get('system_score') is not None
                      else (scan or {}).get('score')),
        corrected_verdict=data.get('corrected_verdict'),
        note=(data.get('note') or '')[:1000] or None,
        reviewer=current_username(),
        reviewer_id=session.get('user_id'),
        artefact_hash=data.get('file_hash') or (scan or {}).get('file_hash'),
        artefact_text=data.get('text') or (scan or {}).get('input_summary'),
    )
    if err:
        return jsonify({'error': err}), 400

    evidence.append_event(
        evidence.EV_FEEDBACK, actor=current_username(),
        subject_type='scan', subject_id=scan_id,
        artefact_hash=data.get('file_hash') or (scan or {}).get('file_hash'),
        payload={'label': label, 'module': module,
                 'corrected_verdict': data.get('corrected_verdict')},
    )

    notifications.review_waiting(
        {'id': fb_id, 'reviewer': current_username(), 'module': module,
         'label': label},
        actor=current_username())

    return jsonify({
        'id': fb_id,
        'status': feedback.STATUS_PENDING,
        'message': (
            "Recorded. One analyst's correction is an opinion, not a label - "
            "it becomes training data once a second analyst confirms it."
        ),
    })


@bp.route('/api/feedback/scan/<int:scan_id>')
@login_required
def api_feedback_for_scan(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({'error': 'scan not found'}), 404
    if not _is_admin() and scan.get('user_id') != session.get('user_id'):
        return jsonify({'error': 'not your scan'}), 403
    return jsonify({'feedback': feedback.for_scan(scan_id)})


@bp.route('/api/feedback/queue')
@admin_required
def api_feedback_queue():
    status = request.args.get('status', feedback.STATUS_PENDING).upper()
    if status == 'ALL':
        status = None
    return jsonify({
        'queue': feedback.queue(status=status,
                                module=request.args.get('module') or None),
        'summary': feedback.summary(),
    })


@bp.route('/api/feedback/<int:feedback_id>/review', methods=['POST'])
@admin_required
def api_review_feedback(feedback_id):
    """
    Adjudicate a pending correction.

    The reviewer must not be its author. A correction that confirms itself
    carries exactly as much evidential weight as the original opinion, and
    treating it as a second signal would silently double-count one person.
    """
    data = request.get_json(silent=True) or {}
    status = (data.get('status') or '').upper().strip()

    row = feedback.get(feedback_id)
    if not row:
        return jsonify({'error': 'feedback not found'}), 404
    if row.get('reviewer_id') == session.get('user_id'):
        return jsonify({
            'error': 'A correction cannot be confirmed by the analyst who '
                     'made it. Another reviewer must adjudicate.'
        }), 403

    ok, err = feedback.review(feedback_id, status, reviewer=current_username())
    if not ok:
        return jsonify({'error': err or 'update failed'}), 400

    notifications.feedback_reviewed(row, status, current_username())

    evidence.append_event(
        evidence.EV_ADMIN, actor=current_username(),
        subject_type='feedback', subject_id=feedback_id,
        payload={'action': 'REVIEW', 'status': status},
    )
    return jsonify({'id': feedback_id, 'status': status})


@bp.route('/api/feedback/metrics')
@admin_required
def api_feedback_metrics():
    return jsonify(feedback.metrics(module=request.args.get('module') or None))


@bp.route('/api/feedback/export')
@admin_required
def api_feedback_export():
    """Confirmed corrections as labelled training rows."""
    module = request.args.get('module') or None
    rows = feedback.training_export(module=module)
    return jsonify({
        'module': module or 'all',
        'count': len(rows),
        'rows': rows,
        'note': (
            'Only corrections confirmed by a second analyst are exported. '
            'Append these to the module training corpus and retrain; they are '
            'not applied automatically, because a retrain that nobody chose '
            'is a model change nobody reviewed.'
        ),
    })


@bp.route('/api/feedback/calibrate/<module>', methods=['POST'])
@admin_required
def api_fit_calibrator(module):
    """
    Fit a calibrator for one module from its confirmed feedback.

    This is the step that turns `calibrated: false` into `calibrated: true`
    in every assessment banner - and it deliberately refuses to run on a
    sample too small to mean anything.
    """
    from services.intel import calibration

    samples = feedback.calibration_samples(module)
    if len(samples) < calibration.MIN_CALIBRATION_SAMPLES:
        return jsonify({
            'error': 'Not enough confirmed feedback to calibrate %s: %d '
                     'samples, %d required.'
                     % (module, len(samples), calibration.MIN_CALIBRATION_SAMPLES),
            'samples': len(samples),
        }), 400

    scores = [s for s, _ in samples]
    labels = [l for _, l in samples]

    model = calibration.fit_histogram(scores, labels)
    report = calibration.reliability_report(scores, labels, model)
    calibration.save_calibrator(module, model)
    calibration.load_calibrator(module, use_cache=False)

    evidence.append_event(
        evidence.EV_ADMIN, actor=current_username(),
        subject_type='calibration', subject_id=module,
        payload={'method': model.get('method'), 'n': model.get('n'),
                 'ece': report.get('ece_after')},
    )
    return jsonify({'module': module, 'model': model, 'evaluation': report})


@bp.route('/feedback')
@admin_required
def feedback_queue_page():
    return render_template('intel/feedback.html', active_page='intel')


# ── Section 63(4) certificate and statutory clocks ────────────────────────
#
# The bridge from a tamper-evident record to an admissible one. See
# services/intel/certificate.py for why the platform drafts but never signs.

@bp.route('/api/scan/<int:scan_id>/certificate')
@login_required
def api_certificate(scan_id):
    """The certificate content as JSON, including why it could not be issued."""
    from services.intel import certificate

    scan = get_scan(scan_id)
    if not scan:
        return jsonify({'error': 'Scan not found.'}), 404
    if not _is_admin() and scan.get('user_id') != session.get('user_id'):
        return jsonify({'error': 'Not authorised to view this scan.'}), 403

    data = certificate.build_certificate(scan_id, base_url=request.host_url.rstrip('/'))
    if not data:
        return jsonify({'error': 'Scan not found.'}), 404

    certifiable, reason = certificate.is_certifiable(scan_id)
    return jsonify({'certificate': data,
                    'certifiable': certifiable,
                    'blocked_because': reason})


@bp.route('/api/scan/<int:scan_id>/certificate.pdf')
@login_required
def api_certificate_pdf(scan_id):
    """
    The drafted certificate as a PDF.

    Produced even when it could not honestly be issued: the reasons are
    printed on its face. An officer who asks for a certificate that cannot be
    given should see why, in the form they asked for, rather than a bare error.
    """
    import io as _io
    from flask import send_file
    from services.certificate_generator import generate_certificate_pdf

    scan = get_scan(scan_id)
    if not scan:
        return jsonify({'error': 'Scan not found.'}), 404
    if not _is_admin() and scan.get('user_id') != session.get('user_id'):
        return jsonify({'error': 'Not authorised to view this scan.'}), 403

    pdf = generate_certificate_pdf(scan_id, base_url=request.host_url.rstrip('/'))
    if pdf is None:
        return jsonify({'error': 'Scan not found.'}), 404

    evidence.append_event(
        evidence.EV_REPORT, actor=current_username(),
        subject_type='scan', subject_id=scan_id,
        artefact_hash=scan.get('file_hash'),
        payload={'action': 'BSA_63_CERTIFICATE_DRAFTED'},
    )

    return send_file(_io.BytesIO(pdf), mimetype='application/pdf',
                     as_attachment=True,
                     download_name='CYBERSURAKSHAA_s63_certificate_draft_%04d.pdf' % scan_id)


@bp.route('/api/clocks/summary')
@admin_required
def api_clock_summary():
    """Live statutory-compliance position across recorded losses."""
    from services.intel import clocks
    return jsonify(clocks.summary())


@bp.route('/api/report/<int:report_id>/clocks')
@login_required
def api_report_clocks(report_id):
    """
    Every deadline running on one reported loss.

    The RBI liability band is the one that matters to the person: it decides
    whether they bear the loss, and it turns on when they told their bank.
    """
    from services.intel import clocks, harm

    report = harm.get_report(report_id)
    if not report:
        return jsonify({'error': 'report not found'}), 404
    return jsonify(clocks.for_victim_report(report))
