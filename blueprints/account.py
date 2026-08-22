"""
blueprints/account.py
---------------------
Self-service account management, and the notification queue.

Both belong to the person signed in rather than to a role, so everything here
is `@login_required` and scoped to the caller. There is deliberately no route
that lets one user read or alter another's account or notifications — the
scoping is in the query, not in a check that could be forgotten.
"""

from __future__ import annotations

from flask import (Blueprint, render_template, request, jsonify, session,
                   redirect, url_for, flash)

from blueprints.auth import login_required, current_username
from extensions import limiter, POLLING_RATE_LIMIT
from services.intel import accounts, notifications, evidence

bp = Blueprint('account', __name__, url_prefix='/account')

# Password endpoints are guessing surfaces even with the current password
# required, so they are limited well below the general allowance.
PASSWORD_RATE_LIMIT = "10 per hour"


# ── Pages ─────────────────────────────────────────────────────────────────

@bp.route('/')
@login_required
def index():
    return render_template('account/index.html', active_page='account')


# ── Profile and sessions ──────────────────────────────────────────────────

@bp.route('/api/overview')
@login_required
def api_overview():
    data = accounts.account_overview(session.get('user_id'),
                                     current_token=session.get('session_token'))
    if not data:
        return jsonify({'error': 'account not found'}), 404
    return jsonify(data)


@bp.route('/api/password', methods=['POST'])
@login_required
@limiter.limit(PASSWORD_RATE_LIMIT)
def api_change_password():
    """
    Rotate the caller's own password.

    The current password is required even though the caller is already
    authenticated: without it, anyone who obtained a session cookie could
    change the password and lock the real owner out permanently.
    """
    data = request.get_json(silent=True) or {}
    ok, reason, revoked = accounts.change_password(
        user_id=session.get('user_id'),
        current_password=data.get('current_password'),
        new_password=data.get('new_password'),
        current_token=session.get('session_token'),
        keep_other_sessions=bool(data.get('keep_other_sessions')),
    )
    if not ok:
        return jsonify({'error': reason}), 400

    evidence.append_event(
        evidence.EV_ADMIN, actor=current_username(),
        subject_type='account', subject_id=session.get('user_id'),
        payload={'action': 'PASSWORD_CHANGED', 'sessions_revoked': revoked},
    )
    return jsonify({
        'changed': True,
        'sessions_revoked': revoked,
        'message': (
            'Password updated. %d other session(s) were signed out.' % revoked
            if revoked else
            'Password updated. No other sessions were active.'
        ),
    })


@bp.route('/api/live-state')
@login_required
@limiter.limit(POLLING_RATE_LIMIT)
def api_live_state():
    """
    The caller's complete live state, computed at request time.

    Identity comes from the session, never from a parameter: there is no way
    to request another user's state, so no ownership check exists to forget.
    An admin gets their own state here like everyone else — other people's
    activity is the admin dashboard's job.
    """
    from services.user_state import live_state
    state = live_state(session.get('user_id'), current_username(),
                       session_token=session.get('session_token'))
    if state is None:
        return jsonify({'error': 'account not found'}), 404
    return jsonify(state)


@bp.route('/api/sessions')
@login_required
@limiter.limit(POLLING_RATE_LIMIT)
def api_sessions():
    token = session.get('session_token')
    return jsonify({'sessions': [
        accounts.describe_session(s, token)
        for s in accounts.list_sessions(session.get('user_id'))
    ]})


@bp.route('/api/sessions/<int:session_id>', methods=['DELETE'])
@login_required
def api_revoke_session(session_id):
    """
    End one of the caller's own sessions.

    Ownership is re-checked against the caller's session list rather than
    trusted from the id, so a guessed id cannot revoke somebody else's.
    """
    mine = {s['id'] for s in accounts.list_sessions(session.get('user_id'))}
    if session_id not in mine:
        return jsonify({'error': 'not your session'}), 403

    accounts.revoke_session(session_id, revoked_by=current_username(),
                            reason='signed out from account settings')
    evidence.append_event(
        evidence.EV_ADMIN, actor=current_username(),
        subject_type='session', subject_id=session_id,
        payload={'action': 'SESSION_REVOKED'},
    )
    return jsonify({'revoked': True, 'id': session_id})


@bp.route('/api/sessions/revoke-all', methods=['POST'])
@login_required
def api_revoke_all():
    """Sign out everywhere except here."""
    count = accounts.revoke_all(
        session.get('user_id'), except_token=session.get('session_token'),
        revoked_by=current_username(), reason='signed out everywhere')

    evidence.append_event(
        evidence.EV_ADMIN, actor=current_username(),
        subject_type='account', subject_id=session.get('user_id'),
        payload={'action': 'REVOKE_ALL_SESSIONS', 'count': count},
    )
    return jsonify({
        'revoked': count,
        'message': ('%d other session(s) signed out. This one is still active.'
                    % count) if count else 'No other sessions were active.',
    })


# ── Notifications ─────────────────────────────────────────────────────────

@bp.route('/api/notifications')
@login_required
@limiter.limit(POLLING_RATE_LIMIT)
def api_notifications():
    me = current_username()
    return jsonify({
        'notifications': notifications.for_user(
            me, unread_only=request.args.get('unread') == '1',
            limit=int(request.args.get('limit', 40))),
        'unread': notifications.unread_count(me),
    })


@bp.route('/api/notifications/count')
@login_required
@limiter.limit(POLLING_RATE_LIMIT)
def api_notification_count():
    """Just the badge number, for polling cheaply."""
    return jsonify({'unread': notifications.unread_count(current_username())})


@bp.route('/api/notifications/<int:notification_id>/read', methods=['POST'])
@login_required
def api_mark_read(notification_id):
    if not notifications.mark_read(notification_id, current_username()):
        return jsonify({'error': 'not found'}), 404
    return jsonify({'read': True, 'id': notification_id})


@bp.route('/api/notifications/read-all', methods=['POST'])
@login_required
def api_mark_all_read():
    return jsonify({'read': notifications.mark_all_read(current_username())})


# ── Forced password change ────────────────────────────────────────────────

@bp.route('/change-password', methods=['GET', 'POST'])
@login_required
@limiter.limit(PASSWORD_RATE_LIMIT, methods=['POST'])
def change_password_page():
    """
    Standalone page for an account an administrator has flagged.

    Separate from the settings page because a forced change happens before the
    user has done anything else, and dropping them into a full settings
    interface to find one field is the wrong shape for that moment.
    """
    user_id = session.get('user_id')

    if request.method == 'POST':
        ok, reason, revoked = accounts.change_password(
            user_id=user_id,
            current_password=request.form.get('current_password'),
            new_password=request.form.get('new_password'),
            current_token=session.get('session_token'),
        )
        if not ok:
            flash(reason, 'danger')
            return render_template('account/change_password.html',
                                   forced=accounts.must_change_password(user_id))

        evidence.append_event(
            evidence.EV_ADMIN, actor=current_username(),
            subject_type='account', subject_id=user_id,
            payload={'action': 'PASSWORD_CHANGED', 'forced': True},
        )
        flash('Password updated.', 'success')
        return redirect(url_for('home'))

    return render_template('account/change_password.html',
                           forced=accounts.must_change_password(user_id))
