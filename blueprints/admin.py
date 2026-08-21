import os
import sqlite3
from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash, session
from blueprints.auth import admin_required
from services.auth_db import get_all_users, update_user_role, delete_user, get_user_scans

bp = Blueprint('admin', __name__, url_prefix='/admin')

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Same env override as 'fake customer carer/database.py' — the two must agree
# on where the shield database lives, or the admin dashboard reads a different
# file from the one the detector writes.
SHIELD_DB_PATH = os.environ.get(
    'SHIELD_DB_PATH',
    os.path.join(BASE_DIR, 'fake customer carer', 'shield.db')
)

# ── Database Helpers ──────────────────────────────────────────

def get_indicators():
    """Retrieve all reported threat indicators from customer care shield database."""
    if not os.path.exists(SHIELD_DB_PATH):
        return []
    try:
        conn = sqlite3.connect(SHIELD_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM indicators ORDER BY reports DESC")
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return rows
    except Exception as e:
        print(f"[ADMIN ERROR] Failed to fetch threat indicators: {e}")
        return []

def delete_indicator(ind_id):
    """
    Delete a flagged scam indicator.

    Returns whether a row was actually removed. Returning True unconditionally
    made the UI report success for ids that do not exist.
    """
    if not os.path.exists(SHIELD_DB_PATH):
        return False
    try:
        conn = sqlite3.connect(SHIELD_DB_PATH, timeout=15)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM indicators WHERE id = ?", (ind_id,))
        conn.commit()
        deleted = cursor.rowcount
        conn.close()
        return deleted > 0
    except Exception as e:
        print(f"[ADMIN ERROR] Failed to delete indicator: {e}")
        return False

# ── Admin Dashboard Routes ────────────────────────────────────

@bp.route('/dashboard')
@admin_required
def dashboard():
    users = get_all_users()
    indicators = get_indicators()
    
    # Fetch global scans for auditing (since admin is logged in, get_user_scans returns all scans)
    scans = get_user_scans(session['user_id'], 'admin', filter_type='all')
    
    return render_template(
        'admin/dashboard.html',
        users=users,
        indicators=indicators,
        scans=scans,
        active_page='admin'
    )

def _would_remove_last_admin(user_id):
    """
    True if acting on user_id would leave the system with no administrator.

    Only self-actions were blocked before, so one admin could demote or delete
    the other and lock everyone out of the admin dashboard permanently.
    """
    admins = [u for u in get_all_users() if u.get('role') == 'admin']
    return len(admins) <= 1 and any(u['id'] == user_id for u in admins)


@bp.route('/user/<int:user_id>/role', methods=['POST'])
@admin_required
def change_role(user_id):
    new_role = request.form.get('role', '').strip()
    if new_role not in ('user', 'admin'):
        return jsonify({'error': "Role must be either 'user' or 'admin'."}), 400

    # Prevent self-demotion
    if user_id == session['user_id']:
        return jsonify({'error': 'You cannot modify your own administrator role.'}), 400

    if new_role != 'admin' and _would_remove_last_admin(user_id):
        return jsonify({'error': 'Cannot demote the last remaining administrator.'}), 400

    success = update_user_role(user_id, new_role)
    if success:
        return jsonify({'success': True})
    return jsonify({'error': 'Failed to update role. The user may no longer exist.'}), 404

@bp.route('/user/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user_route(user_id):
    # Prevent self-deletion
    if user_id == session['user_id']:
        return jsonify({'error': 'You cannot delete your own administrator account.'}), 400

    if _would_remove_last_admin(user_id):
        return jsonify({'error': 'Cannot delete the last remaining administrator.'}), 400

    success = delete_user(user_id)
    if success:
        return jsonify({'success': True})
    return jsonify({'error': 'Failed to delete user. The user may no longer exist.'}), 404

@bp.route('/indicator/<int:ind_id>/delete', methods=['POST'])
@admin_required
def delete_indicator_route(ind_id):
    success = delete_indicator(ind_id)
    if success:
        return jsonify({'success': True})
    return jsonify({'error': 'Failed to delete threat indicator.'}), 500


# ── Audit log ─────────────────────────────────────────────────
#
# The evidence chain has recorded every scan, report, dispatch, case change,
# correction and administrative action since it was built, and verify_chain()
# has always been able to prove the record intact. There was no way to look at
# any of it. An audit trail nobody can read is a compliance artefact rather
# than an oversight mechanism.

@bp.route('/audit')
@admin_required
def audit_log():
    return render_template('admin/audit.html', active_page='admin')


@bp.route('/api/audit')
@admin_required
def api_audit():
    """
    Recent chain entries, with the chain's own integrity alongside them.

    The verification result travels with the entries deliberately. A log
    rendered without it invites the reader to trust what they are seeing, and
    the entire point of a hash chain is that trust should be conditional on a
    check that has actually run.
    """
    from services.intel import evidence

    limit = min(int(request.args.get('limit', 100)), 500)
    event = (request.args.get('event') or '').strip().upper()
    actor = (request.args.get('actor') or '').strip()

    entries = evidence.recent_entries(limit=500)
    if event:
        entries = [e for e in entries if (e.get('event') or '').upper() == event]
    if actor:
        entries = [e for e in entries if (e.get('actor') or '') == actor]

    chain = evidence.verify_chain()

    # A broken chain is not a page-rendering detail. Whoever can act on it is
    # told, once, rather than only finding out if they happen to visit.
    if not chain.get('valid'):
        try:
            from services.intel import notifications
            notifications.chain_broken(chain)
        except Exception as e:
            print("[ADMIN] could not raise chain-break notification: %s" % e)

    return jsonify({
        'entries': entries[:limit],
        'total_matching': len(entries),
        'chain': chain,
        'head': evidence.head(),
        'event_types': sorted({e.get('event') for e in evidence.recent_entries(limit=500)
                               if e.get('event')}),
        'actors': sorted({e.get('actor') for e in evidence.recent_entries(limit=500)
                          if e.get('actor')}),
        'caveat': (
            'This is a hash chain, not a signature. It proves the log is '
            'internally consistent and that no entry was altered in place. It '
            'cannot prove the log was never rewritten end to end by someone '
            'with write access to the whole table — publishing the head hash '
            'externally is what converts that into a guarantee.'
        ),
    })


@bp.route('/api/audit/verify', methods=['POST'])
@admin_required
def api_verify_chain():
    from services.intel import evidence
    result = evidence.verify_chain()
    if not result.get('valid'):
        try:
            from services.intel import notifications
            notifications.chain_broken(result)
        except Exception:
            pass
    return jsonify(result)
