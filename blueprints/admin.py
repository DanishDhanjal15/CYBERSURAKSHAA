import os
import sqlite3
from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash, session
from blueprints.auth import admin_required
from services.auth_db import get_all_users, update_user_role, delete_user, get_user_scans

bp = Blueprint('admin', __name__, url_prefix='/admin')

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHIELD_DB_PATH = os.path.join(BASE_DIR, 'fake customer carer', 'shield.db')

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
    """Delete a flagged scam indicator."""
    if not os.path.exists(SHIELD_DB_PATH):
        return False
    try:
        conn = sqlite3.connect(SHIELD_DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM indicators WHERE id = ?", (ind_id,))
        conn.commit()
        conn.close()
        return True
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

@bp.route('/user/<int:user_id>/role', methods=['POST'])
@admin_required
def change_role(user_id):
    new_role = request.form.get('role', '').strip()
    # Prevent self-demotion
    if user_id == session['user_id']:
        return jsonify({'error': 'You cannot modify your own administrator role.'}), 400
        
    success = update_user_role(user_id, new_role)
    if success:
        return jsonify({'success': True})
    return jsonify({'error': 'Failed to update role.'}), 500

@bp.route('/user/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user_route(user_id):
    # Prevent self-deletion
    if user_id == session['user_id']:
        return jsonify({'error': 'You cannot delete your own administrator account.'}), 400
        
    success = delete_user(user_id)
    if success:
        return jsonify({'success': True})
    return jsonify({'error': 'Failed to delete user.'}), 500

@bp.route('/indicator/<int:ind_id>/delete', methods=['POST'])
@admin_required
def delete_indicator_route(ind_id):
    success = delete_indicator(ind_id)
    if success:
        return jsonify({'success': True})
    return jsonify({'error': 'Failed to delete threat indicator.'}), 500
