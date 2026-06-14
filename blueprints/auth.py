from functools import wraps
from flask import Blueprint, request, jsonify, render_template, redirect, url_for, session, flash, send_file
import io
from services.auth_db import verify_user, create_user, save_scan, get_user_scans, delete_scan, clear_user_scans, get_scan
from services.report_generator import generate_pdf_report, generate_html_report

bp = Blueprint('auth', __name__, url_prefix='/auth')

# ── Route protection decorators ───────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            # If it's an AJAX/JSON request, return 401 instead of redirecting
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.path.startswith('/auth/api/'):
                return jsonify({'error': 'Unauthorized. Please login.'}), 401
            flash('Please log in to access CYBERSURAKSHAA.', 'warning')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.path.startswith('/auth/api/'):
                return jsonify({'error': 'Unauthorized. Please login.'}), 401
            return redirect(url_for('auth.login'))
        if session.get('user_role') != 'admin':
            flash('Access denied. Administrator privileges required.', 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

# ── Authentication Routes ─────────────────────────────────────

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash('Please fill in all fields.', 'danger')
            return render_template('auth/login.html')

        user = verify_user(username, password)
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['user_role'] = user['role']
            flash(f"Welcome back, {user['username']}!", 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('auth/login.html')

@bp.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not username or not password or not confirm_password:
            flash('Please fill in all fields.', 'danger')
            return render_template('auth/register.html')

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('auth/register.html')

        if len(password) < 6:
            flash('Password must be at least 6 characters.', 'danger')
            return render_template('auth/register.html')

        success = create_user(username, password, role="user")
        if success:
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('auth.login'))
        else:
            flash('Username is already taken.', 'danger')

    return render_template('auth/register.html')

@bp.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))

# ── Scan History API Sync Routes ──────────────────────────────

@bp.route('/api/scans', methods=['GET'])
@login_required
def api_get_scans():
    filter_type = request.args.get('filter', 'all')
    user_id = session['user_id']
    user_role = session['user_role']
    
    scans = get_user_scans(user_id, user_role, filter_type)
    return jsonify(scans)

@bp.route('/api/scans', methods=['POST'])
@login_required
def api_save_scan():
    data = request.get_json(silent=True) or {}
    module = data.get('module')
    input_summary = data.get('input')
    verdict = data.get('verdict')
    score = data.get('score', 0)
    reasons = data.get('reasons', [])
    
    # CTI report extra metadata
    file_hash = data.get('file_hash')
    indicators = data.get('indicators')
    recommendation = data.get('recommendation')
    
    if not module or not verdict:
        return jsonify({'error': 'Missing required fields'}), 400
        
    user_id = session['user_id']
    username = session['username']
    
    scan_id = save_scan(
        user_id, username, module, input_summary, verdict, score, reasons,
        file_hash=file_hash, indicators=indicators, recommendation=recommendation
    )
    return jsonify({'success': True, 'id': scan_id})

@bp.route('/api/scans/<int:scan_id>/pdf', methods=['GET'])
@login_required
def api_get_scan_pdf(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({'error': 'Scan record not found'}), 404
        
    user_id = session['user_id']
    user_role = session['user_role']
    if user_role != 'admin' and scan['user_id'] != user_id:
        return jsonify({'error': 'Unauthorized to access this threat report'}), 403
        
    try:
        pdf_bytes = generate_pdf_report(scan)
        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f"CYBERSURAKSHAA_CTI_Report_CS-CTI-2026-{scan_id:04d}.pdf"
        )
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': f"Failed to generate PDF threat report: {e}"}), 500

@bp.route('/api/scans/<int:scan_id>/html', methods=['GET'])
@login_required
def api_get_scan_html(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        return "Scan record not found", 404
        
    user_id = session['user_id']
    user_role = session['user_role']
    if user_role != 'admin' and scan['user_id'] != user_id:
        return "Unauthorized to access this threat report", 403
        
    try:
        html_content = generate_html_report(scan)
        return html_content
    except Exception as e:
        import traceback
        traceback.print_exc()
        return f"Failed to generate HTML threat report: {e}", 500

@bp.route('/api/scans/<int:scan_id>', methods=['DELETE'])
@login_required
def api_delete_scan(scan_id):
    user_id = session['user_id']
    user_role = session['user_role']
    
    success = delete_scan(scan_id, user_id, user_role)
    if success:
        return jsonify({'success': True})
    return jsonify({'error': 'Failed to delete or unauthorized'}), 403

@bp.route('/api/scans', methods=['DELETE'])
@login_required
def api_clear_scans():
    user_id = session['user_id']
    user_role = session['user_role']
    
    clear_user_scans(user_id, user_role)
    return jsonify({'success': True})
