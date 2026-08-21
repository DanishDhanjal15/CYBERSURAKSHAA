from functools import wraps
from flask import Blueprint, request, jsonify, render_template, redirect, url_for, session, flash, send_file
import io
from services.auth_db import verify_user, create_user, save_scan, get_user_scans, delete_scan, clear_user_scans, get_scan, get_latest_alerts, get_alert, block_alert
from services.report_generator import generate_pdf_report, generate_html_report
from services.takedown_generator import generate_takedown_pdf, generate_takedown_html
from extensions import limiter, POLLING_RATE_LIMIT, AUTH_RATE_LIMIT

bp = Blueprint('auth', __name__, url_prefix='/auth')


def current_role():
    """
    Role of the logged-in user, defaulting to the least privileged value.

    Read with .get(): a session carrying user_id but no user_role — an older
    cookie, or one written before the role was added — raised KeyError and
    turned every API call into a 500.
    """
    return session.get('user_role', 'user')


def current_username():
    """
    Username of the logged-in user, read with .get() for the same reason as
    current_role(): a session carrying user_id but no username raised KeyError
    and turned the write endpoints into 500s.
    """
    return session.get('username', 'unknown')

# ── Route protection decorators ───────────────────────────────
def _wants_json():
    """
    Whether this caller expects JSON rather than an HTML page.

    Kept in one place because the same judgement is made by both decorators
    and by the session guard in app.py, and they drifted apart once already.
    """
    return (request.headers.get('X-Requested-With') == 'XMLHttpRequest'
            or '/api/' in request.path)




def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            # JSON callers get 401, not a redirect to an HTML page they will
            # try to parse. `'/api/' in path`, not startswith: every blueprint
            # mounts its API under its own prefix -- /intel/api/…,
            # /account/api/…, /watchtower/api/… -- so the original check only
            # covered the handful under /auth/.
            if _wants_json():
                return jsonify({'error': 'Unauthorized. Please login.'}), 401
            flash('Please log in to access CYBERSURAKSHAA.', 'warning')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            if _wants_json():
                return jsonify({'error': 'Unauthorized. Please login.'}), 401
            return redirect(url_for('auth.login'))
        if current_role() != 'admin':
            if _wants_json():
                return jsonify({'error': 'Administrator privileges required.'}), 403
            flash('Access denied. Administrator privileges required.', 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

# ── Authentication Routes ─────────────────────────────────────

@bp.route('/login', methods=['GET', 'POST'])
@limiter.limit(AUTH_RATE_LIMIT, methods=['POST'])
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

            # Server-side session record. A signed cookie alone cannot be
            # revoked -- one copied off a compromised machine stays valid
            # until the secret key changes, and nothing can see it or stop
            # it. The token here is checked on every request, so revoking
            # the row ends that session wherever it is.
            from services.intel import accounts
            session['session_token'] = accounts.start_session(
                user['id'], user['username'],
                user_agent=request.headers.get('User-Agent'),
                ip=request.remote_addr,
            )

            if accounts.must_change_password(user['id']):
                flash('An administrator reset your password. Choose a new one '
                      'before continuing.', 'warning')
                return redirect(url_for('account.change_password_page'))

            flash(f"Welcome back, {user['username']}!", 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('auth/login.html')

@bp.route('/register', methods=['GET', 'POST'])
@limiter.limit(AUTH_RATE_LIMIT, methods=['POST'])
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

@bp.route('/logout', methods=['GET', 'POST'])
def logout():
    """
    End the session.

    POST is what the interface uses, and it carries a CSRF token. A GET logout
    can be triggered by any page that merely references the URL -- an <img
    src> is enough -- which lets a third party sign a user out without their
    involvement. Harmless compared to most CSRF, but pointless to leave open
    when the fix is a form.

    GET is still accepted so existing bookmarks and links keep working.
    """
    # Revoke the server-side record too. Clearing the cookie only ends the
    # session in the browser doing the clicking; the row is what makes it
    # dead everywhere.
    try:
        from services.intel import accounts
        accounts.revoke_by_token(session.get('session_token'),
                                 revoked_by=session.get('username'),
                                 reason='signed out')
    except Exception as e:
        print("[AUTH] could not revoke session record: %s" % e)

    session.clear()
    flash('You have been signed out.', 'success')
    return redirect(url_for('auth.login'))

# ── Scan History API Sync Routes ──────────────────────────────

@bp.route('/api/scans', methods=['GET'])
@limiter.limit(POLLING_RATE_LIMIT)
@login_required
def api_get_scans():
    filter_type = request.args.get('filter', 'all')
    user_id = session['user_id']
    user_role = current_role()
    
    scans = get_user_scans(user_id, user_role, filter_type)
    return jsonify(scans)

@bp.route('/api/scans', methods=['POST'])
@login_required
def api_save_scan():
    data = request.get_json(silent=True) or {}
    module = data.get('module')
    # Coerced to a string: input_summary is NOT NULL in the schema, so a request
    # that omitted "input" raised IntegrityError and returned a 500 rather than
    # a 400. Same for a non-string value reaching len() in the report builders.
    input_summary = '' if data.get('input') is None else str(data.get('input'))
    verdict = data.get('verdict')
    reasons = data.get('reasons', [])
    if not isinstance(reasons, list):
        reasons = [str(reasons)]

    # CTI report extra metadata
    file_hash = data.get('file_hash')
    indicators = data.get('indicators')
    recommendation = data.get('recommendation')

    if not module or not verdict:
        return jsonify({'error': 'Missing required fields'}), 400
    module = str(module)
    verdict = str(verdict)

    # save_scan() does int(score); a non-numeric value blew up there as a 500.
    try:
        score = int(float(data.get('score') or 0))
    except (TypeError, ValueError):
        return jsonify({'error': "'score' must be a number."}), 400

    user_id = session['user_id']
    username = current_username()


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
    user_role = current_role()
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
    user_role = current_role()
    if user_role != 'admin' and scan['user_id'] != user_id:
        return "Unauthorized to access this threat report", 403
        
    try:
        html_content = generate_html_report(scan)
        return html_content
    except Exception as e:
        import traceback
        traceback.print_exc()
        return f"Failed to generate HTML threat report: {e}", 500

@bp.route('/api/scans/<int:scan_id>/takedown/pdf', methods=['GET'])
@login_required
def api_get_takedown_pdf(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({'error': 'Scan record not found'}), 404
        
    user_id = session['user_id']
    user_role = current_role()
    if user_role != 'admin' and scan['user_id'] != user_id:
        return jsonify({'error': 'Unauthorized to access this compliance notice'}), 403
        
    try:
        pdf_bytes = generate_takedown_pdf(scan)
        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f"CYBERSURAKSHAA_ITAct79_Takedown_Notice_CS-TDR-2026-{scan_id:04d}.pdf"
        )
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': f"Failed to generate PDF takedown notice: {e}"}), 500

@bp.route('/api/scans/<int:scan_id>/takedown/html', methods=['GET'])
@login_required
def api_get_takedown_html(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        return "Scan record not found", 404
        
    user_id = session['user_id']
    user_role = current_role()
    if user_role != 'admin' and scan['user_id'] != user_id:
        return "Unauthorized to access this compliance notice", 403
        
    try:
        html_content = generate_takedown_html(scan)
        return html_content
    except Exception as e:
        import traceback
        traceback.print_exc()
        return f"Failed to generate HTML takedown notice: {e}", 500

@bp.route('/api/scans/<int:scan_id>', methods=['DELETE'])
@login_required
def api_delete_scan(scan_id):
    user_id = session['user_id']
    user_role = current_role()
    
    success = delete_scan(scan_id, user_id, user_role)
    if success:
        return jsonify({'success': True})
    return jsonify({'error': 'Failed to delete or unauthorized'}), 403

@bp.route('/api/scans', methods=['DELETE'])
@login_required
def api_clear_scans():
    user_id = session['user_id']
    user_role = current_role()
    
    clear_user_scans(user_id, user_role)
    return jsonify({'success': True})

# ── Live Crawler Threat Feed Endpoints ─────────────────────────

@bp.route('/api/alerts', methods=['GET'])
@limiter.limit(POLLING_RATE_LIMIT)
@login_required
def api_get_alerts():
    """Retrieve all active crawled threat alerts. Polled by the dashboard."""
    try:
        alerts = get_latest_alerts(limit=15)
        return jsonify(alerts)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/api/alerts/<int:alert_id>/block', methods=['POST'])
@login_required
def api_block_alert(alert_id):
    """Block an alert and auto-generate its takedown notice scan record."""
    user_id = session['user_id']
    username = current_username()

    alert = get_alert(alert_id)
    if not alert:
        return jsonify({'error': 'Alert record not found'}), 404
        
    try:
        # Mark alert as BLOCKED in crawler database feed
        block_alert(alert_id)
        
        # Calculate SHA-256 cryptographic hash of the URL to represent file_hash/indicator
        import hashlib
        url_hash = hashlib.sha256(alert['url'].encode('utf-8')).hexdigest()
        
        # Construct verdict based on alert category
        verdict = 'DANGER'
        cat = alert['category'].upper()
        if 'BETTING' in cat:
            verdict = 'BETTING'
        elif 'FAKE' in cat or 'DEEPFAKE' in cat:
            verdict = 'FAKE'
        elif 'SCAM' in cat or 'INVESTMENT' in cat:
            verdict = 'SCAM'
            
        reasons = [
            "Proactive Threat Intelligence Crawler Detection",
            f"Source URL/Handle: {alert['url']}",
            f"Intel Swept: {alert['content']}",
            f"Swept Channel/Feed: {alert['source']}"
        ]
        
        recommendation = (
            f"RECOMMENDATION: Section 79(3)(b) of the Information Technology Act, 2000 blocking compliance order issued. "
            f"The crawler identified hosting node '{alert['url']}' with high risk profile ({alert['risk_score']}%). "
            f"Intermediaries are legally required to disable access and sinkhole domain lookup records."
        )
        
        indicators = {
            "crawled_source": alert['source'],
            "crawled_url": alert['url'],
            "alert_id": alert['id'],
            "original_risk_score": alert['risk_score']
        }
        
        # Save scan to history database
        scan_id = save_scan(
            user_id=user_id,
            username=username,
            module=alert['category'],
            input_summary=alert['content'],
            verdict=verdict,
            score=alert['risk_score'],
            reasons=reasons,
            file_hash=url_hash,
            indicators=indicators,
            recommendation=recommendation
        )
        
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'message': 'Alert blocked and compliance takedown notice queued.'
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': f"Failed to block alert and queue takedown: {e}"}), 500

