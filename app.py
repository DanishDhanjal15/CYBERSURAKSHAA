"""
CYBERSURAKSHAA — All-in-One Detection Suite
======================================
Unified Flask application combining 4 detection models:
  1. Betting Content Detector (OCR + YOLO + NLP)
  2. Deepfake Detector (EfficientNet B4 + MTCNN)
  3. Fake Customer Care Scam Detector (PaddleOCR + spaCy NER)
  4. Investment Scam Detector (ScamGuard AI)

Run with:
    python app.py

Then open http://127.0.0.1:5000 in your browser.

Deployment:
    Set SECRET_KEY environment variable for persistent sessions.
    Set PORT environment variable for custom port (default: 5000).
    Gunicorn: gunicorn app:app --bind 0.0.0.0:$PORT --timeout 120 --workers 1
"""

import os
import secrets

# Load .env BEFORE anything reads os.environ.
#
# Flask calls load_dotenv() itself, but only from inside app.run() -- long
# after this module has already read SECRET_KEY, FLASK_ENV and everything
# else, and not at all under gunicorn. The result was a .env file that looked
# configured and was entirely ignored: sessions ran on an ephemeral key, and
# FLASK_ENV=production in .env left IS_PRODUCTION False, so the "missing
# SECRET_KEY is fatal in production" guard below could never fire -- exactly
# the silent degradation it exists to prevent.
#
# encoding="utf-8" is explicit because python-dotenv defaults to it and aborts
# on a file saved in the Windows ANSI codepage; a single em dash in a comment
# is enough to take startup down.
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'),
                encoding='utf-8')
except ImportError:
    # python-dotenv is optional. Real deployments inject environment variables
    # directly, and its absence must not stop the app from booting.
    pass
except (UnicodeDecodeError, OSError) as e:
    print("[WARN] Could not read .env (%s). Falling back to the process "
          "environment. If you expected values from .env, re-save it as UTF-8."
          % e)

from flask import (Flask, render_template, jsonify, request, session,
                   redirect, url_for, flash)

IS_PRODUCTION = os.environ.get('FLASK_ENV', 'development') == 'production'

# ── Create Flask App ─────────────────────────────────────────
app = Flask(__name__)

# Apply ProxyFix middleware so Flask correctly interprets headers forwarded
# by reverse proxies / SSL terminators (such as Cloudflare Tunnels). This ensures
# url_for builds correct https:// URLs and respect secure session cookies.
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# ── Secret Key ────────────────────────────────────────────────
# In production a missing SECRET_KEY is fatal rather than silently degrading:
# an ephemeral key means every restart or redeploy invalidates all sessions
# and logs every user out, which is easy to miss until it happens in front of
# real users.
_secret = os.environ.get('SECRET_KEY')
if not _secret:
    if IS_PRODUCTION:
        raise RuntimeError(
            "SECRET_KEY environment variable must be set when FLASK_ENV=production. "
            "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    _secret = secrets.token_hex(32)
    print("[WARN] No SECRET_KEY set — using an ephemeral development key. "
          "Sessions will not survive a restart.")
app.secret_key = _secret

app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500 MB

# ── Session cookie hardening ──────────────────────────────────
# SameSite=Lax stops the session cookie riding along on cross-site POSTs,
# which is the main delivery route for CSRF against the admin endpoints.
#
# Secure defaults to on in production and can be turned off explicitly. A
# Secure cookie is never sent back over plain HTTP, so with FLASK_ENV=production
# on an http:// origin the session is dropped between rendering the login form
# and submitting it — the CSRF token then fails to validate and login returns
# 400 with no way through. That is the right behaviour for a real deployment
# and a hard block for a local container on http://localhost, so the two are
# separated rather than both keyed off FLASK_ENV.
#
# Only set this to 0 when the origin genuinely is not HTTPS. Over HTTPS it must
# stay on: without it the session cookie will also travel over any plain-HTTP
# request to the same host, where it can be read off the wire.
_secure_cookie_env = os.environ.get('SESSION_COOKIE_SECURE')
if _secure_cookie_env is None:
    _secure_cookie = IS_PRODUCTION
else:
    _secure_cookie = _secure_cookie_env.strip().lower() in ('1', 'true', 'yes', 'on')

if IS_PRODUCTION and not _secure_cookie:
    print("[WARN] SESSION_COOKIE_SECURE is disabled in production — the session "
          "cookie will be sent over plain HTTP. Only do this behind a trusted "
          "local proxy or for local testing.")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=_secure_cookie,
)

# ── CSRF protection ───────────────────────────────────────────
# Flask-WTF is optional at runtime so a missing dependency degrades to a loud
# warning instead of a failed boot, but it should be installed — without it
# /admin/user/<id>/delete and friends are reachable cross-site.
try:
    from flask_wtf.csrf import CSRFProtect, generate_csrf
    csrf = CSRFProtect(app)
    app.config['WTF_CSRF_TIME_LIMIT'] = None   # tie token lifetime to the session
    _csrf_enabled = True
except ImportError:
    csrf = None
    generate_csrf = None
    _csrf_enabled = False
    print("[WARN] flask-wtf is not installed — CSRF protection is DISABLED. "
          "Install it with: pip install flask-wtf")


@app.context_processor
def inject_csrf_token():
    """Expose csrf_token() to templates whether or not Flask-WTF is present."""
    if _csrf_enabled:
        return {'csrf_token': generate_csrf}
    return {'csrf_token': lambda: ''}

# ── Running behind a reverse proxy ────────────────────────────
# Every real deployment of this app sits behind something that terminates TLS
# and forwards the request: a Cloudflare tunnel, a Hugging Face Space, a
# Render router, an nginx in front of a VPS. To Flask, all of those look like
# a single client — the proxy — because the socket's peer address IS the
# proxy.
#
# That breaks two things at once, and the first is severe:
#
#   1. Rate limiting collapses. flask-limiter keys on the remote address, so
#      EVERY visitor shares one bucket. The default 300/hour is then a limit
#      on the whole world rather than per person: a handful of people browsing
#      at the same time 429s all of them. This was observed live — the tunnel
#      started returning 429 to everyone.
#   2. Session records and audit entries log the proxy's IP, so "which device
#      was this signed in from" answers the same address for everybody.
#
# ProxyFix reads X-Forwarded-For / -Proto / -Host and restores the real
# client. It is OFF by default and must be enabled explicitly, because
# trusting those headers when NOT behind a proxy is an IP-spoofing hole —
# anyone could set X-Forwarded-For and evade a rate limit or forge an audit
# entry. `x_for=1` trusts exactly one hop: the proxy directly in front of us.
_trust_proxy = os.environ.get('TRUST_PROXY_HEADERS')
if _trust_proxy is None:
    # Sensible default: production is behind a proxy, local development is not.
    _trust_proxy_enabled = IS_PRODUCTION
else:
    _trust_proxy_enabled = _trust_proxy.strip().lower() in ('1', 'true', 'yes', 'on')

if _trust_proxy_enabled:
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
    print("[PROXY] Trusting one hop of X-Forwarded-* headers. "
          "Only correct when a proxy really is in front of this process.")

# ── Rate Limiting ─────────────────────────────────────────────
# Protects all routes from brute-force and abuse. Configured in extensions.py
# so blueprints can attach per-route limits without importing this module.
from extensions import limiter
limiter.init_app(app)


def wants_json_response():
    """
    True when the caller expects JSON rather than an HTML page.

    Checking accept_json and not accept_html is not enough: browser fetch()
    sends "Accept: */*", which matches both, so genuine API calls were served
    HTML error pages and blew up in resp.json().
    """
    if request.path.startswith(('/auth/api/', '/geo/api/', '/customer-care/api/')):
        return True
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return True
    if request.is_json:
        return True
    return (request.accept_mimetypes.accept_json
            and not request.accept_mimetypes.accept_html)


# ── Custom 429 handler ────────────────────────────────────────
@app.errorhandler(429)
def ratelimit_handler(e):
    """Return a JSON error for API calls, HTML for browser requests."""
    if wants_json_response():
        return jsonify(error="Rate limit exceeded. Please slow down.",
                       retry_after=str(getattr(e, 'retry_after', ''))), 429
    return render_template('429.html'), 429


# ── CSRF failure handler ──────────────────────────────────────
if _csrf_enabled:
    from flask_wtf.csrf import CSRFError

    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        if wants_json_response():
            return jsonify(error="CSRF token missing or invalid. Please reload the page."), 400
        return render_template('429.html'), 400

# Ensure upload directory exists
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Initialize auth database at startup
from services.auth_db import init_db
init_db()

# Initialize the intelligence layer: entity graph, campaigns, cases, and the
# tamper-evident evidence chain. Both are idempotent CREATE TABLE IF NOT EXISTS
# migrations and must run after init_db(), which owns the `scans` table they
# reference.
from services.intel.graph import init_graph_db
from services.intel.evidence import init_evidence_db
from services.intel.feedback import init_feedback_db
from services.intel.ctlog import init_ctlog_db, seed_watchlist
from services.intel.takedown import init_takedown_db
from services.intel.resurrection import init_resurrection_db
from services.intel.accounts import init_accounts_db
from services.intel.notifications import init_notifications_db
from services.intel.harm import init_harm_db
from blueprints.public_api import init_api_db
init_graph_db()
init_evidence_db()
init_feedback_db()
init_api_db()
init_ctlog_db()
init_takedown_db()
init_resurrection_db()
init_accounts_db()
init_notifications_db()
init_harm_db()
seed_watchlist()

# Start background threat crawler.
# Gated behind an env flag: this module runs once per gunicorn worker, so with
# more than one worker every process would run its own crawler, multiplying the
# outbound scraping and racing to write the same alerts. Set ENABLE_CRAWLER=0
# on all but one worker (or run the crawler as a separate process).
if os.environ.get('ENABLE_CRAWLER', '1') == '1':
    from services.threat_crawler import start_crawler
    start_crawler(app)
else:
    print("[CRAWLER] Disabled via ENABLE_CRAWLER=0.")

# ── Register Blueprints ──────────────────────────────────────
# Each blueprint is imported and registered independently so that a single
# import failure (e.g. during a hot-reload race) never prevents the remaining
# blueprints — including qr_scan — from being registered.

def _register(import_path, alias=None):
    """Import a blueprint module and register it. Logs and continues on error."""
    try:
        import importlib
        mod = importlib.import_module(import_path)
        bp_obj = getattr(mod, 'bp')
        app.register_blueprint(bp_obj)
        return bp_obj
    except Exception as _exc:
        print(f"[WARN] Blueprint '{import_path}' failed to load: {_exc}")
        return None

from blueprints.auth import bp as auth_bp, login_required
app.register_blueprint(auth_bp)

_register('blueprints.admin')
_register('blueprints.betting')
_register('blueprints.deepfake')
_register('blueprints.customer_care')
_register('blueprints.investment')
_register('blueprints.geo_intel')
_register('blueprints.intel')
_register('blueprints.voice')
_register('blueprints.apk_scan')
_register('blueprints.verify')
_register('blueprints.watchtower')
_register('blueprints.account')
_register('blueprints.harm_report')
_register('blueprints.qr_scan')
_register('blueprints.citizen')
_register('blueprints.nfc_scan')

# public_api needs its own ref for CSRF exemption below
from blueprints.public_api import bp as public_api_bp
app.register_blueprint(public_api_bp)

# Keep named refs for citizen/qr for CSRF exemption (graceful fallback if missing)
try:
    from blueprints.citizen import bp as citizen_bp
except Exception:
    citizen_bp = None
try:
    from blueprints.qr_scan import bp as qr_bp
except Exception:
    qr_bp = None

# The public API is exempt from CSRF, and deliberately so. CSRF protection
# defends a *cookie-authenticated* session against a request the user did not
# intend; this blueprint has no session, authenticates on an X-API-Key header
# a browser will never attach automatically, and is called by a Chrome
# extension and a Telegram bot that cannot obtain a CSRF token. Leaving it
# protected would simply mean it never works.
if _csrf_enabled:
    csrf.exempt(public_api_bp)
    # Same reasoning for the citizen quick-check endpoints: they carry no
    # session, so there is no ambient credential for a forged request to ride.
    if citizen_bp is not None:
        csrf.exempt(citizen_bp)

# ── Model warm-up ─────────────────────────────────────────────
# Every detector loads its models lazily behind a lock, so the first request
# after a restart pays tens of seconds of PaddleOCR / EfficientNet / MTCNN
# initialisation. Loading them in a background thread at boot moves that cost
# off the first user's request. Disable with WARM_UP_MODELS=0 on a host where
# holding every model resident at once would exhaust memory.
from services.intel.ops import warm_up, health_report, readiness, impact_metrics, result_cache
warm_up()

# ── Lifecycle monitors ────────────────────────────────────────────────
# Certificate Transparency polling and takedown-outcome probing both make
# outbound requests on a timer. Off by default: they contact third-party
# services (crt.sh, Cert Spotter) and re-probe reported domains, and a
# developer running this locally should opt into that rather than discover it
# in their egress logs. Enable with WATCHTOWER_MONITORS=1.
if os.environ.get('WATCHTOWER_MONITORS', '0') == '1':
    from services.intel.ctlog import start_poller as _start_ct
    from services.intel.takedown import start_sweeper as _start_sweeper
    _start_ct()
    _start_sweeper()
else:
    print("[WATCHTOWER] Background monitors disabled. "
          "Set WATCHTOWER_MONITORS=1 to enable CT polling and takedown probing.")

# ── Auth Context Processor ──────────────────────────────────

def _unread_badge():
    """
    Unread notification count for the navigation bell.

    Swallows failures: the notification table may not exist yet on a partially
    initialised database, and a missing badge must not take down every page
    that extends base.html.
    """
    if 'user_id' not in session:
        return 0
    try:
        from services.intel import notifications
        return notifications.unread_count(session.get('username'))
    except Exception:
        return 0

@app.context_processor
def inject_auth():
    from flask import session
    return {
        'is_logged_in': 'user_id' in session,
        'current_username': session.get('username'),
        'current_role': session.get('user_role'),
        'is_admin': session.get('user_role') == 'admin',
        # Rendered as the bell badge in base.html. Computed per request rather
        # than polled, so a freshly-loaded page is never stale.
        'unread_notifications': _unread_badge(),
    }


# ── Landing Page ─────────────────────────────────────────────
@app.route('/')
@login_required
def home():
    return render_template('index.html', active_page='home')


@app.route('/round2')
@login_required
def round2():
    """
    The business-and-resilience view: monetisation, scalability, adaptability
    and feasibility, each answered with live figures from this deployment
    rather than with a slide. Includes the emergency-posture demonstration
    inline, so the whole argument fits on one screen without navigating away.
    """
    return render_template('round2.html', active_page='round2')


@app.route('/tv')
@login_required
def tv_mode():
    """
    Command-centre wall display: a full-screen, self-refreshing dashboard
    meant for a projector or wall monitor. It renders no controls — every
    figure comes from the same authenticated APIs the console already uses.
    """
    return render_template('tv.html')


# ── Health & operational endpoints ───────────────────────────
# Unauthenticated by design: a health probe that needs a session cannot be used
# by a container healthcheck or a load balancer. They expose no scan content
# and no user data — only whether the process and its models are functioning.
@app.route('/healthz')
@limiter.exempt
def healthz():
    """Liveness: the process is up and its database is reachable."""
    report = health_report(deep=False)
    code = 200 if report['status'] in ('ok', 'degraded') else 503
    return jsonify(report), code


@app.route('/readyz')
@limiter.exempt
def readyz():
    """Readiness: every model has finished loading."""
    state = readiness()
    return jsonify(state), (200 if state['ready'] else 503)


@app.route('/api/impact')
@login_required
def api_impact():
    """
    Real, database-derived impact counters for the dashboard.

    Replaces the previous front-end figures, which added invented baselines
    (124 threats, 1842 known scam numbers) to the real counts.
    """
    metrics = impact_metrics()
    metrics['cache'] = result_cache.stats()
    return jsonify(metrics)



# ── Session enforcement ──────────────────────────────────────
#
# A signed cookie proves the server issued it; it says nothing about whether
# the session is still supposed to exist. Without a server-side check, a
# cookie copied off a compromised machine stays valid until SECRET_KEY
# changes, "sign out everywhere" is a lie, and an administrator cannot end a
# session they know is hostile.
#
# This runs on every request and costs one indexed lookup. The activity write
# is throttled to once a minute inside touch_session().

# Endpoints reachable without a live session. Matched on Flask's endpoint name
# rather than the path, so a URL prefix change cannot silently open a hole.
_SESSION_EXEMPT_ENDPOINTS = {
    'static',
    'auth.login', 'auth.logout', 'auth.register',
    'verify.verify_index', 'verify.verify_hash',
    'citizen.index', 'citizen.check_text', 'citizen.check_qr',
    'healthz', 'readyz',
}

# Whole blueprints that authenticate by their own mechanism.
_SESSION_EXEMPT_PREFIXES = ('public_api.',)


@app.before_request
def _enforce_session():
    endpoint = request.endpoint or ''
    if endpoint in _SESSION_EXEMPT_ENDPOINTS:
        return None
    if endpoint.startswith(_SESSION_EXEMPT_PREFIXES):
        return None
    if 'user_id' not in session:
        return None      # anonymous; the route's own decorator decides

    from services.intel import accounts

    token = session.get('session_token')
    live = accounts.touch_session(token, ip=request.remote_addr) if token else None

    if live:
        return None

    # Either the session was revoked, it timed out, or the cookie predates
    # server-side sessions entirely. All three mean the same thing to this
    # request: it is not authenticated. Legacy cookies are deliberately not
    # grandfathered — accepting them would preserve exactly the unrevocable
    # sessions this exists to eliminate.
    session.clear()

    # `in`, not `startswith`. Every blueprint mounts its API under its own
    # prefix -- /account/api/…, /intel/api/…, /watchtower/api/… -- so a
    # startswith check only caught the handful at the root. The rest were
    # handed a 302 to an HTML login page, which a fetch() then tried to parse
    # as JSON and failed on in a way that looks nothing like "signed out".
    if wants_json_response() or '/api/' in request.path:
        return jsonify(error='Session ended. Please sign in again.'), 401

    flash('Your session has ended. Please sign in again.', 'warning')
    return redirect(url_for('auth.login'))

# ── Error Handlers ───────────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    """
    Render a dedicated 404 page.

    This used to render index.html directly, which bypassed the @login_required
    on the home route — any unauthenticated request to a bad URL was served the
    full authenticated dashboard markup.
    """
    if wants_json_response():
        return jsonify(error='Not found'), 404
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    return render_template('404.html', active_page='home'), 404


@app.errorhandler(413)
def too_large(e):
    return jsonify(error='File too large. Maximum size is 500MB.'), 413


# ── Run ──────────────────────────────────────────────────────
if __name__ == '__main__':
    # Read PORT from environment (set by Railway/Render/Cloud Run automatically)
    port = int(os.environ.get('PORT', 5000))
    # In production (FLASK_ENV=production), debug is disabled automatically
    is_debug = os.environ.get('FLASK_ENV', 'development') == 'development'
    host = '127.0.0.1' if is_debug else '0.0.0.0'

    print("=" * 60)
    print("  CYBERSURAKSHAA — All-in-One Detection Suite")
    print(f"  http://{host}:{port}")
    print(f"  Debug: {is_debug} | Host: {host}")
    print("=" * 60)
    # use_reloader=False prevents the watchdog from restarting the server
    # when ML libraries (cv2, torch, timm) modify config files during import.
    app.run(debug=is_debug, host=host, port=port, use_reloader=False)
