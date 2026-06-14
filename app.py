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
"""

import os
import secrets
from flask import Flask, render_template

# ── Create Flask App ─────────────────────────────────────────
app = Flask(__name__)
app.secret_key = secrets.token_hex(24)
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500 MB

# Ensure upload directory exists
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Initialize auth database at startup
from services.auth_db import init_db
init_db()

# ── Register Blueprints ──────────────────────────────────────
from blueprints.auth import bp as auth_bp, login_required
from blueprints.admin import bp as admin_bp
from blueprints.betting import bp as betting_bp
from blueprints.deepfake import bp as deepfake_bp
from blueprints.customer_care import bp as customer_care_bp
from blueprints.investment import bp as investment_bp

app.register_blueprint(auth_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(betting_bp)
app.register_blueprint(deepfake_bp)
app.register_blueprint(customer_care_bp)
app.register_blueprint(investment_bp)

# ── Auth Context Processor ──────────────────────────────────
@app.context_processor
def inject_auth():
    from flask import session
    return {
        'is_logged_in': 'user_id' in session,
        'current_username': session.get('username'),
        'current_role': session.get('user_role'),
        'is_admin': session.get('user_role') == 'admin'
    }

# ── Landing Page ─────────────────────────────────────────────
@app.route('/')
@login_required
def home():
    return render_template('index.html', active_page='home')


# ── Error Handlers ───────────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    return render_template('index.html', active_page='home'), 404


@app.errorhandler(413)
def too_large(e):
    return {'error': 'File too large. Maximum size is 500MB.'}, 413


# ── Run ──────────────────────────────────────────────────────
if __name__ == '__main__':
    print("=" * 60)
    print("  CYBERSURAKSHAA — All-in-One Detection Suite")
    print("  http://127.0.0.1:5000")
    print("=" * 60)
    # use_reloader=False prevents the watchdog from restarting the server
    # when ML libraries (cv2, torch, timm) modify config files during import.
    app.run(debug=True, host='127.0.0.1', port=5000, use_reloader=False)
