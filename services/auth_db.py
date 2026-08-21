import os
import sqlite3
import json
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

DATABASE_PATH = os.environ.get(
    'DB_PATH',
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "cybersurakshaa.db")
)


def get_db_connection():
    # timeout: the crawler thread writes every 30s while requests read. Without
    # a wait the default 5s lock timeout surfaces as "database is locked".
    conn = sqlite3.connect(DATABASE_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    # WAL lets readers and a writer proceed concurrently instead of serialising
    # on one global lock.
    try:
        conn.execute("PRAGMA journal_mode=WAL")
    except sqlite3.Error:
        pass
    return conn

def init_db():
    """Create tables and seed admin/user credentials."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Create users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('user', 'admin')),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Create scans table (database-backed scan registry)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            timestamp TEXT NOT NULL,
            module TEXT NOT NULL,
            input_summary TEXT NOT NULL,
            verdict TEXT NOT NULL,
            score INTEGER NOT NULL,
            reasons TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
        )
    """)

    conn.commit()

    # Ensure scans table has newer columns for CTI Reports
    try:
        cursor.execute("ALTER TABLE scans ADD COLUMN file_hash TEXT")
    except sqlite3.OperationalError:
        pass  # Column already exists
    try:
        cursor.execute("ALTER TABLE scans ADD COLUMN indicators TEXT")
    except sqlite3.OperationalError:
        pass  # Column already exists
    try:
        cursor.execute("ALTER TABLE scans ADD COLUMN recommendation TEXT")
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    # Create alerts table (database-backed live crawler feed)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source TEXT NOT NULL,
            content TEXT NOT NULL,
            category TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            url TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'ACTIVE'
        )
    """)
    conn.commit()

    # ── Seed the initial admin account if there are no users ──────────────
    # The password comes from ADMIN_PASSWORD. In production a hardcoded
    # "admin123" would go live on every fresh deployment — and it was printed
    # to the logs — so there it must be supplied explicitly.
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        is_production = os.environ.get('FLASK_ENV', 'development') == 'production'
        admin_password = os.environ.get('ADMIN_PASSWORD')

        if not admin_password:
            if is_production:
                conn.close()
                raise RuntimeError(
                    "No users exist and ADMIN_PASSWORD is not set. Set ADMIN_PASSWORD "
                    "to seed the initial administrator account."
                )
            admin_password = "admin123"
            print("[AUTH DB] WARNING: seeding the development admin account with a "
                  "well-known password. Set ADMIN_PASSWORD before deploying.")

        seeds = [("admin", generate_password_hash(admin_password), "admin")]

        # The demo standard-user account exists for local walkthroughs only.
        # Production seeds the administrator and nothing else.
        if not is_production:
            seeds.append(("user", generate_password_hash("user123"), "user"))

        cursor.executemany("""
            INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)
        """, seeds)
        conn.commit()
        print(f"[AUTH DB] Seeded {len(seeds)} account(s): "
              f"{', '.join(s[0] for s in seeds)}")

    conn.close()

# ── User CRUD helpers ──────────────────────────────────────────

def create_user(username, password, role="user"):
    """Register a new user account."""
    conn = get_db_connection()
    cursor = conn.cursor()
    pwd_hash = generate_password_hash(password)
    try:
        cursor.execute("""
            INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)
        """, (username.strip(), pwd_hash, role))
        conn.commit()
        success = True
    except sqlite3.IntegrityError:
        success = False
    finally:
        conn.close()
    return success

def verify_user(username, password):
    """Authenticate username & password, returns user dict or None."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username.strip(),))
    user = cursor.fetchone()
    conn.close()

    if user and check_password_hash(user["password_hash"], password):
        return dict(user)
    return None

def get_user_by_id(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    return dict(user) if user else None

def get_all_users():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, role, created_at FROM users ORDER BY created_at DESC")
    users = [dict(u) for u in cursor.fetchall()]
    conn.close()
    return users

def update_user_role(user_id, new_role):
    if new_role not in ("user", "admin"):
        return False
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
    conn.commit()
    rows = cursor.rowcount
    conn.close()
    return rows > 0

def delete_user(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    rows = cursor.rowcount
    conn.close()
    return rows > 0

# ── Scan History Audit Log helpers ────────────────────────────

def save_scan(user_id, username, module, input_summary, verdict, score, reasons, file_hash=None, indicators=None, recommendation=None):
    """Save a scan transaction to the audit registry."""
    conn = get_db_connection()
    cursor = conn.cursor()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    reasons_json = json.dumps(reasons or [])
    indicators_json = json.dumps(indicators or {})
    
    cursor.execute("""
        INSERT INTO scans (user_id, username, timestamp, module, input_summary, verdict, score, reasons, file_hash, indicators, recommendation)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (user_id, username, now_str, module, input_summary, verdict, int(score), reasons_json, file_hash, indicators_json, recommendation))
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    return new_id

def get_user_scans(user_id, user_role, filter_type="all"):
    """
    Get scan logs. 
    Standard users only get their own scans.
    Admins get all scans (Global Audit).
    """
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    query = "SELECT * FROM scans"
    params = []
    
    if user_role != "admin":
        query += " WHERE user_id = ?"
        params.append(user_id)
        
    # Apply verdict filtering
    if filter_type != "all":
        filter_clause = ""
        if filter_type == "safe":
            filter_clause = " (LOWER(verdict) LIKE '%safe%' OR LOWER(verdict) LIKE '%real%' OR LOWER(verdict) LIKE '%authentic%')"
        elif filter_type == "suspicious":
            filter_clause = " (LOWER(verdict) LIKE '%suspicious%' OR LOWER(verdict) LIKE '%warn%')"
        elif filter_type == "danger":
            filter_clause = " (LOWER(verdict) LIKE '%betting%' OR LOWER(verdict) LIKE '%fake%' OR LOWER(verdict) LIKE '%scam%' OR LOWER(verdict) LIKE '%danger%' OR LOWER(verdict) LIKE '%red%' OR LOWER(verdict) LIKE '%critical%')"
            
        if filter_clause:
            if "WHERE" in query:
                query += " AND" + filter_clause
            else:
                query += " WHERE" + filter_clause
                
    query += " ORDER BY id DESC"
    
    cursor.execute(query, params)
    scans = []
    for row in cursor.fetchall():
        d = dict(row)
        try:
            d["reasons"] = json.loads(d["reasons"])
        except Exception:
            d["reasons"] = []
        try:
            d["indicators"] = json.loads(d["indicators"]) if d.get("indicators") else {}
        except Exception:
            d["indicators"] = {}
        scans.append(d)
        
    conn.close()
    return scans

def delete_scan(scan_id, user_id, user_role):
    """Delete scan entry (standard users can only delete their own scans)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if user_role == "admin":
        cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    else:
        cursor.execute("DELETE FROM scans WHERE id = ? AND user_id = ?", (scan_id, user_id))
        
    conn.commit()
    rows = cursor.rowcount
    conn.close()
    return rows > 0

def clear_user_scans(user_id, user_role):
    """Clear registry history."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if user_role == "admin":
        cursor.execute("DELETE FROM scans")
    else:
        cursor.execute("DELETE FROM scans WHERE user_id = ?", (user_id,))
        
    conn.commit()
    conn.close()

def get_scan(scan_id):
    """Fetch a single scan by ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        d = dict(row)
        try:
            d["reasons"] = json.loads(d["reasons"])
        except Exception:
            d["reasons"] = []
        try:
            d["indicators"] = json.loads(d["indicators"]) if d.get("indicators") else {}
        except Exception:
            d["indicators"] = {}
        return d
    return None

# ── Alerts Database CRUD helpers ──────────────────────────────

def save_alert(source, content, category, risk_score, url):
    """
    Save a crawler threat alert, refreshing an existing entry for the same URL.

    An analyst's "Block & Takedown" decision is permanent: a BLOCKED alert is
    left untouched. This previously deleted the old row and inserted a fresh
    one with status ACTIVE, so within a crawl cycle or two every blocked threat
    reappeared at the top of the feed as if nothing had happened — and, because
    the fallback pool holds only a handful of templates, the same ones cycled
    back repeatedly. It also churned through primary keys on every sweep.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute(
        "SELECT id, status FROM alerts WHERE url = ? OR (source = ? AND content = ?)",
        (url, source, content)
    )
    existing = cursor.fetchone()

    if existing:
        if existing["status"] == "BLOCKED":
            # Already actioned — do not resurrect it.
            conn.close()
            return existing["id"]
        cursor.execute("""
            UPDATE alerts
               SET timestamp = ?, source = ?, content = ?, category = ?, risk_score = ?
             WHERE id = ?
        """, (now_str, source, content, category, int(risk_score), existing["id"]))
        conn.commit()
        conn.close()
        return existing["id"]

    cursor.execute("""
        INSERT INTO alerts (timestamp, source, content, category, risk_score, url, status)
        VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE')
    """, (now_str, source, content, category, int(risk_score), url))
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    return new_id

def get_latest_alerts(limit=15):
    """
    Retrieve the latest active alerts from the crawler feed.

    Ordered by timestamp, not id. Re-sighted alerts are now updated in place
    rather than deleted and re-inserted, so their id no longer tracks how
    recently they were seen.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM alerts WHERE status = 'ACTIVE'
        ORDER BY timestamp DESC, id DESC LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_alert(alert_id):
    """Fetch details of a single alert by ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def block_alert(alert_id):
    """Mark alert as blocked."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE alerts SET status = 'BLOCKED' WHERE id = ?", (alert_id,))
    conn.commit()
    rows = cursor.rowcount
    conn.close()
    return rows > 0

