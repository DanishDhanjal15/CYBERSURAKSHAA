import os
import sqlite3
from datetime import datetime

# Overridable so the file can live on a mounted volume rather than inside the
# source tree — in a container the source directory is part of the image and
# anything written there is lost on the next deploy. blueprints/admin.py reads
# the same variable.
DATABASE_PATH = os.environ.get(
    'SHIELD_DB_PATH',
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "shield.db")
)

def _normalise_phone(value):
    """Digits-only form used for all indicator comparisons."""
    return "".join(filter(str.isdigit, value or ""))


# Indicators shorter than this are too ambiguous to match on. A 3-digit
# indicator would substring-match a huge share of all phone numbers.
MIN_INDICATOR_DIGITS = 6


def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    # WAL lets the crawler thread write while requests read, instead of both
    # contending on a single global write lock and raising "database is locked".
    try:
        conn.execute("PRAGMA journal_mode=WAL")
    except sqlite3.Error:
        pass
    return conn

def init_db():
    """Initialize SQLite database tables and seed official contacts."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Create official_contacts table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS official_contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            brand TEXT NOT NULL UNIQUE,
            official_phone TEXT NOT NULL,
            official_website TEXT
        )
    """)

    # Create indicators table for threat intelligence
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator_type TEXT NOT NULL,
            indicator_value TEXT NOT NULL UNIQUE,
            reports INTEGER DEFAULT 1,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL
        )
    """)

    # ── Migration: normalised indicator column ────────────────────────────
    # All matching happens on the digits-only form. Storing it lets us use an
    # indexed exact lookup and an atomic upsert instead of scanning the table.
    try:
        cursor.execute("ALTER TABLE indicators ADD COLUMN indicator_norm TEXT")
    except sqlite3.OperationalError:
        pass  # Column already exists

    # Backfill any rows written before the column existed.
    cursor.execute("SELECT id, indicator_value FROM indicators WHERE indicator_norm IS NULL")
    for row in cursor.fetchall():
        cursor.execute(
            "UPDATE indicators SET indicator_norm = ? WHERE id = ?",
            (_normalise_phone(row["indicator_value"]), row["id"])
        )

    # Collapse any duplicates that the old substring logic may have created,
    # keeping the lowest id and summing their report counts — otherwise the
    # unique index below cannot be built.
    cursor.execute("""
        SELECT indicator_type, indicator_norm, MIN(id) AS keep_id, SUM(reports) AS total
        FROM indicators
        WHERE indicator_norm IS NOT NULL AND indicator_norm != ''
        GROUP BY indicator_type, indicator_norm
        HAVING COUNT(*) > 1
    """)
    for dup in cursor.fetchall():
        cursor.execute(
            "UPDATE indicators SET reports = ? WHERE id = ?",
            (dup["total"], dup["keep_id"])
        )
        cursor.execute(
            "DELETE FROM indicators WHERE indicator_type = ? AND indicator_norm = ? AND id != ?",
            (dup["indicator_type"], dup["indicator_norm"], dup["keep_id"])
        )

    cursor.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_indicators_norm
        ON indicators(indicator_type, indicator_norm)
    """)
    conn.commit()

    # Check and seed official_contacts if empty
    cursor.execute("SELECT COUNT(*) FROM official_contacts")
    if cursor.fetchone()[0] == 0:
        official_data = [
            ("Amazon", "1800-3000-9009", "https://www.amazon.in"),
            ("Flipkart", "1800-208-9898", "https://www.flipkart.com"),
            ("SBI", "1800-11-2211", "https://www.sbi.co.in"),
            ("HDFC Bank", "1800-202-6161", "https://www.hdfcbank.com"),
            ("ICICI Bank", "1800-1080", "https://www.icicibank.com"),
            ("Axis Bank", "1800-419-5959", "https://www.axisbank.com"),
            ("Airtel", "121", "https://www.airtel.in"),
            ("Jio", "1860-893-3333", "https://www.jio.com"),
            ("Paytm", "0120-4456-456", "https://paytm.com"),
            ("PhonePe", "080-68727374", "https://www.phonepe.com")
        ]
        cursor.executemany(
            "INSERT INTO official_contacts (brand, official_phone, official_website) VALUES (?, ?, ?)",
            official_data
        )
        conn.commit()
        print("[SHIELD DB] Seeded official contacts.")

    conn.close()

def get_official_contact(brand_name):
    """Get official contact details for a brand (case-insensitive, substring matching)."""
    if not brand_name:
        return None
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Try exact match first
    cursor.execute(
        "SELECT * FROM official_contacts WHERE LOWER(brand) = LOWER(?)", 
        (brand_name.strip(),)
    )
    result = cursor.fetchone()
    
    # Try substring match if no exact match (e.g. "HDFC" matches "HDFC Bank")
    if not result:
        cursor.execute(
            "SELECT * FROM official_contacts WHERE LOWER(brand) LIKE LOWER(?) OR LOWER(?) LIKE '%' || LOWER(brand) || '%'",
            (f"%{brand_name.strip()}%", brand_name.strip())
        )
        result = cursor.fetchone()
        
    conn.close()
    return dict(result) if result else None

def lookup_indicator(indicator_value):
    """
    Look up a phone number in the Threat Intel indicator database.

    Matching is an exact comparison of the normalised (digits-only) value.
    This previously tested substring containment in *both* directions, so a
    single short indicator such as "121" flagged every number that happened to
    contain those digits — 9812134567, 1212345678, and so on — as a confirmed
    scam number.
    """
    clean_val = _normalise_phone(indicator_value)
    if len(clean_val) < MIN_INDICATOR_DIGITS:
        return None

    conn = get_db_connection()
    cursor = conn.cursor()

    # Indexed exact lookup on the normalised column instead of loading the
    # whole table into Python and scanning it on every request.
    cursor.execute(
        "SELECT * FROM indicators WHERE indicator_type = 'phone' AND indicator_norm = ?",
        (clean_val,)
    )
    row = cursor.fetchone()

    # Also treat a match on the last 10 digits as the same subscriber, so
    # "+919876543210" and "9876543210" resolve to one indicator.
    if row is None and len(clean_val) >= 10:
        cursor.execute(
            "SELECT * FROM indicators WHERE indicator_type = 'phone' AND indicator_norm = ?",
            (clean_val[-10:],)
        )
        row = cursor.fetchone()

    conn.close()
    return dict(row) if row else None

def add_or_increment_indicator(indicator_value, indicator_type="phone"):
    """
    Insert a new threat indicator or increment its report count.

    Done as a single atomic upsert. The previous read-modify-write had no
    transaction around it, so two concurrent reports of the same number both
    read reports=1 and both wrote 2 — losing one report.
    """
    clean_val = _normalise_phone(indicator_value)
    if len(clean_val) < MIN_INDICATOR_DIGITS:
        return None

    conn = get_db_connection()
    cursor = conn.cursor()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        INSERT INTO indicators (indicator_type, indicator_value, indicator_norm, reports, first_seen, last_seen)
        VALUES (?, ?, ?, 1, ?, ?)
        ON CONFLICT(indicator_type, indicator_norm)
        DO UPDATE SET reports = reports + 1, last_seen = excluded.last_seen
    """, (indicator_type, indicator_value.strip(), clean_val, now_str, now_str))
    conn.commit()

    cursor.execute(
        "SELECT reports FROM indicators WHERE indicator_type = ? AND indicator_norm = ?",
        (indicator_type, clean_val)
    )
    row = cursor.fetchone()
    new_reports = row['reports'] if row else 1

    conn.close()
    return new_reports

if __name__ == "__main__":
    init_db()
    print("Database initialization successful.")
