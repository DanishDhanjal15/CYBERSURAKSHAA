import os
import sqlite3
from datetime import datetime

DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "shield.db")

def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
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
    """Look up a phone number in the Threat Intel indicator database."""
    if not indicator_value:
        return None
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Normalize for comparison
    clean_val = "".join(filter(str.isdigit, indicator_value))
    
    cursor.execute("SELECT * FROM indicators WHERE indicator_type = 'phone'")
    rows = cursor.fetchall()
    
    match = None
    for row in rows:
        db_clean = "".join(filter(str.isdigit, row['indicator_value']))
        if db_clean and (db_clean in clean_val or clean_val in db_clean):
            match = dict(row)
            break
            
    conn.close()
    return match

def add_or_increment_indicator(indicator_value, indicator_type="phone"):
    """Insert a new threat indicator or increment report count if it exists."""
    if not indicator_value:
        return None
        
    conn = get_db_connection()
    cursor = conn.cursor()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Check if exists (using normalized matching)
    clean_val = "".join(filter(str.isdigit, indicator_value))
    
    cursor.execute("SELECT * FROM indicators WHERE indicator_type = ?", (indicator_type,))
    rows = cursor.fetchall()
    
    existing_id = None
    existing_reports = 0
    for row in rows:
        db_clean = "".join(filter(str.isdigit, row['indicator_value']))
        if db_clean and db_clean == clean_val:
            existing_id = row['id']
            existing_reports = row['reports']
            break
            
    if existing_id:
        cursor.execute(
            "UPDATE indicators SET reports = ?, last_seen = ? WHERE id = ?",
            (existing_reports + 1, now_str, existing_id)
        )
        new_reports = existing_reports + 1
    else:
        cursor.execute(
            "INSERT INTO indicators (indicator_type, indicator_value, reports, first_seen, last_seen) VALUES (?, ?, 1, ?, ?)",
            (indicator_type, indicator_value.strip(), now_str, now_str)
        )
        new_reports = 1
        
    conn.commit()
    conn.close()
    return new_reports

if __name__ == "__main__":
    init_db()
    print("Database initialization successful.")
