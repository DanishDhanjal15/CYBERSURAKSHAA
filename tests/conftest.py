"""
tests/conftest.py
-----------------
Shared fixtures.

The whole `services.intel` package is deliberately stdlib-only and takes its
database handle from `services.intel.db.get_db_connection`, which can be
pointed anywhere. That is what makes these tests runnable without Flask,
without a model checkpoint, and without touching the developer's real
database — the single most common reason a project's tests get skipped in
practice.
"""

import os
import sqlite3
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


# ── Database isolation for the WHOLE session ─────────────────────────────
#
# This must run at import time, before any test module imports `app`.
# `services/auth_db.py` resolves DB_PATH once at module import and caches it in
# a module global, so setting it later has no effect.
#
# Without this, the suite writes to the developer's real database. That is not
# merely untidy: tests/test_public_api.py seeds an API key with a value
# published in this repository, and it was landing in the live database as an
# active credential. A test suite must never be able to create a working
# credential in production.
#
# Kept out of a fixture deliberately — a fixture runs too late.
_TEST_DB = os.path.join(tempfile.gettempdir(), "cybersurakshaa-test-suite.db")
os.environ["DB_PATH"] = _TEST_DB
# Dev mode, so a missing SECRET_KEY is a warning rather than fatal.
os.environ.setdefault("FLASK_ENV", "development")
# Keep the crawler's demonstration pool out of the test database.
os.environ.setdefault("CRAWLER_ALLOW_SIMULATED", "0")

# Pin the seeded administrator password. Without this the suite inherits
# whatever ADMIN_PASSWORD the developer has in .env -- which app.py now loads
# -- so tests either fail on a machine that has one, or quietly authenticate
# using somebody's real credential. Overridden unconditionally, not
# setdefault, because inheriting it is the failure being prevented.
os.environ["ADMIN_PASSWORD"] = "test-suite-seed-password"


@pytest.fixture
def temp_db(monkeypatch):
    """
    A throwaway SQLite database with the tables the intel layer expects.

    `scans` is created here rather than by the intel layer because
    services/auth_db.py owns it in production; the intel modules only read it.
    Creating it in the fixture keeps that ownership boundary intact instead of
    quietly moving a production table definition into the test path.
    """
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)

    from services.intel import db as intel_db
    intel_db.set_database_path(path)

    conn = sqlite3.connect(path)
    conn.execute("""
        CREATE TABLE scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            timestamp TEXT,
            module TEXT,
            input_summary TEXT,
            verdict TEXT,
            score REAL,
            reasons TEXT,
            indicators TEXT,
            file_hash TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT, source TEXT, content TEXT,
            category TEXT, risk_score REAL, url TEXT
        )
    """)
    conn.commit()
    conn.close()

    from services.intel.graph import init_graph_db
    from services.intel.evidence import init_evidence_db
    from services.intel.feedback import init_feedback_db
    init_graph_db()
    init_evidence_db()
    init_feedback_db()

    yield path

    intel_db.set_database_path(None)
    try:
        os.unlink(path)
    except OSError:
        # Windows keeps a handle briefly after close; a leaked temp file is
        # not worth failing a green test run over.
        pass


@pytest.fixture
def sample_scam_text():
    return (
        "URGENT: Your SBI account has been blocked due to KYC expiry. "
        "Complete verification immediately or your account will be permanently "
        "frozen. Pay the Rs.10 verification fee to scamguy@okhdfcbank or "
        "transfer to account number 3847 2910 5566 (IFSC SBIN0001234). "
        "For help call our customer care 98765-43210 or WhatsApp "
        "+91 8123456789. Join https://t.me/sbi_kyc_help for updates. "
        "Download the app from sbi-verification-login.com"
    )
