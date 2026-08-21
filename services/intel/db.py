"""
services/intel/db.py
--------------------
Database connection for the intelligence layer.

In the running application this delegates to `services.auth_db`, so the
intelligence tables live in exactly the same SQLite file as `users`, `scans`
and `alerts` and share its WAL journal, timeout and row factory. There is one
database and one set of connection semantics.

The delegation is guarded because `services.auth_db` imports werkzeug for
password hashing. That pulls the whole Flask dependency tree into anything that
touches the graph -- including the test-suite and any offline analysis script,
neither of which needs authentication. When werkzeug is not importable this
falls back to opening the same file with the same pragmas directly.

DB_PATH is read identically to auth_db so the two can never diverge onto
different files.
"""

from __future__ import annotations

import os
import sqlite3

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

DATABASE_PATH = os.environ.get(
    "DB_PATH",
    os.path.join(_PROJECT_ROOT, "cybersurakshaa.db"),
)


def _standalone_connection(path=None):
    """Open the database with the same settings auth_db uses."""
    conn = sqlite3.connect(path or DATABASE_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL")
    except sqlite3.Error:
        pass
    # The graph relies on ON DELETE CASCADE to clean up edges and sightings
    # when an entity is removed. SQLite disables foreign keys per-connection by
    # default, so without this the cascades silently do nothing and deleting an
    # entity leaves orphaned edges pointing at a missing id.
    try:
        conn.execute("PRAGMA foreign_keys=ON")
    except sqlite3.Error:
        pass
    return conn


# Set by set_database_path(). When a caller has explicitly named a database
# file, that instruction has to win over auth_db's own DB_PATH -- otherwise a
# test that asks for a temporary database silently gets the developer's real
# one, which is the failure mode this flag exists to prevent.
_forced_path = False


def get_db_connection():
    """
    Return a connection to the shared database.

    Prefers auth_db's connector so production has exactly one implementation;
    falls back to a standalone connection when the Flask stack is absent, or
    when a caller has explicitly overridden the database path.
    """
    if _forced_path:
        return _standalone_connection()

    try:
        from services.auth_db import get_db_connection as _auth_conn
    except Exception:
        return _standalone_connection()

    conn = _auth_conn()
    try:
        conn.execute("PRAGMA foreign_keys=ON")
    except sqlite3.Error:
        pass
    return conn


def set_database_path(path):
    """
    Point the standalone connector at a different file.

    Used by the test-suite to run against a temporary database instead of the
    developer's working copy. While a path is set, the auth_db delegation is
    bypassed entirely, so the override holds even in an environment where the
    full Flask stack is installed. Pass None to restore normal behaviour.
    """
    global DATABASE_PATH, _forced_path
    if path is None:
        _forced_path = False
        DATABASE_PATH = os.environ.get(
            "DB_PATH", os.path.join(_PROJECT_ROOT, "cybersurakshaa.db"))
        return
    DATABASE_PATH = path
    _forced_path = True
