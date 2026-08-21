"""
services/intel/accounts.py
--------------------------
Account security: password rotation and real, revocable sessions.

Two gaps this closes
====================
**Nobody could change their own password.** The platform seeds accounts with
well-known defaults and had no rotation route at all — not for users, not for
admins. An account whose credential leaks could only be fixed by deleting it.

**Sessions could not be revoked.** Flask sessions are signed cookies with no
server-side record, so "sign out" only cleared the cookie in the browser doing
the clicking. A session cookie copied off a compromised machine stayed valid
until the secret key changed, and nothing could see it, list it, or stop it.

How sessions work now
=====================
Login mints a random token, stores its **hash** server-side alongside the
user agent and address, and puts the token in the signed cookie. Every request
checks the token is still live. Revoking a row therefore kills that session on
the next request, wherever it is.

Storing the hash rather than the token means a leaked database does not hand
the reader a set of working session cookies — the same reasoning as the API
keys in `blueprints/public_api.py`.

Changing a password revokes every *other* session by default, because the
usual reason to change one is that you think somebody else has it.

Legacy cookies
==============
Sessions created before this existed carry a `user_id` but no token. They are
treated as invalid and sent back to login once. Accepting them would leave
exactly the unrevocable sessions this module exists to eliminate.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta

from services.intel.db import get_db_connection

# How often a session's activity stamp is actually written. Validation reads
# on every request; writing that often would make session tracking the most
# expensive thing in a page load.
TOUCH_INTERVAL_SECONDS = 60

# Sessions idle longer than this stop being accepted. Not a hard expiry on the
# cookie — the check is server-side, so it applies to a copied cookie too.
IDLE_TIMEOUT_DAYS = 14

# Password rules. Deliberately modest: length is what actually matters, and a
# composition rule that forces a punctuation mark mostly produces "Password1!".
MIN_PASSWORD_LENGTH = 10

# Passwords common enough that requiring anything else is worth the friction.
# Short list on purpose -- it exists to stop the obvious, not to be a filter.
OBVIOUS_PASSWORDS = {
    "password", "password1", "password123", "12345678", "123456789",
    "1234567890", "qwertyuiop", "admin123", "user123", "letmein123",
    "welcome123", "cybersurakshaa", "changeme123", "iloveyou123",
}


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _parse(ts):
    try:
        return datetime.strptime(str(ts)[:19], "%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return None


def _hash_token(raw):
    """
    Session tokens are stored hashed.

    SHA-256 with no work factor is right here and wrong for passwords: the
    token is 32 bytes of `secrets.token_urlsafe` entropy, so there is no
    dictionary to run against it and nothing for a slow hash to buy.
    """
    return hashlib.sha256((raw or "").encode("utf-8")).hexdigest()


# ── Schema ────────────────────────────────────────────────────────────────

def init_accounts_db():
    """Create the session table and add password bookkeeping. Idempotent."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS user_sessions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            username    TEXT,
            token_hash  TEXT NOT NULL UNIQUE,
            created_at  TEXT NOT NULL,
            last_seen   TEXT NOT NULL,
            user_agent  TEXT,
            ip          TEXT,
            revoked     INTEGER NOT NULL DEFAULT 0,
            revoked_at  TEXT,
            revoked_by  TEXT,
            revoke_reason TEXT
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_sess_user ON user_sessions(user_id, revoked)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_sess_token ON user_sessions(token_hash)")

    # `users` belongs to services/auth_db.py; only additive columns are added
    # here, and only if absent, so the two cannot fight over the schema.
    existing = {r["name"] for r in cur.execute("PRAGMA table_info(users)").fetchall()}
    if existing:
        if "password_changed_at" not in existing:
            cur.execute("ALTER TABLE users ADD COLUMN password_changed_at TEXT")
        if "must_change_password" not in existing:
            cur.execute("ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0")
        if "last_login" not in existing:
            cur.execute("ALTER TABLE users ADD COLUMN last_login TEXT")

    conn.commit()
    conn.close()



def _get_user(user_id):
    """
    Read a user through this module's own connection.

    Deliberately not `services.auth_db.get_user_by_id`. That module resolves
    its path independently, so reading through it while writing through
    `services.intel.db` means two connection policies operating on one table.
    In production both resolve to the same file and it works by coincidence;
    anywhere they diverge the read silently finds nothing and a password
    change reports "account not found" for an account that plainly exists.
    """
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (int(user_id),)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


# ── Sessions ──────────────────────────────────────────────────────────────

def start_session(user_id, username, user_agent=None, ip=None):
    """Mint a session. Returns the raw token; only its hash is stored."""
    raw = secrets.token_urlsafe(32)
    conn = get_db_connection()
    try:
        conn.execute("""
            INSERT INTO user_sessions
                (user_id, username, token_hash, created_at, last_seen, user_agent, ip)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (user_id, username, _hash_token(raw), _now(), _now(),
              (user_agent or "")[:300], (ip or "")[:64]))
        conn.execute("UPDATE users SET last_login = ? WHERE id = ?", (_now(), user_id))
        conn.commit()
    finally:
        conn.close()
    return raw


def touch_session(raw_token, ip=None):
    """
    Validate a session token and refresh its activity stamp.

    Returns the session row when live, or None — which the caller must treat
    as "log this request out", not as "carry on".
    """
    if not raw_token:
        return None

    conn = get_db_connection()
    try:
        row = conn.execute("""
            SELECT * FROM user_sessions WHERE token_hash = ?
        """, (_hash_token(raw_token),)).fetchone()

        if not row or row["revoked"]:
            return None

        last = _parse(row["last_seen"])
        if last and datetime.now() - last > timedelta(days=IDLE_TIMEOUT_DAYS):
            # Idle too long. Revoked rather than merely rejected, so it shows
            # up in the session list with a reason instead of vanishing.
            conn.execute("""
                UPDATE user_sessions SET revoked = 1, revoked_at = ?,
                       revoked_by = 'system', revoke_reason = 'idle timeout'
                WHERE id = ?
            """, (_now(), row["id"]))
            conn.commit()
            return None

        # The read has to happen on every request; the write does not.
        # Refreshing last_seen more than once a minute buys nothing and turns
        # every page view -- including the polling endpoints -- into a
        # database write.
        if not last or datetime.now() - last > timedelta(seconds=TOUCH_INTERVAL_SECONDS):
            conn.execute(
                "UPDATE user_sessions SET last_seen = ?, ip = COALESCE(?, ip) WHERE id = ?",
                (_now(), (ip or None), row["id"]))
            conn.commit()
        return dict(row)
    finally:
        conn.close()


def list_sessions(user_id, include_revoked=False):
    sql = "SELECT * FROM user_sessions WHERE user_id = ?"
    params = [int(user_id)]
    if not include_revoked:
        sql += " AND revoked = 0"
    sql += " ORDER BY last_seen DESC"

    conn = get_db_connection()
    rows = [dict(r) for r in conn.execute(sql, params).fetchall()]
    conn.close()
    return rows


def revoke_session(session_id, revoked_by=None, reason="signed out"):
    conn = get_db_connection()
    try:
        cur = conn.execute("""
            UPDATE user_sessions SET revoked = 1, revoked_at = ?, revoked_by = ?,
                   revoke_reason = ? WHERE id = ? AND revoked = 0
        """, (_now(), revoked_by, reason, int(session_id)))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def revoke_by_token(raw_token, revoked_by=None, reason="signed out"):
    if not raw_token:
        return False
    conn = get_db_connection()
    try:
        cur = conn.execute("""
            UPDATE user_sessions SET revoked = 1, revoked_at = ?, revoked_by = ?,
                   revoke_reason = ? WHERE token_hash = ? AND revoked = 0
        """, (_now(), revoked_by, reason, _hash_token(raw_token)))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def revoke_all(user_id, except_token=None, revoked_by=None, reason="signed out everywhere"):
    """
    End every session for a user, optionally sparing the current one.

    Sparing the caller's own session is the right default for a self-service
    "sign out everywhere": logging yourself out as a side effect of securing
    your account is a surprise, and it discourages people from doing it.
    """
    sql = """UPDATE user_sessions SET revoked = 1, revoked_at = ?, revoked_by = ?,
             revoke_reason = ? WHERE user_id = ? AND revoked = 0"""
    params = [_now(), revoked_by, reason, int(user_id)]
    if except_token:
        sql += " AND token_hash != ?"
        params.append(_hash_token(except_token))

    conn = get_db_connection()
    try:
        cur = conn.execute(sql, params)
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


def describe_session(row, current_token=None):
    """A session rendered for a human: device, where, when, is this one me."""
    ua = (row.get("user_agent") or "").lower()
    if "edg/" in ua:
        browser = "Edge"
    elif "chrome" in ua and "chromium" not in ua:
        browser = "Chrome"
    elif "firefox" in ua:
        browser = "Firefox"
    elif "safari" in ua:
        browser = "Safari"
    elif "curl" in ua or "python" in ua:
        browser = "Script or API client"
    else:
        browser = "Unknown browser"

    if "windows" in ua:
        platform = "Windows"
    elif "android" in ua:
        platform = "Android"
    elif "iphone" in ua or "ipad" in ua:
        platform = "iOS"
    elif "mac os" in ua or "macintosh" in ua:
        platform = "macOS"
    elif "linux" in ua:
        platform = "Linux"
    else:
        platform = "unknown platform"

    return {
        "id": row["id"],
        "device": "%s on %s" % (browser, platform),
        "ip": row.get("ip") or "unknown",
        "created_at": row["created_at"],
        "last_seen": row["last_seen"],
        "revoked": bool(row.get("revoked")),
        "revoke_reason": row.get("revoke_reason"),
        "current": bool(current_token and row["token_hash"] == _hash_token(current_token)),
    }


# ── Passwords ─────────────────────────────────────────────────────────────

def check_password_strength(password, username=None):
    """
    Returns (ok, reason). Length first, because it is the property that
    actually resists guessing.
    """
    password = password or ""
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, ("Use at least %d characters. Length matters far more "
                       "than punctuation." % MIN_PASSWORD_LENGTH)
    if password.lower() in OBVIOUS_PASSWORDS:
        return False, "That password is one of the first anyone would try."
    if username and username.lower() in password.lower():
        return False, "Do not include your username in your password."
    if len(set(password)) < 5:
        return False, "That is too repetitive to be worth much."
    return True, None


def change_password(user_id, current_password, new_password, current_token=None,
                    keep_other_sessions=False):
    """
    Rotate a password after verifying the current one.

    Requiring the current password is what stops a hijacked session from
    locking the real owner out — without it, anyone who obtained a session
    cookie could take the account permanently.

    Every other session is revoked by default: the usual reason to change a
    password is believing somebody else has it, and leaving their session live
    would defeat the exercise.
    """
    from werkzeug.security import check_password_hash, generate_password_hash

    user = _get_user(user_id)
    if not user:
        return False, "Account not found.", 0

    if not check_password_hash(user["password_hash"], current_password or ""):
        return False, "Current password is incorrect.", 0

    if (new_password or "") == (current_password or ""):
        return False, "The new password is the same as the current one.", 0

    ok, reason = check_password_strength(new_password, user["username"])
    if not ok:
        return False, reason, 0

    conn = get_db_connection()
    try:
        conn.execute("""
            UPDATE users SET password_hash = ?, password_changed_at = ?,
                   must_change_password = 0 WHERE id = ?
        """, (generate_password_hash(new_password), _now(), user_id))
        conn.commit()
    finally:
        conn.close()

    revoked = 0
    if not keep_other_sessions:
        revoked = revoke_all(user_id, except_token=current_token,
                             revoked_by=user["username"],
                             reason="password changed")

    return True, None, revoked


def admin_reset_password(user_id, new_password, reset_by=None):
    """
    Administrative reset, for a locked-out account.

    Sets `must_change_password`, so the temporary credential the admin just
    chose cannot become the account's permanent password. Every session is
    revoked with no exception — an admin resetting somebody else's password
    has no session of theirs to spare, and if the account was compromised,
    the attacker's session must die with the old credential.
    """
    from werkzeug.security import generate_password_hash

    user = _get_user(user_id)
    if not user:
        return False, "Account not found.", 0

    ok, reason = check_password_strength(new_password, user["username"])
    if not ok:
        return False, reason, 0

    conn = get_db_connection()
    try:
        conn.execute("""
            UPDATE users SET password_hash = ?, password_changed_at = ?,
                   must_change_password = 1 WHERE id = ?
        """, (generate_password_hash(new_password), _now(), user_id))
        conn.commit()
    finally:
        conn.close()

    revoked = revoke_all(user_id, revoked_by=reset_by, reason="password reset by administrator")
    return True, None, revoked


def must_change_password(user_id):
    return bool((_get_user(user_id) or {}).get("must_change_password"))


def account_overview(user_id, current_token=None):
    user = _get_user(user_id)
    if not user:
        return None
    sessions = [describe_session(s, current_token)
                for s in list_sessions(user_id, include_revoked=False)]
    return {
        "username": user["username"],
        "role": user["role"],
        "created_at": user.get("created_at"),
        "last_login": user.get("last_login"),
        "password_changed_at": user.get("password_changed_at"),
        "password_never_changed": not user.get("password_changed_at"),
        "must_change_password": bool(user.get("must_change_password")),
        "sessions": sessions,
        "session_count": len(sessions),
    }
