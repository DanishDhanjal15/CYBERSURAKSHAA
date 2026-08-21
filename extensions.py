"""
extensions.py
-------------
Flask extension instances, created here rather than in app.py so that
blueprints can import them without importing the application module (which
would be a circular import).

Bind them to the app with init_app() during startup — see app.py.
"""

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ── Rate limiting ─────────────────────────────────────────────
# The defaults have to sit above what the application itself generates. The
# dashboard polls the live threat feed on a timer, and the previous 60/hour
# default was below that poll rate alone — every user was locked out of every
# route within minutes of opening the page.
limiter = Limiter(
    get_remote_address,
    default_limits=["2000 per day", "300 per hour"],
    storage_uri="memory://",    # Use a Redis URI in production: redis://...
    strategy="fixed-window",
)

# Applied to endpoints the frontend polls on a timer. Deliberately generous so
# that a couple of open tabs cannot exhaust it, while still bounding abuse.
POLLING_RATE_LIMIT = "600 per hour"

# Applied to credential-checking endpoints to slow down brute force.
AUTH_RATE_LIMIT = "20 per hour"
