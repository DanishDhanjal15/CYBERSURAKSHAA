"""
scripts/smoke_test.py
---------------------
Post-deployment verification. Run this against a freshly deployed URL before
telling anyone the deployment worked.

    python scripts/smoke_test.py https://your-deployment
    python scripts/smoke_test.py https://your-deployment --admin-password 'the one you set'

What it checks, and why each one is here rather than "it loaded, ship it":

  * liveness and readiness are different questions — a process can be up with
    every model still loading, and that state serves 500s that look like bugs;
  * the public surfaces (citizen check, evidence verification, API root) must
    work with no session at all, because that is their entire purpose;
  * the security posture that only exists in production — HTTPS, secure
    cookies, no debug — is asserted, not assumed;
  * with credentials, one real scan is run end to end, because a deployment
    where every page renders and no detector works is the failure this script
    exists to catch.

Exit code is 0 only when every required check passed. Stdlib only, so it runs
anywhere Python does — including inside the container.
"""

from __future__ import annotations

import argparse
import json
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar

TIMEOUT = 60

PASS, FAIL, WARN, INFO = "PASS", "FAIL", "WARN", "INFO"
_results = []


def record(status, label, detail=""):
    _results.append((status, label, detail))
    mark = {PASS: "[ ok ]", FAIL: "[FAIL]", WARN: "[warn]", INFO: "[ .. ]"}[status]
    print("%s %-46s %s" % (mark, label, detail))


class Client:
    """Minimal session with cookies, so login survives across requests."""

    def __init__(self, base):
        self.base = base.rstrip("/")
        self.jar = CookieJar()
        ctx = ssl.create_default_context()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar),
            urllib.request.HTTPSHandler(context=ctx),
            NoRedirect(),
        )

    def request(self, path, data=None, headers=None, method=None):
        url = path if path.startswith("http") else self.base + path
        body = None
        hdrs = {"User-Agent": "cybersurakshaa-smoke/1.0"}
        if isinstance(data, dict):
            body = urllib.parse.urlencode(data).encode()
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        elif isinstance(data, (bytes, str)):
            body = data.encode() if isinstance(data, str) else data
        hdrs.update(headers or {})
        req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
        try:
            resp = self.opener.open(req, timeout=TIMEOUT)
            return resp.status, resp.read().decode("utf-8", "replace"), dict(resp.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace"), dict(e.headers)
        except Exception as e:
            return None, str(e), {}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Redirects are answers here — a 302 to /auth/login is the check."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def as_json(text):
    try:
        return json.loads(text)
    except Exception:
        return None


# ── Checks ────────────────────────────────────────────────────────────────

def check_liveness(c):
    status, body, _ = c.request("/healthz")
    d = as_json(body) or {}
    if status == 200 and d.get("status") in ("ok", "degraded"):
        db = (d.get("database") or {}).get("reachable")
        record(PASS if db else FAIL, "liveness /healthz",
               "status=%s database_reachable=%s" % (d.get("status"), db))
        return d
    record(FAIL, "liveness /healthz", "HTTP %s" % status)
    return {}


def check_readiness(c, wait_seconds):
    """Models load lazily; a cold container legitimately needs a few minutes."""
    deadline = time.time() + wait_seconds
    last = {}
    while True:
        status, body, _ = c.request("/readyz")
        last = as_json(body) or {}
        if status == 200 and last.get("ready"):
            record(PASS, "readiness /readyz", "all models loaded")
            return True
        if time.time() >= deadline:
            break
        time.sleep(10)
    pending = last.get("pending") or []
    record(WARN if pending else FAIL, "readiness /readyz",
           "still loading: %s" % (", ".join(pending) or "unknown"))
    return False


def check_public_surfaces(c):
    for path, label, needle in (
        ("/auth/login", "login page renders", "CYBERSURAKSHAA"),
        ("/check/", "citizen quick check is public", "Citizen Quick Check"),
        ("/api/v1/", "public API root", "endpoints"),
    ):
        status, body, _ = c.request(path)
        ok = status == 200 and needle.lower() in body.lower()
        record(PASS if ok else FAIL, label, "HTTP %s" % status)

    # The citizen text check must work with no key and no session.
    status, body, _ = c.request(
        "/check/api/text",
        data=json.dumps({"text": "URGENT: aapka account block ho jayega, "
                                 "turant KYC update karein aur OTP share karein"}),
        headers={"Content-Type": "application/json"})
    d = as_json(body) or {}
    ok = status == 200 and d.get("band") in ("SAFE", "UNSURE", "LIKELY_SCAM")
    record(PASS if ok else FAIL, "citizen text check answers",
           "band=%s score=%s" % (d.get("band"), d.get("score")) if ok else "HTTP %s" % status)


def check_auth_required(c):
    """Everything that isn't deliberately public must refuse an anonymous caller."""
    protected = ["/", "/round2", "/tv", "/qr/", "/nfc/", "/intel/",
                 "/admin/dashboard", "/admin/operations"]
    leaked = []
    for path in protected:
        status, _, _ = c.request(path)
        if status not in (301, 302, 401, 403):
            leaked.append("%s->%s" % (path, status))
    record(PASS if not leaked else FAIL, "protected routes require a session",
           "all %d refuse anonymous" % len(protected) if not leaked else "LEAKING: %s" % leaked)


def check_security_posture(c, base):
    if not base.startswith("https://"):
        record(WARN, "transport is HTTPS", "deployment URL is plain HTTP")
        return
    record(PASS, "transport is HTTPS", "")

    status, body, headers = c.request("/auth/login")
    cookie = headers.get("Set-Cookie", "")
    if cookie:
        secure = "Secure" in cookie
        httponly = "HttpOnly" in cookie
        record(PASS if (secure and httponly) else FAIL, "session cookie hardened",
               "Secure=%s HttpOnly=%s" % (secure, httponly))
    else:
        record(INFO, "session cookie hardened", "no cookie issued on this response")

    # A production build must never render the Werkzeug debugger.
    status, body, _ = c.request("/this-route-does-not-exist-%d" % int(time.time()))
    debug_leak = "Werkzeug" in body or "Traceback (most recent call last)" in body
    record(FAIL if debug_leak else PASS, "debug mode is off",
           "debugger output on error page" if debug_leak else "HTTP %s, no traceback" % status)


def check_verification_endpoint(c):
    """Unauthenticated by design: a verifier only the operator can call proves nothing."""
    status, body, _ = c.request("/api/v1/verify/" + "a" * 64)
    d = as_json(body) or {}
    ok = status == 404 and d.get("found") is False
    record(PASS if ok else FAIL, "evidence verification is public",
           "unknown hash -> found=false" if ok else "HTTP %s" % status)


def check_authenticated(c, password):
    """One real scan, end to end. Without this, 'it deployed' means very little."""
    status, body, _ = c.request("/auth/login")
    m = re.search(r'name="csrf_token" value="([^"]+)"', body)
    if not m:
        record(FAIL, "login form carries a CSRF token", "not found")
        return
    status, body, _ = c.request("/auth/login", data={
        "csrf_token": m.group(1), "username": "admin", "password": password})
    if status not in (301, 302):
        record(FAIL, "admin can sign in", "HTTP %s — wrong ADMIN_PASSWORD?" % status)
        return
    record(PASS, "admin can sign in", "")

    status, body, _ = c.request("/")
    meta = re.search(r'name="csrf-token" content="([^"]+)"', body)
    token = meta.group(1) if meta else ""
    record(PASS if status == 200 else FAIL, "dashboard renders for a session",
           "HTTP %s" % status)

    hdrs = {"Content-Type": "application/json", "X-CSRFToken": token,
            "X-Requested-With": "XMLHttpRequest"}

    # An NFC record exercises the full analyse -> graph -> evidence path with
    # no file upload, so it works over any connection.
    status, body, _ = c.request("/nfc/scan", data=json.dumps({"records": [
        {"recordType": "url",
         "data": "upi://pay?pa=refund.desk@fakepsp&pn=SBI REFUND&am=500"}]}),
        headers=hdrs)
    d = as_json(body) or {}
    ok = status == 200 and d.get("classification") in ("SUSPICIOUS", "HIGH_RISK")
    record(PASS if ok else FAIL, "a real scan runs end to end",
           "NFC scam UPI -> %s (%s)" % (d.get("classification"), d.get("score"))
           if ok else "HTTP %s" % status)

    status, body, _ = c.request("/admin/api/operations", headers=hdrs)
    d = as_json(body) or {}
    ok = status == 200 and "billing" in d
    record(PASS if ok else FAIL, "operations dashboard data",
           "tenants=%s emergency=%s" % (d.get("billing", {}).get("tenant_count"),
                                        d.get("emergency", {}).get("active"))
           if ok else "HTTP %s" % status)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("base_url")
    ap.add_argument("--admin-password",
                    help="Runs the authenticated checks, including one real scan")
    ap.add_argument("--wait", type=int, default=180,
                    help="Seconds to wait for models to finish loading (default 180)")
    args = ap.parse_args()

    base = args.base_url.rstrip("/")
    print("=" * 72)
    print("CYBERSURAKSHAA — post-deployment smoke test")
    print("target: %s" % base)
    print("=" * 72)

    c = Client(base)
    check_liveness(c)
    check_readiness(c, args.wait)
    check_public_surfaces(c)
    check_verification_endpoint(c)
    check_auth_required(c)
    check_security_posture(c, base)

    if args.admin_password:
        print("-" * 72)
        check_authenticated(c, args.admin_password)
    else:
        record(INFO, "authenticated checks", "skipped — pass --admin-password to run")

    failures = [r for r in _results if r[0] == FAIL]
    warnings = [r for r in _results if r[0] == WARN]

    print("=" * 72)
    print("%d passed, %d failed, %d warnings"
          % (len([r for r in _results if r[0] == PASS]), len(failures), len(warnings)))
    if failures:
        print("\nFAILED:")
        for _, label, detail in failures:
            print("  - %s  (%s)" % (label, detail))
        print("\nDeployment is NOT ready.")
        return 1
    print("\nDeployment verified." if not warnings else
          "\nDeployment usable; review the warnings above.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
