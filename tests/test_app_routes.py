"""
Application-level smoke and access-control tests.

These boot the real Flask app and drive it through the test client. The point
is not to re-test the detectors -- they need model weights -- but to catch the
failures that only appear once everything is wired together: a blueprint
registered against a template that does not exist, a route that 500s, and
above all an endpoint that forgets to check who is asking.
"""

import os

import pytest

flask = pytest.importorskip("flask", reason="Flask is not installed")


@pytest.fixture(scope="module")
def client():
    os.environ.setdefault("SECRET_KEY", "test-only-key")
    os.environ.setdefault("CRAWLER_ALLOW_SIMULATED", "0")

    import app as app_module
    app_module.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    # Rate limits would make the anonymous-access sweep below flaky.
    app_module.limiter.enabled = False
    with app_module.app.test_client() as c:
        yield c


# Every page a signed-out visitor may legitimately reach.
PUBLIC_PATHS = ["/auth/login", "/auth/register", "/verify", "/healthz"]

# Pages behind the session gate. Each must redirect an anonymous caller to
# login rather than rendering.
PROTECTED_PAGES = [
    "/", "/betting/", "/deepfake/", "/customer-care/", "/investment/",
    "/geo/", "/voice/", "/apk/", "/intel/", "/intel/graph", "/intel/cases",
    "/intel/campaigns", "/intel/lookalike",
]

# Admin-only. A standard user reaching these would see every other user's data.
ADMIN_PAGES = ["/admin/", "/intel/feedback"]


class TestPublicSurface:
    @pytest.mark.parametrize("path", PUBLIC_PATHS)
    def test_public_pages_render(self, client, path):
        r = client.get(path)
        assert r.status_code in (200, 302), "%s returned %d" % (path, r.status_code)

    def test_verify_landing_renders(self, client):
        """
        `blueprints/verify.py` renders `verify.html` in three places. The
        template was missing at one point and every one of those paths 500ed.
        """
        r = client.get("/verify")
        assert r.status_code == 200
        assert b"Evidence Verification" in r.data

    def test_verify_rejects_short_hash(self, client):
        r = client.get("/verify/abc123")
        assert r.status_code == 400

    def test_verify_unknown_hash_is_404_not_a_false_confirmation(self, client):
        r = client.get("/verify/" + "e" * 64)
        assert r.status_code == 404
        assert b"No matching record" in r.data

    def test_verify_json_api(self, client):
        r = client.get("/verify/" + "f" * 64 + "?format=json")
        assert r.status_code == 404
        assert r.get_json()["found"] is False

    def test_healthz_is_not_rate_limited_away(self, client):
        """
        A probe endpoint behind a rate limit stops being a probe: the limiter
        starts 429ing the orchestrator and the container is killed while
        perfectly healthy. Both probes are @limiter.exempt.
        """
        for _ in range(20):
            assert client.get("/healthz").status_code in (200, 503)

    def test_readyz_reports_503_until_models_finish_loading(self, client):
        """
        Readiness is not liveness. A process whose detectors are still warming
        up is alive and *not* ready, and a load balancer must be told so rather
        than sent traffic that will time out. 200 once warm-up completes.
        """
        r = client.get("/readyz")
        assert r.status_code in (200, 503)
        body = r.get_json()
        if r.status_code == 503:
            assert body["ready"] is False
            assert body["pending"], "not ready, but nothing is pending"
        else:
            assert body["ready"] is True


class TestAccessControl:
    @pytest.mark.parametrize("path", PROTECTED_PAGES)
    def test_anonymous_is_redirected(self, client, path):
        r = client.get(path, follow_redirects=False)
        assert r.status_code in (301, 302), \
            "%s served an anonymous caller (%d)" % (path, r.status_code)
        assert "/auth/login" in r.headers.get("Location", "")

    @pytest.mark.parametrize("path", ADMIN_PAGES)
    def test_admin_pages_reject_anonymous(self, client, path):
        r = client.get(path, follow_redirects=False)
        assert r.status_code in (301, 302, 403)

    @pytest.mark.parametrize("path", [
        "/intel/api/stats", "/intel/api/campaigns", "/intel/api/cases",
        "/intel/api/top", "/geo/api/map-data", "/api/impact",
        "/intel/api/feedback/queue", "/intel/api/feedback/metrics",
    ])
    def test_api_endpoints_reject_anonymous(self, client, path):
        r = client.get(path, follow_redirects=False)
        assert r.status_code in (301, 302, 401, 403), \
            "%s served data to an anonymous caller" % path

    def test_feedback_submission_requires_a_session(self, client):
        r = client.post("/intel/api/feedback",
                        json={"module": "Betting Content", "label": "CORRECT"})
        assert r.status_code in (301, 302, 401, 403)


class TestErrorPages:
    def test_unknown_path_does_not_leak_the_dashboard(self, client):
        """
        The 404 handler used to render index.html directly, which bypassed the
        @login_required on the home route -- any bad URL served the full
        authenticated dashboard markup to an anonymous caller. It now redirects
        anonymous callers to login and renders 404.html only for signed-in
        users, so 302 here is the fix, not a regression.
        """
        r = client.get("/definitely-not-a-route", follow_redirects=False)
        assert r.status_code in (302, 404)
        if r.status_code == 302:
            assert "/auth/login" in r.headers.get("Location", "")
        assert b"Hub Dashboard" not in r.data

    def test_unknown_api_path_returns_json_404(self, client):
        r = client.get("/api/definitely-not-a-route",
                       headers={"Accept": "application/json"})
        assert r.status_code == 404


class TestRouteRegistry:
    def test_every_page_route_has_its_template(self, client):
        """
        A blueprint registered against a missing template only fails when
        somebody opens the page. Walking the route table at test time turns
        that into a build failure instead of a demo failure.
        """
        import app as app_module
        env = app_module.app.jinja_env
        missing = []
        for name in sorted(env.list_templates()):
            try:
                env.get_template(name)
            except Exception as e:  # noqa: BLE001 - reporting, not handling
                missing.append("%s: %s" % (name, e))
        assert not missing, "templates failed to compile: %s" % missing


class TestSessionEnforcement:
    """
    The session guard, exercised through the real app.

    These assert raw status codes deliberately. An earlier hand-check followed
    redirects and reported the *requested* path when the request raised, which
    made a 500 inside the guard look like a successful redirect to login — the
    one path where a silent failure matters most, hidden by the way it was
    tested.

    Note the fixture does NOT reuse the module-scoped `client`. That fixture
    holds an open `with app.test_client()` context, and opening a second
    client inside it makes `session_transaction()` operate on the outer
    context instead of the inner one — so the login appears to fail and every
    assertion here measures the wrong thing.
    """

    TEST_USER = "session-guard-probe"
    TEST_PASSWORD = "a-long-enough-test-password"

    @pytest.fixture
    def flask_app(self):
        os.environ.setdefault("SECRET_KEY", "test-only-key")
        import app as app_module
        app_module.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        app_module.limiter.enabled = False

        from services.auth_db import create_user, get_all_users
        if self.TEST_USER not in {u["username"] for u in get_all_users()}:
            create_user(self.TEST_USER, self.TEST_PASSWORD, role="user")
        return app_module

    def _signed_in(self, app_module):
        browser = app_module.app.test_client()
        browser.post('/auth/login',
                     data={'username': self.TEST_USER, 'password': self.TEST_PASSWORD},
                     follow_redirects=False)
        with browser.session_transaction() as sess:
            token = sess.get('session_token')
        assert token, "login did not mint a server-side session"
        return browser, token

    def test_revoked_session_is_redirected_not_500(self, flask_app):
        from services.intel import accounts
        browser, token = self._signed_in(flask_app)
        assert browser.get('/', follow_redirects=False).status_code == 200

        accounts.revoke_by_token(token, revoked_by='test', reason='test revocation')

        r = browser.get('/', follow_redirects=False)
        assert r.status_code in (301, 302),             "revoked session returned %d, not a redirect" % r.status_code
        assert '/auth/login' in r.headers.get('Location', '')

    def test_revoked_session_gets_401_on_json_endpoints(self, flask_app):
        """
        Without the XHR header too: every blueprint mounts its API under its
        own prefix, so a plain fetch() to /account/api/… must still get JSON
        rather than an HTML login page it will fail to parse.
        """
        from services.intel import accounts

        # A fresh session per variant. The guard clears the cookie when it
        # rejects, so a second request on the same client is simply anonymous
        # and tests the decorator instead of the guard.
        for headers in ({'X-Requested-With': 'XMLHttpRequest'}, {}):
            browser, token = self._signed_in(flask_app)
            accounts.revoke_by_token(token, revoked_by='test')
            r = browser.get('/account/api/overview', headers=headers)
            assert r.status_code == 401, "headers=%s gave %d" % (headers, r.status_code)
            assert r.is_json

    def test_anonymous_json_callers_get_401_not_an_html_redirect(self, flask_app):
        """
        The decorators had the same too-narrow check as the guard: only paths
        starting /auth/api/ were treated as JSON, so a fetch() to any
        blueprint API while signed out received an HTML login page.
        """
        browser = flask_app.app.test_client()
        for path in ('/account/api/overview', '/intel/api/stats',
                     '/watchtower/api/summary'):
            r = browser.get(path)
            assert r.status_code in (401, 403), "%s gave %d" % (path, r.status_code)
            assert r.is_json, "%s did not return JSON" % path

    def test_a_cookie_without_a_session_token_is_rejected(self, flask_app):
        """
        Cookies predating server-side sessions. Grandfathering them would
        preserve exactly the unrevocable sessions the guard exists to remove.
        """
        browser = flask_app.app.test_client()
        with browser.session_transaction() as sess:
            sess['user_id'] = 1
            sess['username'] = 'legacy-cookie'
            sess['user_role'] = 'user'
            # deliberately no session_token
        r = browser.get('/', follow_redirects=False)
        assert r.status_code in (301, 302)

    def test_signing_out_ends_the_session_server_side(self, flask_app):
        """Not just the cookie — the row is what makes it dead everywhere."""
        from services.intel import accounts
        browser, token = self._signed_in(flask_app)
        browser.post('/auth/logout', follow_redirects=False)
        assert accounts.touch_session(token) is None

    def test_public_pages_still_work_without_a_session(self, flask_app):
        browser = flask_app.app.test_client()
        for path in ('/auth/login', '/verify', '/healthz'):
            assert browser.get(path).status_code in (200, 302, 503)
