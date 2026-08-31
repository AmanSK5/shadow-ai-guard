"""The portal login: sessions from the receiver, carried as a cookie.

Managed mode is login mode - the receiver owns the admin account, the portal
signs in against it, and the session rides as an HttpOnly cookie the page
script can never read. These tests call route functions and dependencies
directly, like the rest of the suite (no TestClient: the portal deliberately
has no HTTP client dependency), with receiver_request stubbed and recorded.
"""

import asyncio
import os

os.environ.setdefault("PORTAL_AUTH", "none")

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app import main, managed


def _request(cookie_token=None, scheme="http", headers=()):
    hs = [(b"host", b"portal")] + [(k.encode(), v.encode()) for k, v in headers]
    if cookie_token is not None:
        hs.append((b"cookie",
                   ("%s=%s" % (main.SESSION_COOKIE, cookie_token)).encode()))
    return Request({"type": "http", "method": "GET", "path": "/",
                    "scheme": scheme, "headers": hs, "query_string": b""})


@pytest.fixture
def login_mode(monkeypatch):
    """Managed mode with real auth (the test env sets PORTAL_AUTH=none at
    import, which would short-circuit require_auth), a recorded receiver,
    and a clean session cache."""
    calls = []

    def fake(base, method, path, token, body=None):
        calls.append({"method": method, "path": path, "token": token,
                      "body": body})
        if path == "/admin/session":
            return {"username": "aman", "expires_at": "2027-01-01T00:00:00+00:00"}
        if method == "POST" and path == "/admin/login":
            return {"token": "aigt_NEW", "username": body["username"],
                    "expires_at": "2027-01-01T00:00:00+00:00"}
        if method == "GET" and path == "/admin/setup":
            return {"needed": True}
        if method == "POST" and path == "/admin/setup":
            return {"token": "aigt_FIRST", "username": body["username"],
                    "expires_at": "2027-01-01T00:00:00+00:00"}
        return {"ok": True}

    monkeypatch.setattr(main, "PORTAL_AUTH", "")
    monkeypatch.setattr(main, "RECEIVER_URL", "http://receiver.internal:8080")
    monkeypatch.setattr(main, "LOGIN_MODE", True)
    monkeypatch.setattr(main.managed, "receiver_request", fake)
    monkeypatch.setattr(main, "_session_cache", {})
    return calls


def http_error(fn, *args, **kw) -> HTTPException:
    with pytest.raises(HTTPException) as e:
        fn(*args, **kw)
    return e.value


# ------------------------------------------------------------ the read gate --


def test_no_cookie_is_a_401_page_not_a_browser_dialog(login_mode):
    err = http_error(main.require_auth, _request(), None)
    assert err.status_code == 401
    # No WWW-Authenticate: the login is a page the SPA draws, and the header
    # would put a basic-auth dialog in front of it.
    assert not (err.headers or {}).get("WWW-Authenticate")


def test_a_live_session_passes_and_is_cached(login_mode):
    main.require_auth(_request(cookie_token="aigt_s"), None)
    main.require_auth(_request(cookie_token="aigt_s"), None)
    # One validation for the pair: the second ran inside the positive cache.
    assert len(login_mode) == 1
    assert login_mode[0] == {"method": "GET", "path": "/admin/session",
                             "token": "aigt_s", "body": None}


def test_a_refused_session_is_401_and_never_cached(login_mode, monkeypatch):
    def refuse(base, method, path, token, body=None):
        login_mode.append({"path": path})
        raise managed.ReceiverError(401, "bad token")
    monkeypatch.setattr(main.managed, "receiver_request", refuse)

    for _ in range(2):
        err = http_error(main.require_auth, _request(cookie_token="aigt_dead"), None)
        assert err.status_code == 401
    # Refused twice, asked twice: a no is never cached, so a revocation
    # holds from the next request.
    assert len(login_mode) == 2


def test_an_unreachable_receiver_is_a_502_not_an_answer(login_mode, monkeypatch):
    """Unreachable must not read as revoked, and it must certainly not read
    as valid."""
    def down(base, method, path, token, body=None):
        raise managed.ReceiverError(502, "could not reach the receiver (X)")
    monkeypatch.setattr(main.managed, "receiver_request", down)

    err = http_error(main.require_auth, _request(cookie_token="aigt_s"), None)
    assert err.status_code == 502


def test_the_page_shell_is_open_in_login_mode(login_mode):
    """The shell holds no estate data and has to load for the login screen
    to exist; every API it calls is still gated."""
    assert main.require_page_auth(_request(), None) is None


def test_classic_mode_keeps_basic_auth_on_the_shell(monkeypatch):
    monkeypatch.setattr(main, "LOGIN_MODE", False)
    monkeypatch.setattr(main, "PORTAL_AUTH", "")
    monkeypatch.setattr(main, "PORTAL_USER", "u")
    monkeypatch.setattr(main, "PORTAL_PASSWORD", "p")
    err = http_error(main.require_page_auth, _request(), None)
    assert err.status_code == 401
    assert (err.headers or {}).get("WWW-Authenticate") == "Basic"


# ----------------------------------------------------------------- /api/auth --


def test_auth_state_in_classic_mode_names_the_mode_and_calls_nothing(monkeypatch):
    calls = []
    monkeypatch.setattr(main, "LOGIN_MODE", False)
    monkeypatch.setattr(main, "PORTAL_AUTH", "")
    monkeypatch.setattr(main.managed, "receiver_request",
                        lambda *a, **k: calls.append(a))
    out = main.auth_state(_request())
    assert out["mode"] == "basic" and out["setup_needed"] is False
    assert calls == []


def test_auth_state_offers_create_account_on_a_fresh_receiver(login_mode):
    out = main.auth_state(_request())
    assert out == {"mode": "login", "authenticated": False, "username": "",
                   "role": "", "setup_needed": True, "sso": False,
                   "sso_enforced": False}
    # It asked the receiver's unauthenticated probe, nothing else.
    assert [c["path"] for c in login_mode] == ["/admin/setup"]


def test_the_sign_in_screen_is_told_when_federated_sign_in_is_on(monkeypatch):
    """The screen cannot offer the Entra button to somebody who has no
    password here unless it is told, and it is asking before anyone has
    authenticated - so the bit rides on the one unauthenticated probe."""
    def fake(base, method, path, token, body=None):
        assert path == "/admin/setup"
        return {"needed": False, "sso_enabled": True}

    monkeypatch.setattr(main.managed, "receiver_request", fake)
    monkeypatch.setattr(main, "LOGIN_MODE", True)
    monkeypatch.setattr(main, "PORTAL_AUTH", "login")
    assert main.auth_state(_request(cookie_token=None))["sso"] is True


def test_a_receiver_too_old_to_report_it_reads_as_off(monkeypatch):
    """The key is absent, not false, and absent has to mean the screen it
    was serving before this existed."""
    monkeypatch.setattr(main.managed, "receiver_request",
                        lambda *a, **k: {"needed": False})
    monkeypatch.setattr(main, "LOGIN_MODE", True)
    monkeypatch.setattr(main, "PORTAL_AUTH", "login")
    assert main.auth_state(_request(cookie_token=None))["sso"] is False


def test_auth_state_with_a_live_session_says_who(login_mode):
    out = main.auth_state(_request(cookie_token="aigt_s"))
    assert out["authenticated"] is True and out["username"] == "aman"
    assert out["setup_needed"] is False


# ------------------------------------------------------------- login/logout --


def _cookie(resp):
    return resp.headers.get("set-cookie") or ""


def test_login_proxies_and_sets_the_cookie_the_page_cannot_read(login_mode):
    resp = main.api_login(main.LoginRequest(username="aman", password="pw"),
                          _request())
    c = _cookie(resp)
    assert "aiguard_session=aigt_NEW" in c
    assert "HttpOnly" in c and "SameSite=strict" in c.replace("Strict", "strict")
    assert "Path=/" in c
    # Plain HTTP login: no Secure, or the cookie would never come back on
    # the documented localhost and behind-a-plain-proxy paths.
    assert "Secure" not in c
    assert login_mode[0]["path"] == "/admin/login"
    assert login_mode[0]["body"] == {"username": "aman", "password": "pw"}


def test_the_cookie_is_secure_when_the_login_arrived_over_tls(login_mode):
    for req in (_request(scheme="https"),
                _request(headers=[("x-forwarded-proto", "https")])):
        resp = main.api_login(
            main.LoginRequest(username="aman", password="pw"), req)
        assert "Secure" in _cookie(resp)


def test_a_refused_login_passes_the_receivers_answer_through(login_mode, monkeypatch):
    def refuse(base, method, path, token, body=None):
        raise managed.ReceiverError(401, "bad username or password")
    monkeypatch.setattr(main.managed, "receiver_request", refuse)
    err = http_error(main.api_login,
                     main.LoginRequest(username="aman", password="no"),
                     _request())
    assert err.status_code == 401
    assert err.detail == "bad username or password"


def test_setup_claims_the_code_and_arrives_signed_in(login_mode):
    resp = main.api_setup(
        main.SetupRequest(setup_code="aigs_code", username="aman",
                          password="a-long-enough-password"), _request())
    assert "aiguard_session=aigt_FIRST" in _cookie(resp)
    assert login_mode[0]["body"]["setup_code"] == "aigs_code"


def test_setup_enforces_the_password_floor_at_the_edge():
    with pytest.raises(ValueError):
        main.SetupRequest(setup_code="c", username="u", password="short")


def test_logout_revokes_remotely_flushes_the_cache_and_kills_the_cookie(login_mode):
    main.require_auth(_request(cookie_token="aigt_s"), None)  # warm the cache
    resp = main.api_logout(_request(cookie_token="aigt_s"))
    assert [c["path"] for c in login_mode] == ["/admin/session", "/admin/logout"]
    assert login_mode[1]["token"] == "aigt_s"
    assert "aigt_s" not in main._session_cache
    c = _cookie(resp)
    assert "aiguard_session=" in c and ("Max-Age=0" in c or "expires" in c.lower())


def test_logout_still_clears_the_cookie_when_the_receiver_is_down(login_mode, monkeypatch):
    def down(base, method, path, token, body=None):
        raise managed.ReceiverError(502, "could not reach the receiver (X)")
    monkeypatch.setattr(main.managed, "receiver_request", down)
    resp = main.api_logout(_request(cookie_token="aigt_s"))
    assert "Max-Age=0" in _cookie(resp) or "expires" in _cookie(resp).lower()


def test_login_routes_do_not_exist_in_classic_mode(monkeypatch):
    monkeypatch.setattr(main, "LOGIN_MODE", False)
    for call in (
        lambda: main.api_login(
            main.LoginRequest(username="u", password="p"), _request()),
        lambda: main.api_setup(
            main.SetupRequest(setup_code="c", username="u",
                              password="a-long-enough-password"), _request()),
        lambda: main.api_logout(_request()),
    ):
        assert http_error(call).status_code == 404


# -------------------------------------------------------------------- CSRF --


def _post_through_middleware(path, content_type):
    class _Url:
        pass

    class _Req:
        method = "POST"
        url = _Url()
        headers = {"content-type": content_type} if content_type else {}
    _Req.url.path = path

    async def _next(req):
        return "passed"

    async def run():
        return await main.json_posts_only(_Req(), _next)
    return asyncio.run(run())


def test_a_post_without_json_content_type_is_refused(login_mode):
    """The CSRF half that cookies made necessary: a cross-site form cannot
    declare application/json, so requiring it (with SameSite=Strict) closes
    what the old in-memory header token used to close by construction."""
    resp = _post_through_middleware("/api/enrollment-tokens", "text/plain")
    assert resp.status_code == 415
    resp = _post_through_middleware("/api/login", None)
    assert resp.status_code == 415
    assert _post_through_middleware("/api/login", "application/json") == "passed"


def test_the_json_rule_is_login_mode_only(monkeypatch):
    monkeypatch.setattr(main, "LOGIN_MODE", False)
    assert _post_through_middleware("/api/login", "text/plain") == "passed"


# ------------------------------------------------------------ startup shapes --


def _import_portal(env):
    import subprocess
    import sys

    base = {k: v for k, v in os.environ.items()
            if k not in ("PORTAL_AUTH", "PORTAL_USER", "PORTAL_PASSWORD",
                         "RECEIVER_URL")}
    return subprocess.run(
        [sys.executable, "-c", "import app.main"], env={**base, **env},
        capture_output=True, text=True,
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_managed_mode_starts_without_a_basic_auth_pair():
    """The fresh-install path: helm install sets RECEIVER_URL and nothing
    else auth-shaped, and the portal must come up with its login rather
    than refuse to start."""
    proc = _import_portal({"RECEIVER_URL": "http://receiver:8080"})
    assert proc.returncode == 0, proc.stderr


def test_classic_mode_still_fails_closed():
    proc = _import_portal({})
    assert proc.returncode != 0
    assert "refusing to start" in proc.stderr


def test_a_basic_auth_pair_in_managed_mode_is_named_as_ignored():
    proc = _import_portal({"RECEIVER_URL": "http://receiver:8080",
                           "PORTAL_USER": "u", "PORTAL_PASSWORD": "p"})
    assert proc.returncode == 0
    assert "ignored in managed mode" in proc.stderr


# -------------------------------------------------------------- the page --


def test_the_page_no_longer_carries_an_admin_token_field():
    html = (main.STATIC / "index.html").read_text()
    assert "X-Admin-Token" not in html
    assert "admin-token-input" not in html
    # And it carries the login instead, wired through delegated handlers
    # like everything else.
    for needle in ("do-login", "do-setup", "/api/auth", "/api/login",
                   "/api/setup", "/api/logout"):
        assert needle in html, needle


def test_diagnostics_report_the_login_mode(login_mode):
    # request=None: in login mode the custom entries need a session cookie
    # to read, and this test is about auth_mode, not the registry counts.
    out = main.diagnostics(request=None, _=None)
    assert out["runtime"]["auth_mode"] == "login"


# --------------------------------------------------- the callback's two jobs --


def test_the_wizards_test_sign_in_stays_put():
    """The wizard's test has its answer the moment the message lands, so
    the tab must not navigate into the portal afterwards."""
    html = main._sso_page("Signed in", "Taking you to the portal.",
                          go="/", who="gengar", test=True).body.decode()
    assert 'window.opener.postMessage' in html
    # The payload is HTML-escaped into an attribute on purpose - see the
    # note in _sso_page about provider text and script contexts.
    assert "&quot;test&quot;: true" in html
    # The return is what stops the navigation below it running.
    assert 'dataset.test="1";return;' in html
    assert "You can close this tab" in html


def test_a_real_sign_in_goes_to_the_portal():
    """Somebody actually arriving must land in the portal, and must not be
    told to close their tab and go back to a wizard they never opened."""
    html = main._sso_page("Signed in", "Taking you to the portal.",
                          go="/", who="gengar").body.decode()
    assert "&quot;test&quot;: false" in html
    assert 'dataset.test' in html          # the branch exists
    assert "if(r.go)location.replace(r.go)" in html
    assert 'href="/"' in html


def test_the_marker_does_not_come_from_window_opener():
    """It used to. An opener is set by ANY link opened in a new tab, so
    somebody who opened the sign-in screen that way and signed in normally
    was told to close their tab and left sitting on the callback page.
    The flag now travels with the sign-in that started it."""
    html = main._sso_page("Signed in", "x", go="/", who="a").body.decode()
    assert "if(window.opener){" not in html
    assert 'dataset.opener' not in html
