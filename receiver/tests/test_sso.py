"""Federated sign-in: what it refuses, and what it binds to.

The flow itself is ordinary OpenID Connect. What is worth holding here is
the part that is specific to this product and easy to get wrong: which
claim an account is matched on, and the fact that no sign-in ever creates
one.

Microsoft's own guidance is the reason for the first: an address "isn't
guaranteed to be correct and is mutable over time. Never use it for
authorization", because addresses get reassigned. A joiner inheriting a
leaver's address would otherwise inherit their account and their role.
"""

import asyncio
import json
import os
import time

os.environ.setdefault("AUTH_TOKEN", "test-token-for-ci")

import pytest

from app import main
from app import state as state_mod

PASSWORD = "a-long-enough-password"
TENANT = "11111111-2222-3333-4444-555555555555"


@pytest.fixture
def managed(tmp_path, monkeypatch):
    st = state_mod.State(str(tmp_path / "state.db"))
    monkeypatch.setattr(main, "STATE", st)
    monkeypatch.setattr(main, "_EXPECTED_ADMIN", b"Bearer admin-test-token")
    st.create_admin("root", PASSWORD)
    yield st


# ------------------------------------------------------------- the match --


def test_an_address_matches_only_until_it_is_bound(managed):
    """The address is an invitation, spent the first time somebody accepts
    it. After that the immutable pair is the only thing that signs the
    account in."""
    managed.create_user("jo", PASSWORD, "viewer", by="t", email="jo@example.com")
    uid = next(u["id"] for u in managed.list_users() if u["username"] == "jo")

    found = managed.sso_account(TENANT, "oid-jo", "jo@example.com")
    assert found["id"] == uid and found["bound"] is False
    managed.sso_bind(uid, TENANT, "oid-jo")

    # Bound: the pair finds it whatever the address now says.
    again = managed.sso_account(TENANT, "oid-jo", "someone-else@example.com")
    assert again["id"] == uid and again["bound"] is True


def test_a_reused_address_cannot_take_over_a_bound_account(managed):
    """The failure this design exists to prevent: somebody leaves, a joiner
    is given their address, and signs in as them."""
    managed.create_user("jo", PASSWORD, "admin", by="t", email="jo@example.com")
    uid = next(u["id"] for u in managed.list_users() if u["username"] == "jo")
    managed.sso_bind(uid, TENANT, "oid-the-leaver")

    # The joiner: same address, different object id.
    assert managed.sso_account(TENANT, "oid-the-joiner", "jo@example.com") is None


def test_an_account_is_never_created_by_a_sign_in(managed):
    """Somebody who can set an address in a tenant cannot mint themselves a
    way in here. Every account exists because a person decided it should."""
    assert managed.sso_account(TENANT, "oid-nobody", "stranger@example.com") is None


def test_an_account_with_no_address_cannot_be_reached(managed):
    """Which is what makes one usable as a shared break-glass credential:
    a password in a password manager, reachable by nobody through the
    provider."""
    assert managed.list_users()[0]["email"] is None
    assert managed.sso_account(TENANT, "oid-anything", "") is None
    assert managed.sso_account(TENANT, "oid-anything", "root@example.com") is None


def test_one_federated_identity_signs_in_one_account(managed):
    managed.create_user("a", PASSWORD, "viewer", by="t", email="a@example.com")
    managed.create_user("b", PASSWORD, "viewer", by="t", email="b@example.com")
    ids = {u["username"]: u["id"] for u in managed.list_users()}
    managed.sso_bind(ids["a"], TENANT, "oid-shared")
    with pytest.raises(Exception):
        managed.sso_bind(ids["b"], TENANT, "oid-shared")


def test_rebinding_a_bound_account_is_refused(managed):
    """Rebinding is how an address change would move somebody else's
    account, which is what binding exists to stop."""
    managed.create_user("jo", PASSWORD, "viewer", by="t", email="jo@example.com")
    uid = next(u["id"] for u in managed.list_users() if u["username"] == "jo")
    managed.sso_bind(uid, TENANT, "oid-one")
    with pytest.raises(state_mod.AuthError) as e:
        managed.sso_bind(uid, TENANT, "oid-two")
    assert e.value.status == 409


def test_unbinding_obeys_the_rank_rule(managed):
    """Unbinding an account above yours would let you re-bind it to
    yourself on the next sign-in."""
    owner = next(u["id"] for u in managed.list_users() if u["role"] == "owner")
    managed.sso_bind(owner, TENANT, "oid-owner")
    with pytest.raises(state_mod.AuthError) as e:
        managed.sso_unbind(owner, by="operator", by_role="admin")
    assert e.value.status == 403
    assert managed.sso_unbind(owner, by="root", by_role="owner") is True


# ------------------------------------------------------------ the session --


def test_a_federated_session_carries_the_accounts_role(managed):
    managed.create_user("jo", PASSWORD, "admin", by="t", email="jo@example.com")
    uid = next(u["id"] for u in managed.list_users() if u["username"] == "jo")
    out = managed.sso_login(uid)
    assert out["role"] == "admin" and out["username"] == "jo"
    assert managed.session_user(out["token"])["user_id"] == uid


def test_the_endpoints_are_absent_until_it_is_configured(managed):
    """An estate that has not configured federated sign-in does not
    advertise the endpoint."""
    from fastapi.testclient import TestClient
    c = TestClient(main.app)
    assert c.get("/admin/sso/start").status_code == 404


def test_a_callback_without_a_live_state_is_refused(managed):
    """What protects an unauthenticated endpoint: the state it must quote
    was minted here minutes earlier, is single-use, and is paired with a
    verifier the browser never saw."""
    from fastapi.testclient import TestClient
    c = TestClient(main.app)
    r = c.post("/admin/sso/callback",
               json={"code": "anything", "state": "never-minted"})
    assert r.status_code == 200 and r.json()["ok"] is False
    assert "expired or was not started here" in r.json()["detail"]


def test_a_state_is_single_use(managed):
    from fastapi.testclient import TestClient
    c = TestClient(main.app)
    main._SSO_FLIGHT["s1"] = {"nonce": "n", "verifier": "v", "at": time.time(),
                              "issuer": "i", "token_endpoint": "http://x"}
    c.post("/admin/sso/callback", json={"code": "c", "state": "s1"})
    assert "s1" not in main._SSO_FLIGHT


# ----------------------------------------------------- enforced sign-in --
# Requiring single sign-on is how an estate gets its multi-factor policy in
# front of this portal. The whole risk of it is lockout, so most of what is
# held here is about the one account that can still get in, and about not
# letting the feature be switched on before it has been shown to work.


def _bind_owner(st, email="root@example.com"):
    """Give the setup account an address and a completed federated sign-in."""
    uid = next(u["id"] for u in st.list_users() if u["username"] == "root")
    st.set_user_email(uid, email, by="t", by_role="owner")
    st.sso_bind(uid, TENANT, "subject-root")
    return uid


def test_the_setup_account_is_the_break_glass_account(managed):
    """Not a choice anybody makes. An escape hatch somebody has to remember
    to nominate is the one that is missing on the day it is needed."""
    users = {u["username"]: u for u in managed.list_users()}
    assert users["root"]["break_glass"] == 1
    managed.create_user("jo", PASSWORD, "admin", by="t", by_role="owner")
    later = {u["username"]: u for u in managed.list_users()}
    assert later["jo"]["break_glass"] == 0
    assert managed.break_glass_username() == "root"


def test_enforcement_is_refused_until_an_owner_has_actually_signed_in(managed):
    """An address on an account is an intention. A binding is the provider
    having answered for somebody who can still turn this back off."""
    managed.set_setting("sso_enabled", "1", "t")
    assert managed.an_owner_is_bound() is False
    owner = "Bearer " + managed.login("root", PASSWORD)["token"]
    with pytest.raises(main.HTTPException) as e:
        main.put_settings(main.SettingsUpdate(sso_enforce="1"),
                          authorization=owner)
    assert e.value.status_code == 422
    assert "completed a single sign-on" in e.value.detail
    assert managed.get_setting("sso_enforce") is None

    # Bound, and now it is allowed.
    _bind_owner(managed)
    main.put_settings(main.SettingsUpdate(sso_enforce="1"), authorization=owner)
    assert managed.get_setting("sso_enforce") == "1"


def test_enforcement_is_refused_while_single_sign_on_itself_is_off(managed):
    _bind_owner(managed)
    owner = "Bearer " + managed.login("root", PASSWORD)["token"]
    with pytest.raises(main.HTTPException) as e:
        main.put_settings(main.SettingsUpdate(sso_enforce="1"),
                          authorization=owner)
    assert e.value.status_code == 422
    assert "has to be on" in e.value.detail


def test_enforced_sign_in_refuses_a_correct_password(managed):
    managed.set_setting("sso_enabled", "1", "t")
    _bind_owner(managed)
    managed.create_user("jo", PASSWORD, "admin", by="t", by_role="owner")
    managed.set_setting("sso_enforce", "1", "t")

    with pytest.raises(state_mod.AuthError) as e:
        managed.login("jo", PASSWORD)
    # 403 and not 401: the credential was right, the policy refused. The
    # caller needs the difference to keep this off the failure throttle.
    assert e.value.status == 403
    assert "single sign-on" in e.value.detail


def test_a_wrong_password_still_answers_the_same_under_enforcement(managed):
    """Enforcement is checked after the password verifies, so somebody with
    no credential cannot walk a list of usernames and read off which one is
    the escape hatch."""
    managed.set_setting("sso_enabled", "1", "t")
    _bind_owner(managed)
    managed.create_user("jo", PASSWORD, "admin", by="t", by_role="owner")
    managed.set_setting("sso_enforce", "1", "t")

    for name in ("jo", "root", "nobody-at-all"):
        with pytest.raises(state_mod.AuthError) as e:
            managed.login(name, "the-wrong-password-entirely")
        assert e.value.status == 401
        assert e.value.detail == "bad username or password"


def test_the_break_glass_account_still_gets_in_and_says_so(managed):
    managed.set_setting("sso_enabled", "1", "t")
    _bind_owner(managed)
    managed.set_setting("sso_enforce", "1", "t")

    out = managed.login("root", PASSWORD)
    assert out["token"].startswith(state_mod.SESSION_PREFIX)
    kinds = [e["kind"] for e in managed.list_events(50)]
    assert "break_glass_login" in kinds


def test_the_break_glass_account_cannot_be_removed_while_it_is_load_bearing(managed):
    managed.set_setting("sso_enabled", "1", "t")
    uid = _bind_owner(managed)
    # A second owner, so what refuses below is the break-glass guard and
    # not the older "cannot remove the last owner" one.
    managed.create_user("second", PASSWORD, "owner", by="t", by_role="owner")
    managed.set_setting("sso_enforce", "1", "t")

    with pytest.raises(state_mod.AuthError) as e:
        managed.delete_user(uid, by="t", by_role="owner")
    assert e.value.status == 409
    with pytest.raises(state_mod.AuthError) as e:
        managed.set_user_role(uid, "admin", by="t", by_role="owner")
    assert e.value.status == 409

    # Off again, and it is an ordinary account.
    managed.set_setting("sso_enforce", None, "t")
    assert managed.set_user_role(uid, "admin", by="t", by_role="owner") is True


def test_the_authority_is_microsoft_unless_something_says_otherwise():
    """The override is the whole trust root of federated sign-in, so it is
    deliberately explicit: no heuristic, no autodetection, and a boot line
    every time it is in effect."""
    assert main._MS_AUTHORITY == "https://login.microsoftonline.com"
    assert main._DISCOVERY.startswith(main._MS_AUTHORITY), (
        "SSO_AUTHORITY_URL must not be set in the test environment")
    assert "%s/v2.0/.well-known/openid-configuration" in main._DISCOVERY


# ------------------------------------------------------------------ mail --
# Telling somebody an account has been made for them. What matters here is
# what the invite does NOT do: block an account being created, and carry
# anything worth intercepting.


def _owner(st):
    return "Bearer " + st.login("root", PASSWORD)["token"]


def test_an_account_is_created_even_when_no_relay_exists(managed, monkeypatch):
    """The half a blocked Add account gets wrong. The account is real, and
    the response says plainly that nobody was emailed."""
    out = main.post_user(
        main.UserCreate(username="jo", password=PASSWORD, role="admin",
                        email="jo@example.com"),
        authorization="Bearer admin-test-token")
    assert out["username"] == "jo"
    assert out["invited"] is False
    assert "no mail server" in out["invite_error"]
    assert any(u["username"] == "jo" for u in managed.list_users())


def test_a_configured_relay_invites_on_creation(managed, monkeypatch):
    sent = []
    monkeypatch.setattr(main, "_smtp_send",
                        lambda to, subject, body: sent.append((to, subject, body)) or "")
    managed.set_setting("smtp_host", "smtp.example.com", "t")
    managed.set_setting("smtp_from", "noreply@example.com", "t")
    out = main.post_user(
        main.UserCreate(username="jo", password=PASSWORD, role="admin",
                        email="jo@example.com"),
        authorization="Bearer admin-test-token")
    assert out["invited"] is True and out["invite_error"] == ""
    assert sent[0][0] == "jo@example.com"
    rec = next(u for u in managed.list_users() if u["username"] == "jo")
    assert rec["invited_at"]


def test_a_failing_relay_does_not_lose_the_account(managed, monkeypatch):
    monkeypatch.setattr(main, "_smtp_send",
                        lambda *a: "SMTPAuthenticationError: bad credentials")
    managed.set_setting("smtp_host", "smtp.example.com", "t")
    managed.set_setting("smtp_from", "noreply@example.com", "t")
    out = main.post_user(
        main.UserCreate(username="jo", password=PASSWORD, role="admin",
                        email="jo@example.com"),
        authorization="Bearer admin-test-token")
    assert out["invited"] is False
    # The relay's own words, because "could not send" is undebuggable.
    assert "bad credentials" in out["invite_error"]
    rec = next(u for u in managed.list_users() if u["username"] == "jo")
    assert rec["invited_at"] is None


def test_the_invite_can_be_rewritten_whole(managed):
    """It is their mail on their deployment. Both placeholders are filled,
    and a stray brace does not lose the message."""
    managed.set_setting("portal_public_url", "https://portal.example.com", "t")
    managed.set_setting("invite_subject", "Welcome to {portal_url}", "t")
    managed.set_setting(
        "invite_body", "Hi {username},\n\nGo to {portal_url}.\n{oops}\n", "t")
    subject, body = main._invite_text("jo")
    lines = body.splitlines()
    assert subject == "Welcome to https://portal.example.com"
    # Whole lines, compared exactly. "the URL appears somewhere in here" is
    # a weaker claim than the one worth making, and checking a URL by
    # substring is the habit that lets portal.example.com.elsewhere.net
    # through everywhere else it is done.
    assert "Hi jo," in lines
    assert "Go to https://portal.example.com." in lines
    # An unknown placeholder arrives as itself rather than raising.
    assert "{oops}" in lines


def test_an_empty_template_falls_back_to_the_built_in_one(managed):
    managed.set_setting("portal_public_url", "https://portal.example.com", "t")
    managed.set_setting("invite_body", "   ", "t")
    subject, body = main._invite_text("jo")
    assert subject == main.INVITE_SUBJECT
    assert "An account has been created for you." in body
    assert "{username}" not in body and "{portal_url}" not in body


def test_the_default_invite_carries_nothing_worth_intercepting(managed):
    managed.set_setting("smtp_from", "noreply@example.com", "t")
    managed.set_setting("smtp_host", "smtp.example.com", "t")
    managed.set_setting("portal_public_url", "https://portal.example.com", "t")
    subject, body = main._invite_text("jo")
    lines = body.splitlines()
    # The whole line, so the address is the entire value of the field
    # rather than something appearing inside a longer one.
    assert "Username: jo" in lines
    assert "Where: https://portal.example.com" in lines
    # No token, no password, no link that grants anything. An estate can
    # replace all of this - the guarantee is about what ships, not about
    # what somebody chooses to write instead.
    for word in ("token", "password reset", "tok_", "?t=", "invite/"):
        assert word not in body.lower()


def test_the_missed_can_be_invited_afterwards(managed, monkeypatch):
    """A deployment that made accounts before it had a relay should not be
    left with a permanent gap for everybody it onboarded early."""
    main.post_user(main.UserCreate(username="jo", password=PASSWORD,
                                   role="admin", email="jo@example.com"),
                   authorization="Bearer admin-test-token")
    main.post_user(main.UserCreate(username="sam", password=PASSWORD,
                                   role="viewer", email="sam@example.com"),
                   authorization="Bearer admin-test-token")
    assert len(managed.uninvited()) == 2

    sent = []
    monkeypatch.setattr(main, "_smtp_send",
                        lambda to, s_, b_: sent.append(to) or "")
    managed.set_setting("smtp_host", "smtp.example.com", "t")
    managed.set_setting("smtp_from", "noreply@example.com", "t")
    out = main.send_invites(main.InviteRequest(),
                            authorization="Bearer admin-test-token")
    assert out["sent"] == 2 and out["failed"] == []
    assert sorted(sent) == ["jo@example.com", "sam@example.com"]
    assert managed.uninvited() == []


def test_smtp_security_and_port_are_checked(managed):
    owner = _owner(managed)
    with pytest.raises(main.HTTPException) as e:
        main.put_settings(main.SettingsUpdate(smtp_security="ssl-ish"),
                          authorization=owner)
    assert e.value.status_code == 422
    with pytest.raises(main.HTTPException) as e:
        main.put_settings(main.SettingsUpdate(smtp_port="99999"),
                          authorization=owner)
    assert e.value.status_code == 422
    main.put_settings(main.SettingsUpdate(smtp_security="tls", smtp_port="465"),
                      authorization=owner)
    assert managed.get_setting("smtp_port") == "465"


def test_the_smtp_password_is_never_echoed(managed):
    managed.set_setting("smtp_password", "hunter2hunter2", "t")
    out = main.get_settings(authorization="Bearer admin-test-token")
    assert out["settings"]["smtp_password"] == {"set": True, "source": "db"}
    assert "hunter2hunter2" not in json.dumps(out)


def test_a_relay_refusal_comes_back_as_the_relay_said_it(managed, monkeypatch):
    """The relay's own words are the useful half of a failure. What must
    not come back is whatever else an exception happened to carry."""
    import smtplib

    class Boom:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def starttls(self): pass
        def login(self, *a): pass
        def send_message(self, *a):
            raise smtplib.SMTPSenderRefused(
                550, b"5.7.1 relay access denied", "noreply@example.com")

    managed.set_setting("smtp_host", "smtp.example.com", "t")
    managed.set_setting("smtp_from", "noreply@example.com", "t")
    monkeypatch.setattr(main.smtplib, "SMTP", lambda *a, **k: Boom())
    why = main._smtp_send("jo@example.com", "s", "b")
    assert "550" in why and "relay access denied" in why


def test_anything_else_is_named_rather_than_quoted(managed, monkeypatch):
    def blow_up(*a, **k):
        raise ConnectionRefusedError("connection refused to 10.1.2.3:25")

    managed.set_setting("smtp_host", "smtp.example.com", "t")
    managed.set_setting("smtp_from", "noreply@example.com", "t")
    monkeypatch.setattr(main.smtplib, "SMTP", blow_up)
    why = main._smtp_send("jo@example.com", "s", "b")
    # The wall it hit, not the message: an exception string is not a thing
    # to relay into an API response.
    assert why == "ConnectionRefusedError"
    assert "10.1.2.3" not in why


# ------------------------------------------- how recently they signed in --
# The weakness this closes: somebody already signed in to the provider in
# that browser was returned straight here with no interaction. Clicking a
# link was enough to be inside a tool that says who uses which AI.


def _request_with_query(qs):
    """A bare Request, which is all sso_start reads."""
    from starlette.requests import Request
    return Request({"type": "http", "method": "GET", "path": "/",
                    "scheme": "https", "headers": [(b"host", b"r")],
                    "query_string": qs.encode()})


def _callback_with(st, auth_time, subject="subject-root"):
    """Drive the callback with a token carrying the auth_time we choose.

    The exchange itself is stubbed: what is under test is what the receiver
    checks about the claims, not httpx.
    """
    from fastapi.testclient import TestClient

    now = int(time.time())
    claims = {"iss": "https://issuer.example.com", "aud": "c", "nonce": "n",
              "exp": now + 600, "tid": TENANT, "oid": subject,
              "email": "root@example.com"}
    if auth_time is not None:
        claims["auth_time"] = auth_time
    token = "%s.%s.x" % (main._b64u(b'{"alg":"none"}'),
                         main._b64u(json.dumps(claims).encode()))

    class Resp:
        status_code = 200

        def json(self):
            return {"id_token": token}

    class FakeClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, *a, **k): return Resp()

    st.set_setting("sso_client_id", "c", "t")
    st.set_setting("sso_tenant_id", TENANT, "t")
    st.set_setting("sso_client_secret", "s", "t")
    st.set_setting("sso_redirect_uri", "https://portal.example.com/sso/callback", "t")
    _bind_owner(st)
    orig = main.httpx.AsyncClient
    main.httpx.AsyncClient = lambda *a, **k: FakeClient()
    try:
        c = TestClient(main.app)
        return c.post("/admin/sso/callback",
                      json={"code": "c", "state": "state-x"}).json()
    finally:
        main.httpx.AsyncClient = orig


def _flight(st, **over):
    """A sign-in in flight, as /admin/sso/start would have recorded it."""
    f = {"nonce": "n", "verifier": "v", "at": time.time(),
         "issuer": "https://issuer.example.com", "token_endpoint": "https://t",
         "max_age": 12 * 3600, "test": False}
    f.update(over)
    main._SSO_FLIGHT["state-x"] = f
    return f


def test_the_authorize_request_is_never_silent(managed, monkeypatch):
    """prompt=select_account is the floor: signing in has to be something a
    person did, not something that happened to them."""
    async def fake_discover(tenant):
        return {"issuer": "https://issuer.example.com",
                "authorization_endpoint": "https://login.example.com/authorize",
                "token_endpoint": "https://login.example.com/token"}

    monkeypatch.setattr(main, "_sso_discover", fake_discover)
    for k, v in [("sso_tenant_id", TENANT), ("sso_client_id", "c"),
                 ("sso_client_secret", "s"),
                 ("sso_redirect_uri", "https://portal.example.com/sso/callback")]:
        managed.set_setting(k, v, "t")

    req = _request_with_query("")
    out = asyncio.run(main.sso_start(req))
    url = out["authorize_url"]
    assert "prompt=select_account" in url
    assert "max_age=43200" in url        # the twelve hour default


def test_a_stale_provider_session_is_refused(managed):
    """A token minted a second ago off a week-old sign-in. exp says the
    token is fresh; auth_time says the person is not."""
    _flight(managed, max_age=12 * 3600)
    week = int(time.time()) - 7 * 24 * 3600
    out = _callback_with(managed, auth_time=week)
    assert out["ok"] is False
    assert "Sign in again" in out["detail"]


def test_a_recent_sign_in_is_allowed(managed):
    _flight(managed, max_age=12 * 3600)
    out = _callback_with(managed, auth_time=int(time.time()) - 60)
    assert out.get("ok") is True


def test_a_token_with_no_auth_time_is_refused(managed):
    """max_age is a request. A provider that ignores it silently must not
    be indistinguishable from one that honoured it."""
    _flight(managed, max_age=12 * 3600)
    out = _callback_with(managed, auth_time=None)
    assert out["ok"] is False
    assert "when this person last signed in" in out["detail"]


def test_the_window_is_configurable_and_checked(managed):
    managed.set_setting("sso_max_age_hours", "1", "t")
    assert main._sso_max_age() == 3600
    _flight(managed, max_age=3600)
    out = _callback_with(managed, auth_time=int(time.time()) - 2 * 3600)
    assert out["ok"] is False
    managed.set_setting("sso_max_age_hours", "", "t")
    assert main._sso_max_age() == main.SSO_MAX_AGE_DEFAULT_HOURS * 3600


def test_the_window_is_bounded(managed):
    owner = "Bearer " + managed.login("root", PASSWORD)["token"]
    with pytest.raises(main.HTTPException) as e:
        main.put_settings(main.SettingsUpdate(sso_max_age_hours="9999"),
                          authorization=owner)
    assert e.value.status_code == 422


def test_the_relay_password_can_come_from_a_file(tmp_path, monkeypatch):
    """The env table promises NAME_FILE for every secret in it, and Compose
    has no other secret story - a file rather than an environment variable
    is the whole reason that resolver exists. The relay password used to
    read the environment directly, so the promise did not hold for the one
    secret a Compose deployment is most likely to want it for.

    Two halves, because the module reads its environment once at import and
    reloading it re-registers the Prometheus collectors: that the resolver
    handles this variable, and that the relay config goes through it.
    """
    f = tmp_path / "smtp_password"
    # A trailing newline, because almost every way of writing a file leaves
    # one and a password differing by one byte fails with no clue why.
    f.write_text("s3cret\n")
    monkeypatch.setenv("SMTP_PASSWORD_FILE", str(f))
    monkeypatch.delenv("SMTP_PASSWORD", raising=False)
    assert main._secret("SMTP_PASSWORD", "") == "s3cret"

    import pathlib
    src = pathlib.Path(main.__file__).read_text()
    assert '"smtp_password": _secret("SMTP_PASSWORD", "")' in src
