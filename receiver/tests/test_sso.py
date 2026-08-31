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
