"""Accounts and roles: admin runs the platform, viewer reads it.

The properties under test: a viewer session passes every read gate and is
refused by every write gate with a 403 that says why; the last admin cannot
be deleted; a password reset kills the sessions the old password minted;
a viewer still owns their own password; and the whole trail lands in the
audit log with the acting username on it.
"""

import os

os.environ.setdefault("AUTH_TOKEN", "test-token-for-ci")

import pytest
from fastapi.testclient import TestClient

from app import main
from app import state as state_mod
from app.main import app

client = TestClient(app)

API_ADMIN = {"Authorization": "Bearer admin-test-token"}


@pytest.fixture
def managed(tmp_path, monkeypatch):
    st = state_mod.State(str(tmp_path / "state.db"))
    monkeypatch.setattr(main, "STATE", st)
    monkeypatch.setattr(main, "_EXPECTED_ADMIN", b"Bearer admin-test-token")
    yield st


def _mk(managed, username, role, password="a-long-enough-password"):
    return managed.create_user(username, password, role, by="test")


def _session(managed, username, password="a-long-enough-password"):
    tok = managed.login(username, password)["token"]
    return {"Authorization": "Bearer " + tok}


@pytest.fixture
def viewer(managed):
    managed.create_admin("root", "a-long-enough-password")
    _mk(managed, "auditor", "viewer")
    return _session(managed, "auditor")


@pytest.fixture
def admin(managed):
    # created by the viewer fixture's create_admin when both are used;
    # standalone tests create their own.
    if not managed.has_admin():
        managed.create_admin("root", "a-long-enough-password")
    return _session(managed, "root")


# ------------------------------------------------------------ the gate ----


def test_viewer_reads_everything(viewer):
    for path in ("/admin/settings", "/admin/devices", "/admin/candidates",
                 "/admin/governance", "/admin/events", "/admin/users",
                 "/admin/finding-status"):
        assert client.get(path, headers=viewer).status_code == 200, path


def test_viewer_cannot_recover_the_log_store_credential(viewer, admin):
    """The stored credential is typically write-capable (hosted stores hand
    out one token for both directions), so a read-only account recovering
    it would be a path to injecting findings past the receiver. Admin
    sessions and the service credential still can."""
    assert client.get("/admin/settings/secrets",
                      headers=viewer).status_code == 403
    assert client.get("/admin/settings/secrets",
                      headers=admin).status_code == 200
    assert client.get("/admin/settings/secrets",
                      headers=API_ADMIN).status_code == 200


def test_viewer_writes_nothing_and_is_told_why(viewer):
    refusals = [
        client.put("/admin/settings", headers=viewer,
                   json={"corp_domains": ["example.com"]}),
        client.post("/admin/enrollment-tokens", headers=viewer,
                    json={"note": "x"}),
        client.put("/admin/finding-status", headers=viewer,
                   json={"key": "k", "status": "acknowledged"}),
        client.post("/admin/users", headers=viewer,
                    json={"username": "sneaky", "role": "admin",
                          "password": "a-long-enough-password"}),
    ]
    for r in refusals:
        assert r.status_code == 403
        assert "read-only" in r.json()["detail"]


def test_the_session_probe_names_the_role(viewer, admin):
    assert client.get("/admin/session", headers=viewer).json()["role"] == "viewer"
    assert client.get("/admin/session", headers=admin).json()["role"] == "owner"


# ------------------------------------------------------- account management --


def test_admin_creates_lists_and_deletes_accounts(managed, admin):
    r = client.post("/admin/users", headers=admin,
                    json={"username": "auditor", "role": "viewer",
                          "password": "a-long-enough-password"})
    assert r.status_code == 200 and r.json()["role"] == "viewer"
    users = client.get("/admin/users", headers=admin).json()["users"]
    assert [(u["username"], u["role"]) for u in users] == \
        [("root", "owner"), ("auditor", "viewer")]
    uid = users[1]["id"]
    assert client.post(f"/admin/users/{uid}/delete",
                       headers=admin).status_code == 200
    users = client.get("/admin/users", headers=admin).json()["users"]
    assert len(users) == 1


def test_duplicate_usernames_and_odd_roles_are_refused(managed, admin):
    body = {"username": "root", "role": "viewer",
            "password": "a-long-enough-password"}
    assert client.post("/admin/users", headers=admin, json=body).status_code == 409
    body = {"username": "ok.name", "role": "superuser",
            "password": "a-long-enough-password"}
    assert client.post("/admin/users", headers=admin, json=body).status_code == 422


def test_the_last_owner_cannot_be_deleted(managed, admin):
    """The floor that replaced the last-admin one. It is stricter than
    that floor ever was: an admin cannot make an owner, so losing the last
    one cannot be undone from inside at all."""
    uid = client.get("/admin/users", headers=admin).json()["users"][0]["id"]
    r = client.post(f"/admin/users/{uid}/delete", headers=admin)
    assert r.status_code == 409
    assert "last owner" in r.json()["detail"]


def test_the_last_admin_may_be_deleted_while_an_owner_remains(managed, admin):
    """An owner does everything an admin does, so there is nothing to
    protect - the old floor here would have refused this."""
    _mk(managed, "operator", "admin")
    uid = next(u["id"] for u in managed.list_users()
               if u["username"] == "operator")
    assert client.post(f"/admin/users/{uid}/delete",
                       headers=admin).status_code == 200


def test_deleting_an_account_kills_its_sessions(managed, admin):
    _mk(managed, "temp", "viewer")
    sess = _session(managed, "temp")
    uid = next(u["id"] for u in managed.list_users() if u["username"] == "temp")
    client.post(f"/admin/users/{uid}/delete", headers=admin)
    assert client.get("/admin/settings", headers=sess).status_code == 401


def test_password_reset_revokes_the_old_sessions(managed, admin):
    _mk(managed, "temp", "viewer")
    old = _session(managed, "temp")
    uid = next(u["id"] for u in managed.list_users() if u["username"] == "temp")
    r = client.post(f"/admin/users/{uid}/password", headers=admin,
                    json={"new": "a-different-long-password"})
    assert r.status_code == 200
    assert client.get("/admin/settings", headers=old).status_code == 401
    assert _session(managed, "temp", "a-different-long-password")


def test_a_viewer_owns_their_own_password(managed, viewer):
    r = client.post("/admin/password", headers=viewer,
                    json={"current": "a-long-enough-password",
                          "new": "my-new-viewer-password"})
    assert r.status_code == 200
    # ...and it changed THEIR password, not the admin's.
    assert _session(managed, "auditor", "my-new-viewer-password")
    assert _session(managed, "root")


def test_account_actions_land_in_the_audit_trail(managed, admin):
    client.post("/admin/users", headers=admin,
                json={"username": "auditor", "role": "viewer",
                      "password": "a-long-enough-password"})
    events = client.get("/admin/events", headers=admin).json()["events"]
    e = next(x for x in events if x["kind"] == "user_created")
    assert e["detail"]["username"] == "auditor"
    assert e["detail"]["by"] == "root"


# ------------------------------------------------ changing a role in place --
# A role used to be fixed at creation, so moving somebody between levels
# meant deleting the account and making a new one - which cost them their
# password to record something the trail can simply state.


def test_a_role_changes_in_place(managed, admin):
    _mk(managed, "temp", "viewer")
    uid = next(u["id"] for u in managed.list_users() if u["username"] == "temp")
    r = client.post(f"/admin/users/{uid}/role", headers=admin,
                    json={"role": "admin"})
    assert r.status_code == 200
    assert next(u["role"] for u in managed.list_users()
                if u["id"] == uid) == "admin"


def test_the_password_survives_a_role_change(managed, admin):
    """The reason to do this at all: a promotion should not cost somebody
    their credential."""
    _mk(managed, "temp", "viewer")
    uid = next(u["id"] for u in managed.list_users() if u["username"] == "temp")
    client.post(f"/admin/users/{uid}/role", headers=admin,
                json={"role": "admin"})
    assert _session(managed, "temp")


def test_a_demotion_takes_effect_without_a_sign_out(managed, admin):
    """The property that makes "log out for this to apply" unnecessary: the
    role is read off the account row per request, not frozen into the
    session when it was minted."""
    _mk(managed, "temp", "admin")
    live = _session(managed, "temp")
    assert client.put("/admin/settings", headers=live,
                      json={"grafana_url": "https://grafana.example.com"}
                      ).status_code == 200

    uid = next(u["id"] for u in managed.list_users() if u["username"] == "temp")
    client.post(f"/admin/users/{uid}/role", headers=admin,
                json={"role": "viewer"})

    # Same token, no sign-out, and the next write is refused.
    assert client.put("/admin/settings", headers=live,
                      json={"grafana_url": "https://other.example.com"}
                      ).status_code == 403
    # Still signed in, and still able to read.
    assert client.get("/admin/settings", headers=live).status_code == 200


def test_a_promotion_takes_effect_without_a_sign_out(managed, admin):
    _mk(managed, "temp", "viewer")
    live = _session(managed, "temp")
    uid = next(u["id"] for u in managed.list_users() if u["username"] == "temp")
    client.post(f"/admin/users/{uid}/role", headers=admin,
                json={"role": "admin"})
    assert client.put("/admin/settings", headers=live,
                      json={"grafana_url": "https://grafana.example.com"}
                      ).status_code == 200


def test_the_last_owner_cannot_be_demoted(managed, admin):
    uid = next(u["id"] for u in managed.list_users() if u["username"] == "root")
    r = client.post(f"/admin/users/{uid}/role", headers=admin,
                    json={"role": "viewer"})
    assert r.status_code == 409
    assert "last owner" in r.json()["detail"]


def test_an_owner_may_be_demoted_once_another_exists(managed, admin):
    _mk(managed, "second", "owner")
    uid = next(u["id"] for u in managed.list_users() if u["username"] == "root")
    assert client.post(f"/admin/users/{uid}/role", headers=admin,
                       json={"role": "viewer"}).status_code == 200


def test_a_viewer_cannot_change_a_role(managed, viewer):
    """Otherwise read-only is a formality."""
    uid = next(u["id"] for u in managed.list_users() if u["username"] == "root")
    assert client.post(f"/admin/users/{uid}/role", headers=viewer,
                       json={"role": "viewer"}).status_code == 403


def test_an_unknown_role_and_an_unknown_account_are_refused(managed, admin):
    uid = next(u["id"] for u in managed.list_users() if u["username"] == "root")
    assert client.post(f"/admin/users/{uid}/role", headers=admin,
                       json={"role": "superuser"}).status_code == 422
    assert client.post("/admin/users/0123456789abcdef/role", headers=admin,
                       json={"role": "admin"}).status_code == 404


def test_a_role_change_is_one_event_naming_both_levels(managed, admin):
    """What delete-and-recreate could not say: a reader had to correlate a
    removal with a creation and infer what had happened."""
    _mk(managed, "temp", "viewer")
    uid = next(u["id"] for u in managed.list_users() if u["username"] == "temp")
    client.post(f"/admin/users/{uid}/role", headers=admin,
                json={"role": "admin"})
    events = client.get("/admin/events", headers=admin).json()["events"]
    e = next(x for x in events if x["kind"] == "user_role_changed")
    assert e["detail"]["from"] == "viewer"
    assert e["detail"]["to"] == "admin"
    assert e["detail"]["by"] == "root"


def test_setting_the_role_it_already_has_records_nothing(managed, admin):
    """The trail records changes, and a write that changed nothing is not
    one."""
    _mk(managed, "temp", "viewer")
    uid = next(u["id"] for u in managed.list_users() if u["username"] == "temp")
    assert client.post(f"/admin/users/{uid}/role", headers=admin,
                       json={"role": "viewer"}).status_code == 200
    events = client.get("/admin/events", headers=admin).json()["events"]
    assert [x for x in events if x["kind"] == "user_role_changed"] == []


# ------------------------------------------------------------ the rank rule --
# You cannot act on an account that outranks you, and you cannot grant a
# role above your own. Without it the tier above admin exists in name
# only: an admin reaches an owner through any of three doors - reset their
# password and sign in as them, set the address a federated sign-in
# matches on, or simply change their role.


def _admin_session(managed, name="operator"):
    _mk(managed, name, "admin")
    return _session(managed, name), next(
        u["id"] for u in managed.list_users() if u["username"] == name)


def test_an_admin_cannot_reset_an_owners_password(managed, admin):
    """The most direct door: reset it, then sign in as them."""
    sess, _ = _admin_session(managed)
    owner = next(u["id"] for u in managed.list_users() if u["role"] == "owner")
    r = client.post(f"/admin/users/{owner}/password", headers=sess,
                    json={"new": "a-brand-new-long-password"})
    assert r.status_code == 403
    assert "above yours" in r.json()["detail"]


def test_an_admin_cannot_set_an_owners_email(managed, admin):
    """The quieter door, and the one this rule exists for: the address is
    what a federated sign-in matches on, so setting it on an account above
    yours is that account's credentials by another route."""
    sess, _ = _admin_session(managed)
    owner = next(u["id"] for u in managed.list_users() if u["role"] == "owner")
    r = client.post(f"/admin/users/{owner}/email", headers=sess,
                    json={"email": "attacker@example.com"})
    assert r.status_code == 403


def test_an_admin_cannot_demote_an_owner(managed, admin):
    sess, _ = _admin_session(managed)
    owner = next(u["id"] for u in managed.list_users() if u["role"] == "owner")
    assert client.post(f"/admin/users/{owner}/role", headers=sess,
                       json={"role": "viewer"}).status_code == 403


def test_an_admin_cannot_delete_an_owner(managed, admin):
    sess, _ = _admin_session(managed)
    owner = next(u["id"] for u in managed.list_users() if u["role"] == "owner")
    assert client.post(f"/admin/users/{owner}/delete",
                       headers=sess).status_code == 403


def test_an_admin_cannot_grant_owner(managed, admin):
    """Not by creating one, and not by promoting one. Either would let a
    role make a role above itself, which is the whole thing the rule
    prevents."""
    sess, uid = _admin_session(managed)
    assert client.post("/admin/users", headers=sess,
                       json={"username": "climber", "role": "owner",
                             "password": "a-long-enough-password"}
                       ).status_code == 403
    _mk(managed, "colleague", "viewer")
    cid = next(u["id"] for u in managed.list_users()
               if u["username"] == "colleague")
    assert client.post(f"/admin/users/{cid}/role", headers=sess,
                       json={"role": "owner"}).status_code == 403


def test_an_admin_still_manages_admins_and_viewers(managed, admin):
    """The rule is about rank, not about account management: an operator
    keeps the job they had, including resetting a colleague-admin's
    password. Only the tier above them is out of reach."""
    sess, _ = _admin_session(managed)
    assert client.post("/admin/users", headers=sess,
                       json={"username": "colleague", "role": "admin",
                             "password": "a-long-enough-password"}
                       ).status_code == 200
    cid = next(u["id"] for u in managed.list_users()
               if u["username"] == "colleague")
    assert client.post(f"/admin/users/{cid}/password", headers=sess,
                       json={"new": "another-long-password"}).status_code == 200
    assert client.post(f"/admin/users/{cid}/email", headers=sess,
                       json={"email": "colleague@example.com"}
                       ).status_code == 200
    assert client.post(f"/admin/users/{cid}/role", headers=sess,
                       json={"role": "viewer"}).status_code == 200
    assert client.post(f"/admin/users/{cid}/delete",
                       headers=sess).status_code == 200


def test_an_owner_may_act_on_another_owner(managed, admin):
    """Equal rank is not above it. Otherwise two owners could never manage
    each other and the role would need a fourth tier to supervise it."""
    _mk(managed, "second", "owner")
    sess = _session(managed, "second")
    root = next(u["id"] for u in managed.list_users() if u["username"] == "root")
    assert client.post(f"/admin/users/{root}/email", headers=sess,
                       json={"email": "root@example.com"}).status_code == 200


def test_the_api_credential_is_outside_the_rank_rule(managed, admin):
    """It is the operator's break-glass, held by whoever can set the
    receiver's environment - who already owns the box. Rank-limiting it
    would only lock the operator out of their own recovery path."""
    owner = next(u["id"] for u in managed.list_users() if u["role"] == "owner")
    assert client.post(f"/admin/users/{owner}/email", headers=API_ADMIN,
                       json={"email": "root@example.com"}).status_code == 200


def test_break_glass_finds_the_owner_not_a_missing_admin(managed, admin):
    """It used to name role = 'admin' outright, which stopped finding
    anything the moment the setup account became an owner - breaking the
    one path that exists for being locked out."""
    r = client.post("/admin/password", headers=API_ADMIN,
                    json={"new": "recovered-long-password"})
    assert r.status_code == 200
    assert managed.login("root", "recovered-long-password")["token"]


# --------------------------------------------------------- the owner tier --


def test_only_an_owner_configures_federated_sign_in(managed, admin):
    """The one thing the tier above admin exists to hold. Everything else
    on the settings page stays an admin's job."""
    sess, _ = _admin_session(managed)
    r = client.put("/admin/settings", headers=sess,
                   json={"sso_tenant_id": "contoso.onmicrosoft.com"})
    assert r.status_code == 403
    assert "owner" in r.json()["detail"]
    # ...and the rest of the page is untouched by the gate.
    assert client.put("/admin/settings", headers=sess,
                      json={"grafana_url": "https://grafana.example.com"}
                      ).status_code == 200


def test_an_owner_configures_federated_sign_in(managed, admin):
    assert client.put("/admin/settings", headers=admin,
                      json={"sso_tenant_id": "contoso.onmicrosoft.com"}
                      ).status_code == 200


def test_the_client_secret_is_never_echoed(managed, admin):
    """Same treatment as the log-store password and the webhook: a stored
    secret that a GET hands back is a stored secret anybody with a read
    can walk off with."""
    client.put("/admin/settings", headers=admin,
               json={"sso_client_secret": "a-real-looking-secret"})
    body = client.get("/admin/settings", headers=admin).json()
    assert "a-real-looking-secret" not in str(body)
    assert body["settings"]["sso_client_secret"]["set"] is True
