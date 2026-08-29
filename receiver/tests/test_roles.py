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
    assert client.get("/admin/session", headers=admin).json()["role"] == "admin"


# ------------------------------------------------------- account management --


def test_admin_creates_lists_and_deletes_accounts(managed, admin):
    r = client.post("/admin/users", headers=admin,
                    json={"username": "auditor", "role": "viewer",
                          "password": "a-long-enough-password"})
    assert r.status_code == 200 and r.json()["role"] == "viewer"
    users = client.get("/admin/users", headers=admin).json()["users"]
    assert [(u["username"], u["role"]) for u in users] == \
        [("root", "admin"), ("auditor", "viewer")]
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


def test_the_last_admin_cannot_be_deleted(managed, admin):
    uid = client.get("/admin/users", headers=admin).json()["users"][0]["id"]
    r = client.post(f"/admin/users/{uid}/delete", headers=admin)
    assert r.status_code == 409
    assert "last admin" in r.json()["detail"]


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


def test_the_last_admin_cannot_be_demoted(managed, admin):
    """The same floor that stops the last admin being deleted: a deployment
    with accounts and no admin cannot manage its own accounts."""
    uid = next(u["id"] for u in managed.list_users() if u["username"] == "root")
    r = client.post(f"/admin/users/{uid}/role", headers=admin,
                    json={"role": "viewer"})
    assert r.status_code == 409
    assert "last admin" in r.json()["detail"]


def test_an_admin_may_be_demoted_once_another_exists(managed, admin):
    _mk(managed, "second", "admin")
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
                       json={"role": "owner"}).status_code == 422
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
