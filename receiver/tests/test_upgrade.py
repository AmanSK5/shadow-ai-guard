"""The command line's grant, token and upgrade-run routes. See SECURITY.md,
"Upgrading": an owner approves one grant in the portal, the command redeems
it once for a token that opens the upgrade routes and nothing else, and the
receiver holds the progress. Nothing here touches a cluster or a host."""
import hashlib
import os
import secrets

os.environ.setdefault("AUTH_TOKEN", "test-token-for-ci")

import pytest
from fastapi.testclient import TestClient

from app import state as state_mod
from app.main import app

client = TestClient(app)
PASSWORD = "a-long-enough-password"


@pytest.fixture
def managed(tmp_path, monkeypatch):
    from app import main
    st = state_mod.State(str(tmp_path / "state.db"))
    monkeypatch.setattr(main, "STATE", st)
    monkeypatch.setattr(main, "_EXPECTED_ADMIN", b"Bearer admin-test-token")
    monkeypatch.setattr(main, "_SETUP_CODE", "aigs_test-setup-code")
    monkeypatch.setattr(main, "LOGIN_FAILURE_DELAY_SECONDS", 0)
    monkeypatch.setattr(main, "_cli_misses", [])
    monkeypatch.setattr(state_mod, "GRANT_POLL_INTERVAL", 0)
    return st


def _hdr(token):
    return {"Authorization": f"Bearer {token}"}


def _owner():
    return client.post("/admin/setup", json={
        "setup_code": "aigs_test-setup-code", "username": "aman",
        "password": PASSWORD}).json()["token"]


def _admin(owner_token):
    client.post("/admin/users", headers=_hdr(owner_token), json={
        "username": "ops", "password": PASSWORD, "role": "admin"})
    return client.post("/admin/login", json={
        "username": "ops", "password": PASSWORD}).json()["token"]


def _ask(client_name="aiguardctl 0.29.0"):
    verifier = secrets.token_urlsafe(32)
    resp = client.post("/admin/cli/authorize", json={
        "purpose": "upgrade",
        "verifier_hash": hashlib.sha256(verifier.encode()).hexdigest(),
        "client": client_name})
    assert resp.status_code == 200, resp.text
    return verifier, resp.json()


def _poll(grant, verifier):
    return client.post("/admin/cli/token", json={
        "device_code": grant["device_code"], "verifier": verifier})


def test_the_routes_do_not_exist_in_classic_mode():
    assert client.post("/admin/cli/authorize", json={
        "purpose": "upgrade", "verifier_hash": "0" * 64}).status_code == 404
    assert client.get("/admin/upgrade/runs/current").status_code == 404


def test_a_grant_is_pending_until_an_owner_approves_it(managed):
    owner = _owner()
    verifier, grant = _ask()
    assert grant["device_code"].startswith("aigd_")
    assert len(grant["user_code"]) == 9 and grant["user_code"][4] == "-"
    assert grant["approve_path"] == "/#cli-approve/" + grant["user_code"]
    assert _poll(grant, verifier).status_code == 428
    shown = client.get("/admin/cli/grants/" + grant["user_code"],
                       headers=_hdr(owner)).json()
    assert shown["status"] == "pending" and shown["purpose"] == "upgrade"
    assert "device" not in "".join(shown.keys())
    ok = client.post("/admin/cli/approve", headers=_hdr(owner),
                     json={"user_code": grant["user_code"].lower(), "approve": True})
    assert ok.status_code == 200 and ok.json()["status"] == "approved"
    got = _poll(grant, verifier)
    assert got.status_code == 200
    assert got.json()["token"].startswith("aigu_")
    # once
    assert _poll(grant, verifier).status_code == 409


def test_only_an_owner_can_see_or_approve_a_request(managed):
    owner = _owner()
    admin = _admin(owner)
    _, grant = _ask()
    assert client.get("/admin/cli/grants/" + grant["user_code"],
                      headers=_hdr(admin)).status_code == 403
    assert client.post("/admin/cli/approve", headers=_hdr(admin),
                       json={"user_code": grant["user_code"],
                             "approve": True}).status_code == 403
    # the API credential is an admin, not an owner
    assert client.post("/admin/cli/approve",
                       headers={"Authorization": "Bearer admin-test-token"},
                       json={"user_code": grant["user_code"],
                             "approve": True}).status_code == 403


def test_the_verifier_binds_the_token_to_the_process_that_asked(managed):
    owner = _owner()
    verifier, grant = _ask()
    client.post("/admin/cli/approve", headers=_hdr(owner),
                json={"user_code": grant["user_code"], "approve": True})
    wrong = client.post("/admin/cli/token", json={
        "device_code": grant["device_code"], "verifier": "not-the-verifier-at-all"})
    assert wrong.status_code == 403
    assert _poll(grant, verifier).status_code == 200


def test_a_denied_request_stays_denied_and_says_so(managed):
    owner = _owner()
    verifier, grant = _ask()
    client.post("/admin/cli/approve", headers=_hdr(owner),
                json={"user_code": grant["user_code"], "approve": False})
    assert _poll(grant, verifier).status_code == 403
    assert client.post("/admin/cli/approve", headers=_hdr(owner),
                       json={"user_code": grant["user_code"],
                             "approve": True}).status_code == 409


def test_an_upgrade_token_opens_the_upgrade_routes_and_nothing_else(managed):
    owner = _owner()
    verifier, grant = _ask()
    client.post("/admin/cli/approve", headers=_hdr(owner),
                json={"user_code": grant["user_code"], "approve": True})
    token = _poll(grant, verifier).json()["token"]
    # the upgrade routes
    plan = client.get("/admin/upgrade/plan", headers=_hdr(token))
    assert plan.status_code == 200 and plan.json()["approved"]["by"] == "aman"
    # nothing else: every admin route refuses it as a bad token
    for path in ("/admin/settings", "/admin/users", "/admin/devices",
                 "/admin/events", "/admin/budget"):
        assert client.get(path, headers=_hdr(token)).status_code == 401, path
    assert client.put("/admin/settings", headers=_hdr(token),
                      json={"org_name": "x"}).status_code == 401
    # and a session does not open the run routes
    assert client.post("/admin/upgrade/runs", headers=_hdr(owner), json={
        "route": "helm", "from_version": "0.28.0", "to_version": "0.29.0"}
    ).status_code == 401


def test_one_run_per_token_with_steps_the_portal_can_read(managed):
    owner = _owner()
    verifier, grant = _ask()
    client.post("/admin/cli/approve", headers=_hdr(owner),
                json={"user_code": grant["user_code"], "approve": True})
    token = _poll(grant, verifier).json()["token"]
    run = client.post("/admin/upgrade/runs", headers=_hdr(token), json={
        "route": "helm", "from_version": "0.28.0", "to_version": "0.29.0",
        "plan": {"release": "ai-guard", "namespace": "ai-guard"}})
    assert run.status_code == 200
    rid = run.json()["id"]
    assert run.json()["started_by_name"] == "aman"
    again = client.post("/admin/upgrade/runs", headers=_hdr(token), json={
        "route": "helm", "from_version": "0.28.0", "to_version": "0.29.0"})
    assert again.status_code == 409
    step = client.post(f"/admin/upgrade/runs/{rid}/steps", headers=_hdr(token),
                       json={"step": "helm upgrade", "status": "running"})
    assert step.status_code == 200
    # a viewer can watch the rollout
    client.post("/admin/users", headers=_hdr(owner), json={
        "username": "auditor", "password": PASSWORD, "role": "viewer"})
    viewer = client.post("/admin/login", json={
        "username": "auditor", "password": PASSWORD}).json()["token"]
    cur = client.get("/admin/upgrade/runs/current", headers=_hdr(viewer)).json()["run"]
    assert cur["id"] == rid and cur["steps"][0]["step"] == "helm upgrade"
    assert cur["status"] == "running"
    done = client.post(f"/admin/upgrade/runs/{rid}/finish", headers=_hdr(token),
                       json={"outcome": "succeeded", "detail": "0.29.0 is up"})
    assert done.status_code == 200 and done.json()["outcome"] == "succeeded"
    # the token's work is over: it can write nothing more
    assert client.post(f"/admin/upgrade/runs/{rid}/steps", headers=_hdr(token),
                       json={"step": "late", "status": "done"}).status_code == 401
    kinds = [e["kind"] for e in client.get("/admin/events", headers=_hdr(owner)).json()["events"]]
    for k in ("cli_grant_requested", "cli_grant_approved", "cli_token_issued",
              "upgrade_started", "upgrade_finished"):
        assert k in kinds, k


def test_progress_is_bounded_and_carries_no_secrets_by_shape(managed):
    owner = _owner()
    verifier, grant = _ask()
    client.post("/admin/cli/approve", headers=_hdr(owner),
                json={"user_code": grant["user_code"], "approve": True})
    token = _poll(grant, verifier).json()["token"]
    rid = client.post("/admin/upgrade/runs", headers=_hdr(token), json={
        "route": "compose", "from_version": "0.28.0", "to_version": "0.29.0"}).json()["id"]
    long = client.post(f"/admin/upgrade/runs/{rid}/steps", headers=_hdr(token),
                       json={"step": "x", "status": "done", "detail": "d" * 400})
    assert long.status_code == 422, "detail is capped at the model"
    for i in range(state_mod.UPGRADE_STEP_CAP):
        r = client.post(f"/admin/upgrade/runs/{rid}/steps", headers=_hdr(token),
                        json={"step": f"s{i}", "status": "done"})
        assert r.status_code == 200
    assert client.post(f"/admin/upgrade/runs/{rid}/steps", headers=_hdr(token),
                       json={"step": "one more", "status": "done"}).status_code == 413


def test_unknown_codes_spend_a_budget_and_the_budget_ends(managed, monkeypatch):
    from app import main
    monkeypatch.setattr(main, "CLI_MAX_MISSES", 5)
    for _ in range(5):
        client.post("/admin/cli/token", json={
            "device_code": "aigd_nobody-knows-this-one", "verifier": "x" * 20})
    last = client.post("/admin/cli/token", json={
        "device_code": "aigd_nobody-knows-this-one", "verifier": "x" * 20})
    assert last.status_code == 429
    kinds = [e["kind"] for e in managed.list_events()]
    assert kinds.count("cli_throttled") == 1


def test_polling_faster_than_told_is_slowed_down(managed, monkeypatch):
    monkeypatch.setattr(state_mod, "GRANT_POLL_INTERVAL", 3)
    verifier, grant = _ask()
    assert _poll(grant, verifier).status_code == 428
    assert _poll(grant, verifier).status_code == 429
