"""Managed mode: enrollment, device credentials, revocation, admin API.

The module is imported classic (MANAGED_MODE unset), as in test_smoke, and
managed mode is switched on per-test by giving the module a State and an
admin credential. That mirrors production faithfully - every code path reads
those globals at call time - and avoids re-importing the module, which
re-registers every Prometheus metric.
"""

import os

os.environ.setdefault("AUTH_TOKEN", "test-token-for-ci")

import pytest
from fastapi.testclient import TestClient

from app import state as state_mod
from app.main import app

client = TestClient(app)

AUTH = {"Authorization": "Bearer test-token-for-ci"}
ADMIN = {"Authorization": "Bearer admin-test-token"}


@pytest.fixture
def managed(tmp_path, monkeypatch):
    from app import main

    st = state_mod.State(str(tmp_path / "state.db"))
    monkeypatch.setattr(main, "STATE", st)
    monkeypatch.setattr(main, "_EXPECTED_ADMIN", b"Bearer admin-test-token")
    return st


def _mint(**kw) -> dict:
    resp = client.post("/admin/enrollment-tokens", headers=ADMIN,
                       json={"note": "test", **kw})
    assert resp.status_code == 200
    return resp.json()


def _enroll(token, serial="C02TEST", platform="macos", **kw):
    return client.post("/enroll",
                       headers={"Authorization": f"Bearer {token}"},
                       json={"platform": platform, "serial": serial,
                             "hostname": "test-mac", **kw})


# ------------------------------------------------------------ mode gating --


def test_managed_routes_do_not_exist_in_classic_mode():
    """Off means byte-for-byte today's receiver: 404, not 401, so a classic
    deployment does not advertise routes it does not serve."""
    assert client.post("/enroll", json={}).status_code == 404
    assert client.get("/admin/devices", headers=ADMIN).status_code == 404
    assert client.post("/admin/enrollment-tokens", headers=ADMIN,
                       json={}).status_code == 404


def test_admin_requires_its_own_token(managed):
    assert client.get("/admin/devices").status_code == 401
    assert client.get("/admin/devices", headers=AUTH).status_code == 401  # shared token is not admin
    assert client.get("/admin/devices", headers=ADMIN).status_code == 200


# -------------------------------------------------------------- lifecycle --


def test_the_full_lifecycle(managed):
    """Mint, enroll, report as the device, appear in inventory, revoke, 401.

    The last step is the property the whole phase exists for: one machine's
    credential stops working without touching any other machine."""
    minted = _mint()
    assert minted["token"].startswith("aige_")

    resp = _enroll(minted["token"], agent_version="2.0.0")
    assert resp.status_code == 200
    cred = resp.json()["device_token"]
    did = resp.json()["device_id"]
    assert cred.startswith("aigd_")

    dev_auth = {"Authorization": f"Bearer {cred}",
                "X-AiGuard-Agent-Version": "2.0.1"}
    resp = client.post("/report", headers=dev_auth,
                       json={"tool": "chatgpt", "surface": "cli", "os": "macos"})
    assert resp.status_code == 200

    devices = client.get("/admin/devices", headers=ADMIN).json()["devices"]
    (d,) = [d for d in devices if d["id"] == did]
    assert d["last_seen"] is not None
    assert d["agent_version"] == "2.0.1"  # header wins over the enroll-time value
    assert "cred_hash" not in d

    assert client.post(f"/admin/devices/{did}/revoke", headers=ADMIN).status_code == 200
    resp = client.post("/report", headers=dev_auth,
                       json={"tool": "chatgpt", "surface": "cli", "os": "macos"})
    assert resp.status_code == 401


def test_device_credential_reads_the_registry(managed, tmp_path, monkeypatch):
    """The collector's second request. A credential that can report but not
    fetch identifiers would enroll a fleet that then refuses to scan."""
    from app import main

    reg = tmp_path / "collector.json"
    reg.write_text('{"version": 1}')
    monkeypatch.setattr(main, "COLLECTOR_REGISTRY_PATH", str(reg))

    cred = _enroll(_mint()["token"]).json()["device_token"]
    resp = client.get("/registry/collector",
                      headers={"Authorization": f"Bearer {cred}"})
    assert resp.status_code == 200


def test_shared_token_still_works_in_managed_mode(managed):
    """The migration path: unenrolled machines keep reporting."""
    resp = client.post("/report", headers=AUTH,
                       json={"tool": "chatgpt", "surface": "cli", "os": "macos"})
    assert resp.status_code == 200


# ------------------------------------------------------- token boundaries --


def test_an_enrollment_token_cannot_report(managed):
    """It mints device records and does nothing else - that boundary is why
    a long TTL inside an MDM artifact is acceptable."""
    token = _mint()["token"]
    resp = client.post("/report", headers={"Authorization": f"Bearer {token}"},
                       json={"tool": "chatgpt"})
    assert resp.status_code == 401


def test_a_device_credential_cannot_enroll_or_administrate(managed):
    cred = _enroll(_mint()["token"]).json()["device_token"]
    hdr = {"Authorization": f"Bearer {cred}"}
    assert _enroll(cred, serial="OTHER").status_code == 401
    assert client.get("/admin/devices", headers=hdr).status_code == 401


def test_expired_and_revoked_tokens_are_refused_and_distinguishable(managed):
    minted = _mint()
    managed._db.execute(
        "UPDATE enrollment_tokens SET expires_at = '2000-01-01T00:00:00+00:00'"
        " WHERE id = ?", (minted["id"],))
    managed._db.commit()
    resp = _enroll(minted["token"])
    assert resp.status_code == 401
    # "expired" names an operations task, not an attack; the collector puts
    # this string in the MDM log.
    assert "expired" in resp.json()["detail"]

    second = _mint()
    assert client.post(f"/admin/enrollment-tokens/{second['id']}/revoke",
                       headers=ADMIN).status_code == 200
    resp = _enroll(second["token"])
    assert resp.status_code == 401
    assert "expired" not in resp.json()["detail"]


def test_token_listing_carries_no_secrets(managed):
    _mint()
    tokens = client.get("/admin/enrollment-tokens", headers=ADMIN).json()["tokens"]
    assert tokens and all("token" not in t and "token_hash" not in t for t in tokens)
    assert all(t["expires_at"] for t in tokens)  # what an operator judges by


# ------------------------------------------------------------ supersession --


def test_a_silent_device_is_superseded_by_reenrollment(managed):
    """The reimaged laptop: its old record is revoked, its new one works, and
    nobody had to notice the machine never said goodbye."""
    token = _mint()["token"]
    first = _enroll(token).json()
    second = _enroll(token).json()
    assert second["device_id"] != first["device_id"]

    # Old credential dead, new one live.
    assert client.post("/report", json={"tool": "x"}, headers={
        "Authorization": f"Bearer {first['device_token']}"}).status_code == 401
    assert client.post("/report", json={"tool": "x"}, headers={
        "Authorization": f"Bearer {second['device_token']}"}).status_code == 200


def test_an_actively_reporting_device_cannot_be_displaced(managed):
    """The stolen-token shape: same serial while the real machine is alive is
    a 409 and an audit event, not a silent takeover."""
    token = _mint()["token"]
    first = _enroll(token).json()
    client.post("/report", json={"tool": "x"}, headers={
        "Authorization": f"Bearer {first['device_token']}"})  # stamps last_seen

    resp = _enroll(token)
    assert resp.status_code == 409
    # The real machine is untouched.
    assert client.post("/report", json={"tool": "x"}, headers={
        "Authorization": f"Bearer {first['device_token']}"}).status_code == 200
    kinds = [r["kind"] for r in managed._db.execute("SELECT kind FROM events")]
    assert "supersede_conflict" in kinds

    # Manual revoke is the documented path through the 409.
    did = first["device_id"]
    client.post(f"/admin/devices/{did}/revoke", headers=ADMIN)
    assert _enroll(token).status_code == 200


# ------------------------------------------------------------- edge cases --


def test_enroll_validates_platform_and_caps_the_body(managed):
    token = _mint()["token"]
    assert _enroll(token, platform="solaris").status_code == 422
    resp = client.post("/enroll",
                       headers={"Authorization": f"Bearer {token}",
                                "Content-Length": "9999999"})
    assert resp.status_code == 413


def test_enroll_with_a_shaped_but_unknown_token_is_401(managed):
    assert _enroll("aige_never-minted").status_code == 401
