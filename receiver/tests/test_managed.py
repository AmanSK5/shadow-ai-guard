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


def test_a_registry_read_counts_as_seen(managed, tmp_path, monkeypatch):
    """Discovery only ever reads the registry, and a collector's registry
    fetch precedes its report. Either should show the device alive, with the
    version it sent, rather than leaving last_seen empty until a finding."""
    from app import main

    reg = tmp_path / "collector.json"
    reg.write_text('{"version": 1}')
    monkeypatch.setattr(main, "COLLECTOR_REGISTRY_PATH", str(reg))

    enrolled = _enroll(_mint()["token"], platform="linux", serial="srv-1").json()
    resp = client.get("/registry/collector", headers={
        "Authorization": f"Bearer {enrolled['device_token']}",
        "X-AiGuard-Agent-Version": "2.0.1"})
    assert resp.status_code == 200
    (d,) = client.get("/admin/devices", headers=ADMIN).json()["devices"]
    assert d["last_seen"] is not None and d["agent_version"] == "2.0.1"

    # And the 1h active guard sees it: a second enrollment now is the
    # stolen-token shape, not the reimaged one.
    assert _enroll(_mint()["token"], platform="linux", serial="srv-1").status_code == 409


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


# ------------------------------------------------------------ re-enrollment --


def test_a_silent_device_is_reissued_in_place_by_reenrollment(managed):
    """The reimaged laptop, and the stateless scanner that enrolls every run:
    same device id, new credential, and no revoked row left behind. The old
    credential is dead the instant the new one exists."""
    token = _mint()["token"]
    first = _enroll(token, hostname="old-name").json()
    second = _enroll(token, hostname="new-name", agent_version="2.1.0").json()
    assert second["device_id"] == first["device_id"]
    assert second["device_token"] != first["device_token"]

    assert client.post("/report", json={"tool": "x"}, headers={
        "Authorization": f"Bearer {first['device_token']}"}).status_code == 401
    assert client.post("/report", json={"tool": "x"}, headers={
        "Authorization": f"Bearer {second['device_token']}"}).status_code == 200

    devices = client.get("/admin/devices", headers=ADMIN).json()["devices"]
    assert len(devices) == 1  # one row, not one per run
    assert devices[0]["hostname"] == "new-name"
    assert devices[0]["agent_version"] == "2.1.0"
    assert devices[0]["revoked_at"] is None
    # The visible trace that a re-enrollment happened, for the operator who
    # would otherwise see one tidy row where a device was displaced.
    assert devices[0]["enrollments"] == 2 and devices[0]["reenrolled_at"] is not None
    kinds = [r["kind"] for r in managed._db.execute("SELECT kind FROM events")]
    assert kinds.count("enrolled") == 1 and "reenrolled" in kinds


def test_a_stateless_scanner_reenrolls_even_while_active(managed):
    """A scanner keeps nothing between runs and enrolls every time. An hourly
    schedule, or a Job retried after its registry fetch, would trip the
    active guard that protects laptops; for scanners it always reissues."""
    token = _mint()["token"]
    first = _enroll(token, platform="scanner", serial="nightly").json()
    client.post("/report", json={"tool": "x"}, headers={
        "Authorization": f"Bearer {first['device_token']}"})  # active right now
    second = _enroll(token, platform="scanner", serial="nightly")
    assert second.status_code == 200
    assert second.json()["device_id"] == first["device_id"]


def test_a_database_from_before_the_added_columns_is_upgraded(tmp_path):
    """The homelab has a state.db from 0.9.5. Opening it must add the new
    device columns and keep every row."""
    import sqlite3
    path = tmp_path / "old.db"
    db = sqlite3.connect(path)
    db.executescript(state_mod._SCHEMA)
    db.execute("INSERT INTO enrollment_tokens VALUES ('t1', X'00', '', '2026-01-01', '2027-01-01', NULL)")
    db.execute("INSERT INTO devices (id, platform, serial, cred_hash, enrolled_at, enrolled_with)"
               " VALUES ('d1', 'macos', 'S', X'01', '2026-01-01', 't1')")
    db.commit()
    # Simulate the pre-upgrade shape by recreating the table without the
    # added columns.
    db.executescript("""
        CREATE TABLE devices_old AS SELECT id, platform, serial, hostname, cred_hash,
          enrolled_at, enrolled_with, last_seen, agent_version, revoked_at FROM devices;
        DROP TABLE devices;
        ALTER TABLE devices_old RENAME TO devices;
    """)
    db.commit()
    db.close()

    st = state_mod.State(str(path))
    (d,) = st.list_devices()
    assert d["id"] == "d1" and d["enrollments"] == 1 and d["reenrolled_at"] is None


def test_a_revoked_serial_cannot_enroll_itself_back(managed):
    """Revocation has to survive the token that created the device.

    The enrollment token lives in an MDM artifact, which is exactly where
    someone being cut off would still have it. If a revoked serial could
    enroll again, revoke would mean "until the next check-in"."""
    token = _mint()["token"]
    first = _enroll(token).json()
    client.post(f"/admin/devices/{first['device_id']}/revoke", headers=ADMIN)

    resp = _enroll(token)
    assert resp.status_code == 409
    assert "allow" in resp.json()["detail"]
    # Nothing was minted: the fleet still holds one row, and it is revoked.
    devices = client.get("/admin/devices", headers=ADMIN).json()["devices"]
    assert [bool(d["revoked_at"]) for d in devices] == [True]
    kinds = [r["kind"] for r in managed._db.execute("SELECT kind FROM events")]
    assert "enroll_refused_revoked" in kinds


def test_an_admin_can_let_a_revoked_serial_back_exactly_once(managed):
    """The reimage and the replacement machine, said deliberately. The
    allowance is spent by the enrollment it permits, so the new credential
    is revocable with the same finality as the one it replaces."""
    token = _mint()["token"]
    first = _enroll(token).json()
    did = first["device_id"]
    client.post(f"/admin/devices/{did}/revoke", headers=ADMIN)
    assert client.post(f"/admin/devices/{did}/allow-reenrollment",
                       headers=ADMIN).status_code == 200

    second = _enroll(token).json()
    assert second["device_id"] != did
    # The revoked row stays as history beside the new one.
    devices = client.get("/admin/devices", headers=ADMIN).json()["devices"]
    assert sorted(bool(d["revoked_at"]) for d in devices) == [False, True]
    # And the allowance is gone: revoking the new row re-arms the tombstone.
    client.post(f"/admin/devices/{second['device_id']}/revoke", headers=ADMIN)
    assert _enroll(token).status_code == 409


def test_allowing_reenrollment_needs_a_revoked_device(managed):
    """An active device has nothing to allow, and a standing allowance
    cannot be stacked up ahead of time."""
    token = _mint()["token"]
    did = _enroll(token).json()["device_id"]
    assert client.post(f"/admin/devices/{did}/allow-reenrollment",
                       headers=ADMIN).status_code == 404
    assert client.post("/admin/devices/nope/allow-reenrollment",
                       headers=ADMIN).status_code == 404

    client.post(f"/admin/devices/{did}/revoke", headers=ADMIN)
    assert client.post(f"/admin/devices/{did}/allow-reenrollment",
                       headers=ADMIN).status_code == 200
    # Twice is not two enrollments.
    assert client.post(f"/admin/devices/{did}/allow-reenrollment",
                       headers=ADMIN).status_code == 404


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

    # Manual revoke is still the documented path through the 409, and since
    # a revoked serial is a tombstone it takes the second deliberate step.
    did = first["device_id"]
    client.post(f"/admin/devices/{did}/revoke", headers=ADMIN)
    assert _enroll(token).status_code == 409
    client.post(f"/admin/devices/{did}/allow-reenrollment", headers=ADMIN)
    assert _enroll(token).status_code == 200


# ------------------------------------------------------ the off-switch --


def test_requiring_device_credentials_turns_the_shared_token_away(managed, monkeypatch,
                                                                  tmp_path):
    """The final step of the migration: once every surface has enrolled, the
    shared token stops being a credential. Device credentials, enrollment and
    admin all keep working; the refusal names itself so a straggler's MDM
    log says enroll rather than bad token."""
    from app import main

    reg = tmp_path / "collector.json"
    reg.write_text('{"version": 1}')
    monkeypatch.setattr(main, "COLLECTOR_REGISTRY_PATH", str(reg))

    cred = _enroll(_mint()["token"]).json()["device_token"]
    monkeypatch.setattr(main, "REQUIRE_DEVICE_CREDENTIALS", True)

    for path, call, kw in (("/report", client.post, {"json": {"tool": "x"}}),
                           ("/registry/collector", client.get, {})):
        resp = call(path, headers=AUTH, **kw)
        assert resp.status_code == 401
        assert "enroll" in resp.json()["detail"]
        assert call(path, headers={"Authorization": f"Bearer {cred}"}, **kw).status_code == 200
    # A wrong token is still just a bad token, not an invitation.
    assert client.post("/report", json={"tool": "x"},
                       headers={"Authorization": "Bearer nope"}).json()["detail"] == "bad token"
    assert _enroll(_mint()["token"], serial="OTHER").status_code == 200
    assert client.get("/admin/devices", headers=ADMIN).status_code == 200


def test_requiring_device_credentials_without_managed_mode_refuses_to_start():
    """Nothing could authenticate: a startup error, not a receiver that
    silently 401s the whole estate."""
    import subprocess
    import sys

    env = {**os.environ, "AUTH_TOKEN": "x", "REQUIRE_DEVICE_CREDENTIALS": "true"}
    env.pop("MANAGED_MODE", None)
    proc = subprocess.run([sys.executable, "-c", "import app.main"], env=env,
                          capture_output=True, text=True,
                          cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    assert proc.returncode != 0
    assert "MANAGED_MODE" in proc.stderr


# ------------------------------------------------------------- edge cases --


def test_enroll_validates_platform_and_caps_the_body(managed):
    token = _mint()["token"]
    assert _enroll(token, platform="solaris").status_code == 422
    # The non-collector surfaces enroll too, keyed apart by platform so a
    # laptop's browser profile never collides with its collector.
    assert _enroll(token, platform="browser", serial="C02TEST/3f9a1c2e").status_code == 200
    assert _enroll(token, platform="scanner", serial="scanner").status_code == 200
    assert _enroll(token, platform="macos", serial="C02TEST").status_code == 200
    assert len(client.get("/admin/devices", headers=ADMIN).json()["devices"]) == 3
    resp = client.post("/enroll",
                       headers={"Authorization": f"Bearer {token}",
                                "Content-Length": "9999999"})
    assert resp.status_code == 413


def test_enroll_with_a_shaped_but_unknown_token_is_401(managed):
    assert _enroll("aige_never-minted").status_code == 401
