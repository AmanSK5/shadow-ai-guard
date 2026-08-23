"""Admin accounts and sessions: the portal's login, backed by the receiver.

Same testing shape as test_managed: the module is imported classic and
managed mode is switched on per-test through the globals, which mirrors
production (every code path reads them at call time) and avoids re-importing
the module. LOGIN_FAILURE_DELAY_SECONDS is zeroed so failure tests do not
spend half a second each proving a sleep happens.
"""

import os

os.environ.setdefault("AUTH_TOKEN", "test-token-for-ci")

import pytest
from fastapi.testclient import TestClient

from app import state as state_mod
from app.main import app

client = TestClient(app)

API_ADMIN = {"Authorization": "Bearer admin-test-token"}
PASSWORD = "a-long-enough-password"


@pytest.fixture
def managed(tmp_path, monkeypatch):
    """Managed mode with a boot-printed setup code and NO API credential,
    which is the fresh-install shape the wizard is designed for."""
    from app import main

    st = state_mod.State(str(tmp_path / "state.db"))
    monkeypatch.setattr(main, "STATE", st)
    monkeypatch.setattr(main, "_EXPECTED_ADMIN", b"")
    monkeypatch.setattr(main, "_SETUP_CODE", "aigs_test-setup-code")
    monkeypatch.setattr(main, "LOGIN_FAILURE_DELAY_SECONDS", 0)
    return st


def _setup(**kw):
    return client.post("/admin/setup", json={
        "setup_code": "aigs_test-setup-code", "username": "aman",
        "password": PASSWORD, **kw})


def _login(username="aman", password=PASSWORD):
    return client.post("/admin/login",
                       json={"username": username, "password": password})


def _hdr(token):
    return {"Authorization": f"Bearer {token}"}


# ------------------------------------------------------------ mode gating --


def test_auth_routes_do_not_exist_in_classic_mode():
    assert client.get("/admin/setup").status_code == 404
    assert _setup().status_code == 404
    assert _login().status_code == 404


# ------------------------------------------------------------- first boot --


def test_the_first_boot_flow(managed):
    """The acceptance test's opening move: fresh install, setup code from
    the logs, create the account, and leave already signed in."""
    assert client.get("/admin/setup").json() == {"needed": True}

    resp = _setup()
    assert resp.status_code == 200
    token = resp.json()["token"]
    assert token.startswith("aigt_")

    # The session from setup is immediately an admin.
    assert client.get("/admin/devices", headers=_hdr(token)).status_code == 200
    assert client.get("/admin/setup").json() == {"needed": False}

    # And it is a named person, not a credential.
    who = client.get("/admin/session", headers=_hdr(token)).json()
    assert who["username"] == "aman" and who["expires_at"]


def test_a_wrong_setup_code_is_refused(managed):
    assert _setup(setup_code="aigs_guessed").status_code == 401
    # Non-ASCII must be a 401, not a compare_digest TypeError and a 500.
    assert _setup(setup_code="aigs_guéssed").status_code == 401
    assert client.get("/admin/setup").json() == {"needed": True}


def test_the_door_shuts_after_the_first_account(managed):
    _setup()
    resp = _setup(username="second")
    assert resp.status_code == 409
    # Consumed even for the holder of the real code: one boot, one claim.
    from app import main
    assert main._SETUP_CODE is None


def test_a_short_password_is_refused_at_the_door(managed):
    assert _setup(password="short").status_code == 422
    assert client.get("/admin/setup").json() == {"needed": True}


def test_a_fresh_managed_boot_without_admin_token_starts_and_prints_a_code(tmp_path):
    """ADMIN_TOKEN used to be required in managed mode. A fresh install now
    boots without it and prints the setup code to its log."""
    import subprocess
    import sys

    env = {**os.environ, "AUTH_TOKEN": "x", "MANAGED_MODE": "true",
           "STATE_DB_PATH": str(tmp_path / "state.db")}
    env.pop("ADMIN_TOKEN", None)
    proc = subprocess.run(
        [sys.executable, "-c", "import app.main"], env=env,
        capture_output=True, text=True,
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    assert proc.returncode == 0, proc.stderr
    assert '"kind": "setup_code"' in proc.stdout
    assert "aigs_" in proc.stdout


def test_a_boot_with_an_existing_admin_prints_no_code(tmp_path):
    import subprocess
    import sys

    st = state_mod.State(str(tmp_path / "state.db"))
    st.create_admin("aman", PASSWORD)
    env = {**os.environ, "AUTH_TOKEN": "x", "MANAGED_MODE": "true",
           "STATE_DB_PATH": str(tmp_path / "state.db")}
    proc = subprocess.run(
        [sys.executable, "-c", "import app.main"], env=env,
        capture_output=True, text=True,
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    assert proc.returncode == 0, proc.stderr
    assert "setup_code" not in proc.stdout


# --------------------------------------------------------------- sessions --


def test_login_logout_lifecycle(managed):
    _setup()
    assert _login(password="wrong").status_code == 401
    assert _login(username="nobody").status_code == 401
    # One message for both failures: naming which half was wrong tells an
    # attacker which usernames exist.
    assert (_login(password="wrong").json()["detail"]
            == _login(username="nobody").json()["detail"])

    token = _login().json()["token"]
    assert client.get("/admin/devices", headers=_hdr(token)).status_code == 200
    assert client.post("/admin/logout", headers=_hdr(token)).status_code == 200
    assert client.get("/admin/devices", headers=_hdr(token)).status_code == 401


def test_an_expired_session_is_refused(managed):
    _setup()
    token = _login().json()["token"]
    managed._db.execute("UPDATE sessions SET expires_at = '2000-01-01T00:00:00+00:00'")
    managed._db.commit()
    assert client.get("/admin/devices", headers=_hdr(token)).status_code == 401


def test_sessions_store_no_plaintext(managed):
    _setup()
    token = _login().json()["token"]
    rows = managed._db.execute("SELECT token_hash FROM sessions").fetchall()
    assert rows and all(token.encode() not in bytes(r["token_hash"]) for r in rows)
    stored = managed._db.execute(
        "SELECT password_hash FROM admin_users").fetchone()["password_hash"]
    assert PASSWORD not in stored and stored.startswith("scrypt$")


def test_a_session_is_not_an_ingest_credential_and_vice_versa(managed):
    """Same boundary discipline as every other prefix: a session
    administrates, it does not report, and the fleet's tokens do not
    administrate."""
    token = _setup().json()["token"]
    assert client.post("/report", headers=_hdr(token),
                       json={"tool": "x"}).status_code == 401
    mint = client.post("/admin/enrollment-tokens", headers=_hdr(token),
                       json={"note": "t"})
    assert mint.status_code == 200
    enroll = client.post("/enroll", headers=_hdr(mint.json()["token"]),
                         json={"platform": "macos", "serial": "S"})
    cred = enroll.json()["device_token"]
    assert client.get("/admin/devices", headers=_hdr(cred)).status_code == 401


# --------------------------------------------------------------- password --


def test_password_change_requires_the_current_one_and_kills_other_sessions(managed):
    mine = _setup().json()["token"]
    other = _login().json()["token"]

    resp = client.post("/admin/password", headers=_hdr(mine),
                       json={"current": "wrong", "new": "another-long-password"})
    assert resp.status_code == 401

    resp = client.post("/admin/password", headers=_hdr(mine),
                       json={"current": PASSWORD, "new": "another-long-password"})
    assert resp.status_code == 200

    # The session that made the change lives; the stolen one dies with the
    # password it was stolen under.
    assert client.get("/admin/devices", headers=_hdr(mine)).status_code == 200
    assert client.get("/admin/devices", headers=_hdr(other)).status_code == 401
    assert _login(password=PASSWORD).status_code == 401
    assert _login(password="another-long-password").status_code == 200


def test_the_api_credential_is_break_glass(managed, monkeypatch):
    """Locked out: set ADMIN_TOKEN, reset the password without knowing the
    old one, log back in."""
    from app import main

    _setup()
    monkeypatch.setattr(main, "_EXPECTED_ADMIN", b"Bearer admin-test-token")
    resp = client.post("/admin/password", headers=API_ADMIN,
                       json={"new": "recovered-long-password"})
    assert resp.status_code == 200
    assert _login(password="recovered-long-password").status_code == 200
    # The credential is not a person: the probe says so.
    who = client.get("/admin/session", headers=API_ADMIN).json()
    assert who == {"username": "", "expires_at": None}


def test_password_change_with_no_account_is_409(managed, monkeypatch):
    from app import main

    monkeypatch.setattr(main, "_EXPECTED_ADMIN", b"Bearer admin-test-token")
    resp = client.post("/admin/password", headers=API_ADMIN,
                       json={"new": "recovered-long-password"})
    assert resp.status_code == 409
