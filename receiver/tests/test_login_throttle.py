"""Failed-login throttling: /admin/login is necessarily open and scrypt is
deliberately expensive, so without a cap an unauthenticated caller can spend
receiver CPU freely and grow the audit log one row per attempt.

The properties under test: past the per-username cap the answer is a cheap
429 with Retry-After and no new audit rows; other usernames keep working
until the global cap; a correct login under the cap is unaffected; and the
audit log records a bounded number of failures plus one throttle event,
however long the attack runs.
"""

import os

os.environ.setdefault("AUTH_TOKEN", "test-token-for-ci")

import pytest
from fastapi.testclient import TestClient

from app import main
from app import state as state_mod
from app.main import app

client = TestClient(app)

ADMIN = {"Authorization": "Bearer admin-test-token"}
PW = "a-long-enough-password"


@pytest.fixture
def managed(tmp_path, monkeypatch):
    st = state_mod.State(str(tmp_path / "state.db"))
    monkeypatch.setattr(main, "STATE", st)
    monkeypatch.setattr(main, "_EXPECTED_ADMIN", b"Bearer admin-test-token")
    # Fresh counters per test, and no real sleeping in the failure path.
    monkeypatch.setattr(main, "_login_failures", {})
    monkeypatch.setattr(main, "LOGIN_FAILURE_DELAY_SECONDS", 0)
    st.create_admin("root", PW)
    yield st


def _fail(username="root", n=1):
    last = None
    for _ in range(n):
        last = client.post("/admin/login",
                           json={"username": username, "password": "wrong-x-wrong"})
    return last


def test_past_the_cap_is_a_cheap_429_with_retry_after(managed):
    assert _fail(n=main.LOGIN_MAX_FAILURES_PER_USER).status_code == 401
    r = _fail()
    assert r.status_code == 429
    assert "Retry-After" in r.headers


def test_a_throttled_user_does_not_block_others(managed):
    _fail(n=main.LOGIN_MAX_FAILURES_PER_USER)
    assert _fail(username="someone-else").status_code == 401


def test_the_global_cap_backstops_username_spraying(managed, monkeypatch):
    monkeypatch.setattr(main, "LOGIN_MAX_FAILURES_GLOBAL", 5)
    for i in range(5):
        _fail(username="user-%d" % i)
    r = _fail(username="user-fresh")
    assert r.status_code == 429


def test_a_correct_login_under_the_cap_still_works(managed):
    _fail(n=3)
    r = client.post("/admin/login", json={"username": "root", "password": PW})
    assert r.status_code == 200 and r.json()["token"].startswith("aigt_")


def test_the_audit_log_stays_bounded_under_attack(managed):
    _fail(n=main.LOGIN_MAX_FAILURES_PER_USER + 20)
    events = client.get("/admin/events", headers=ADMIN).json()["events"]
    failed = [e for e in events if e["kind"] == "login_failed"]
    throttled = [e for e in events if e["kind"] == "login_throttled"]
    assert len(failed) == main.LOGIN_LOGGED_FAILURES
    assert len(throttled) == 1
