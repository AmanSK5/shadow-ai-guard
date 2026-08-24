"""Delivery semantics: a 200 from /report means the finding reached the
configured log store, not merely this container's stdout.

Collectors advance their delivered state only on 200, so acknowledging a
finding the store rejected made them discard it: a broken token produced a
clean-looking dashboard because telemetry silently stopped reaching
storage - the exact failure the platform exists to catch. The properties
under test: a failed push is a 503 the collector will retry, a successful
push is a 200, and no push configured keeps the stdout-only contract.
"""

import os

os.environ.setdefault("AUTH_TOKEN", "test-token-for-ci")

import httpx
import pytest
from fastapi.testclient import TestClient

from app import main
from app.main import app

client = TestClient(app)

AUTH = {"Authorization": "Bearer test-token-for-ci"}

FINDING = {
    "tool": "claude-code", "surface": "cli", "os": "macos",
    "account_domain": "gmail.com", "device": "MAC-1", "user": "sam",
    "evidence": "~/.claude.json", "severity": "warn",
    "reported_at": "2026-08-24T12:00:00Z", "source": "collector-macos",
}


@pytest.fixture
def pushing(monkeypatch):
    """A configured push target; each test decides whether it works."""
    monkeypatch.setattr(main, "LOKI_PUSH_URL",
                        "http://loki.example/loki/api/v1/push")
    yield


def _fake_post(result):
    class FakeResponse:
        status_code = 401

        def raise_for_status(self):
            if not result:
                raise httpx.HTTPStatusError(
                    "no", request=None, response=self)

    async def post(self, url, **kw):
        return FakeResponse()

    return post


def test_a_failed_push_is_a_503_the_collector_will_retry(pushing, monkeypatch):
    monkeypatch.setattr(httpx.AsyncClient, "post", _fake_post(False))
    r = client.post("/report", headers=AUTH, json=FINDING)
    assert r.status_code == 503
    assert "retry" in r.json()["detail"]


def test_a_successful_push_is_a_200(pushing, monkeypatch):
    monkeypatch.setattr(httpx.AsyncClient, "post", _fake_post(True))
    r = client.post("/report", headers=AUTH, json=FINDING)
    assert r.status_code == 200


def test_no_push_configured_keeps_the_stdout_contract(monkeypatch):
    monkeypatch.setattr(main, "LOKI_PUSH_URL", "")
    r = client.post("/report", headers=AUTH, json=FINDING)
    assert r.status_code == 200


def test_a_full_scrypt_gate_is_a_cheap_429(tmp_path, monkeypatch):
    """A first-burst of logins that beats the failure counters is refused
    rather than queued: waiters on the gate would occupy the worker threads
    the gate exists to protect."""
    from app import state as state_mod
    st = state_mod.State(str(tmp_path / "state.db"))
    monkeypatch.setattr(main, "STATE", st)
    monkeypatch.setattr(main, "_login_failures", {})
    st.create_admin("root", "a-long-enough-password")
    for _ in range(4):
        assert main._scrypt_gate.acquire(blocking=False)
    try:
        r = client.post("/admin/login",
                        json={"username": "root",
                              "password": "a-long-enough-password"})
        assert r.status_code == 429
        assert "Retry-After" in r.headers
    finally:
        for _ in range(4):
            main._scrypt_gate.release()
    # Slots free again: the same login succeeds.
    r = client.post("/admin/login",
                    json={"username": "root",
                          "password": "a-long-enough-password"})
    assert r.status_code == 200
