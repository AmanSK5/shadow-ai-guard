"""Finding lifecycle, the audit read, and the discovery webhook.

Three small features with one shape: the receiver stores the human's answer
(a finding status, an admin action, a webhook URL) and never re-derives the
question. The properties under test: statuses are validated and auditable,
the audit read returns what the writes recorded, and the webhook fires
exactly once per new candidate - never on a rerun, never when unset, and
never in a way that can fail the ingest request.
"""

import os

os.environ.setdefault("AUTH_TOKEN", "test-token-for-ci")

import pytest
from fastapi.testclient import TestClient

from app import main
from app import state as state_mod
from app.main import app

client = TestClient(app)

AUTH = {"Authorization": "Bearer test-token-for-ci"}
ADMIN = {"Authorization": "Bearer admin-test-token"}

CANDIDATE = {
    "kind": "domain", "name": "Mystery AI", "vendor": "Mystery Labs",
    "category": "assistant", "confidence": "high",
    "domains": ["mystery-ai.example"], "devices": 3,
    "evidence": "seen in fleet DNS over 7d",
}


@pytest.fixture
def managed(tmp_path, monkeypatch):
    st = state_mod.State(str(tmp_path / "state.db"))
    monkeypatch.setattr(main, "STATE", st)
    monkeypatch.setattr(main, "_EXPECTED_ADMIN", b"Bearer admin-test-token")
    yield st


@pytest.fixture
def webhook(managed, monkeypatch):
    """Point the webhook at a recorder, and run the notify thread inline so
    the test can assert on it."""
    managed.set_setting("webhook_url", "https://hooks.example/T/B/x")
    sent = []
    monkeypatch.setattr(main.httpx, "post",
                        lambda url, json=None, timeout=None:
                        sent.append((url, json)))

    class InlineThread:
        def __init__(self, target=None, daemon=None):
            self._target = target
        def start(self):
            self._target()

    monkeypatch.setattr(main.threading, "Thread", InlineThread)
    yield sent


# ------------------------------------------------------- finding lifecycle --


def test_status_round_trip_with_actor_and_reason(managed):
    r = client.put("/admin/finding-status", headers=ADMIN, json={
        "key": '["sam","gmail.com","chatgpt","MAC-1"]',
        "status": "accepted", "reason": "migrating to the work account"})
    assert r.status_code == 200
    (s,) = client.get("/admin/finding-status",
                      headers=ADMIN).json()["statuses"]
    assert s["status"] == "accepted"
    assert s["reason"] == "migrating to the work account"
    assert s["actor"] == "api"          # the API credential, not a person
    assert s["at"]


def test_status_must_be_a_known_one(managed):
    r = client.put("/admin/finding-status", headers=ADMIN,
                   json={"key": "k", "status": "ignored"})
    assert r.status_code == 422


def test_clear_removes_and_404s_when_nothing_stood(managed):
    client.put("/admin/finding-status", headers=ADMIN,
               json={"key": "k", "status": "acknowledged"})
    assert client.post("/admin/finding-status/clear", headers=ADMIN,
                       json={"key": "k"}).status_code == 200
    assert client.get("/admin/finding-status",
                      headers=ADMIN).json()["statuses"] == []
    assert client.post("/admin/finding-status/clear", headers=ADMIN,
                       json={"key": "k"}).status_code == 404


def test_lifecycle_routes_need_admin(managed):
    assert client.get("/admin/finding-status",
                      headers=AUTH).status_code == 401
    assert client.put("/admin/finding-status", headers=AUTH,
                      json={"key": "k", "status": "acknowledged"}).status_code == 401


# ------------------------------------------------------------------ audit --


def test_the_audit_read_returns_what_writes_recorded(managed):
    client.put("/admin/finding-status", headers=ADMIN,
               json={"key": "k", "status": "acknowledged"})
    events = client.get("/admin/events", headers=ADMIN).json()["events"]
    kinds = [e["kind"] for e in events]
    assert "finding_status_set" in kinds
    e = next(x for x in events if x["kind"] == "finding_status_set")
    assert e["detail"]["status"] == "acknowledged"
    assert e["at"]


def test_events_newest_first_and_capped(managed):
    for i in range(5):
        client.put("/admin/finding-status", headers=ADMIN,
                   json={"key": "k%d" % i, "status": "acknowledged"})
    events = client.get("/admin/events?limit=3", headers=ADMIN).json()["events"]
    assert len(events) == 3
    assert events[0]["detail"]["key"] == "k4"     # newest first


# ---------------------------------------------------------------- webhook --


def test_new_candidate_fires_the_webhook_once(webhook):
    client.post("/candidates", headers=AUTH,
                json={"candidates": [CANDIDATE]})
    assert len(webhook) == 1
    url, payload = webhook[0]
    assert url == "https://hooks.example/T/B/x"
    assert "Mystery AI" in payload["text"]
    # A rerun of the same discovery is not a new decision to make.
    client.post("/candidates", headers=AUTH,
                json={"candidates": [CANDIDATE]})
    assert len(webhook) == 1


def test_no_webhook_url_means_no_call(managed, monkeypatch):
    called = []
    monkeypatch.setattr(main.httpx, "post",
                        lambda *a, **k: called.append(1))
    client.post("/candidates", headers=AUTH,
                json={"candidates": [CANDIDATE]})
    assert called == []


def test_webhook_failure_never_fails_the_ingest(webhook, monkeypatch):
    def boom(*a, **k):
        raise OSError("connection refused")
    monkeypatch.setattr(main.httpx, "post", boom)
    r = client.post("/candidates", headers=AUTH,
                    json={"candidates": [CANDIDATE]})
    assert r.status_code == 200
