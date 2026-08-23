"""The candidates queue: observed-but-undefined tools, awaiting a human.

The properties under test: a reporting credential can suggest a tool but
never define one; the receiver re-validates every field rather than
trusting the scanner that posted it; a dismissal is a stored decision that
a rerun cannot reopen; and adding a registry entry resolves the candidate
that suggested it, closing the discovery loop without a second decision.
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
    "kind": "domain",
    "name": "Mystery AI",
    "vendor": "Mystery Labs",
    "category": "assistant",
    "confidence": "high",
    "domains": ["mystery-ai.example"],
    "devices": 3,
    "evidence": "seen in fleet DNS over 7d",
}


@pytest.fixture
def managed(tmp_path, monkeypatch):
    st = state_mod.State(str(tmp_path / "state.db"))
    monkeypatch.setattr(main, "STATE", st)
    monkeypatch.setattr(main, "_EXPECTED_ADMIN", b"Bearer admin-test-token")
    yield st


def _post(body=None, headers=AUTH):
    return client.post("/candidates", headers=headers,
                       json=body or {"candidates": [CANDIDATE]})


# ---------------------------------------------------------------- the loop --


def test_a_posted_candidate_reaches_the_admin_queue(managed):
    resp = _post()
    assert resp.status_code == 200 and resp.json() == {"accepted": 1}
    (c,) = client.get("/admin/candidates", headers=ADMIN).json()["candidates"]
    assert c["key"] == "domain:mystery-ai"
    assert c["name"] == "Mystery AI"
    assert c["domains"] == ["mystery-ai.example"]
    assert c["devices"] == 3
    assert c["source"] == "shared-token"
    assert c["resolved"] is False
    assert c["dismissed_at"] is None


def test_a_rerun_refreshes_counts_but_not_first_seen(managed):
    _post()
    first = client.get("/admin/candidates", headers=ADMIN).json()["candidates"][0]
    _post({"candidates": [{**CANDIDATE, "devices": 9, "confidence": "medium"}]})
    (c,) = client.get("/admin/candidates", headers=ADMIN).json()["candidates"]
    assert c["devices"] == 9 and c["confidence"] == "medium"
    assert c["first_seen"] == first["first_seen"]


def test_dismissal_survives_the_next_run(managed):
    _post()
    resp = client.post("/admin/candidates/domain:mystery-ai/dismiss",
                       headers=ADMIN)
    assert resp.status_code == 200
    _post({"candidates": [{**CANDIDATE, "devices": 12}]})
    (c,) = client.get("/admin/candidates", headers=ADMIN).json()["candidates"]
    assert c["dismissed_at"] is not None
    assert c["devices"] == 12  # still tracked, still dismissed


def test_dismissing_twice_is_a_404_not_a_second_decision(managed):
    _post()
    client.post("/admin/candidates/domain:mystery-ai/dismiss", headers=ADMIN)
    resp = client.post("/admin/candidates/domain:mystery-ai/dismiss",
                       headers=ADMIN)
    assert resp.status_code == 404


def test_adding_the_registry_entry_resolves_the_candidate(managed):
    """The closing of the loop: define the tool the candidate suggested and
    the candidate stops being a question."""
    _post()
    entry = {
        "id": "mystery-ai", "name": "Mystery AI", "vendor": "Mystery Labs",
        "category": "assistant", "domains": ["mystery-ai.example"],
    }
    resp = client.put("/admin/registry-entries", headers=ADMIN,
                      json={"entries": [entry]})
    assert resp.status_code == 200, resp.text
    (c,) = client.get("/admin/candidates", headers=ADMIN).json()["candidates"]
    assert c["resolved"] is True


# ----------------------------------------------------------------- the gate --


def test_the_key_is_computed_not_taken(managed):
    """Capitalisation variants land on one row, and a caller cannot supply
    its own key at all (extra fields are refused)."""
    _post({"candidates": [{**CANDIDATE, "name": "MYSTERY ai"}]})
    _post()
    got = client.get("/admin/candidates", headers=ADMIN).json()["candidates"]
    assert len(got) == 1
    assert _post({"candidates": [{**CANDIDATE, "key": "evil"}]}).status_code == 422


def test_the_receiver_validates_what_the_scanner_claims_it_validated(managed):
    bad = [
        {**CANDIDATE, "name": "<script>alert(1)</script>"},
        {**CANDIDATE, "vendor": "a\nb"},
        {**CANDIDATE, "kind": "surprise"},
        {**CANDIDATE, "confidence": "sure"},
        {**CANDIDATE, "domains": ["Mystery-AI.Example"]},
        {**CANDIDATE, "domains": ["bad domain"]},
    ]
    for c in bad:
        assert _post({"candidates": [c]}).status_code == 422, c
    assert client.get("/admin/candidates",
                      headers=ADMIN).json()["candidates"] == []


def test_a_reporting_credential_cannot_read_or_dismiss(managed):
    _post()
    assert client.get("/admin/candidates", headers=AUTH).status_code == 401
    assert client.post("/admin/candidates/domain:mystery-ai/dismiss",
                       headers=AUTH).status_code == 401


def test_unauthenticated_posts_are_refused(managed):
    assert _post(headers={}).status_code == 401


def test_classic_mode_has_no_candidates_surface():
    assert _post().status_code == 404
    assert client.get("/admin/candidates", headers=ADMIN).status_code == 404
