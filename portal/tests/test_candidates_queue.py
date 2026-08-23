"""The portal side of the discovery queue: forwarding, not deciding.

The receiver owns the candidates and their validation; the portal's job is
to forward the operator's own session verbatim, keep the receiver's
annotations intact for the page, and make the CronJob artifact that feeds
the queue downloadable like every other deployment artifact.
"""

import os

os.environ.setdefault("PORTAL_AUTH", "none")

import pytest

from app import main, managed


@pytest.fixture
def configured(monkeypatch):
    monkeypatch.setattr(main, "RECEIVER_URL", "http://receiver.internal:8080")
    monkeypatch.setattr(main, "RECEIVER_PUBLIC_URL", "https://rx.example.com")


@pytest.fixture
def receiver(monkeypatch, configured):
    calls = []

    def fake(base, method, path, admin_token, body=None):
        calls.append({"method": method, "path": path,
                      "token": admin_token, "body": body})
        if path == "/admin/candidates":
            return {"candidates": [
                {"key": "domain:mystery-ai", "name": "Mystery AI",
                 "domains": ["mystery-ai.example"], "devices": 3,
                 "resolved": False, "dismissed_at": None}]}
        if method == "POST" and path == "/admin/enrollment-tokens":
            return {"id": "tok1", "token": "aige_MINTED",
                    "expires_at": "2027-01-01T00:00:00+00:00"}
        if path.endswith("/dismiss"):
            return {"dismissed": "domain:mystery-ai"}
        return {"settings": {}}

    monkeypatch.setattr(main.managed, "receiver_request", fake)
    return calls


def test_the_queue_is_forwarded_with_the_operators_session(receiver):
    out = main.api_candidates(_=None, token="aigt_sess")
    assert out["candidates"][0]["key"] == "domain:mystery-ai"
    assert out["candidates"][0]["resolved"] is False
    assert receiver == [{"method": "GET", "path": "/admin/candidates",
                         "token": "aigt_sess", "body": None}]


def test_a_dismissal_names_the_key_in_the_path_url_encoded(receiver):
    main.api_candidate_dismiss(
        main.CandidateDismiss(key="domain:mystery-ai"), _=None, token="t")
    assert receiver[0]["method"] == "POST"
    assert receiver[0]["path"] == "/admin/candidates/domain%3Amystery-ai/dismiss"


def test_the_dismiss_body_refuses_extras():
    with pytest.raises(ValueError):
        main.CandidateDismiss(key="k", resolved=True)


def test_the_discovery_cronjob_artifact_downloads_configured(receiver):
    resp = main.artifact("discovery-cronjob", _=None, token="t")
    assert ('filename="ai-guard-discovery-cronjob.yaml"'
            in resp.headers["content-disposition"])
    body = resp.body.decode()
    assert "enrollmentToken: aige_MINTED" in body
    assert 'value: "https://rx.example.com"' in body
    assert "S1_BASE_URL" in body and "ANTHROPIC_API_KEY" in body
    # The credentials are named as comments for the operator to supply,
    # never baked: the portal has nothing to bake them from.
    for line in body.splitlines():
        if "S1_API_TOKEN" in line or "ANTHROPIC_API_KEY" in line:
            assert line.lstrip().startswith("#")
    assert receiver[1]["body"]["note"] == "portal artifact: discovery-cronjob"


def test_the_generator_refuses_unembeddable_values():
    with pytest.raises(managed.ArtifactError):
        managed.generate_discovery_cronjob("https://x", "tok\nen", "1.0")
    with pytest.raises(managed.ArtifactError):
        managed.generate_discovery_cronjob("https://x'", "token", "1.0")
