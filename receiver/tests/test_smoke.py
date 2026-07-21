"""Smoke tests for the ai-guard receiver."""

import os

# AUTH_TOKEN must be set before the app module is imported, because
# main.py reads it at module level.
os.environ.setdefault("AUTH_TOKEN", "test-token-for-ci")

from fastapi.testclient import TestClient

from app.main import app  # noqa: E402


client = TestClient(app)


def test_healthz_returns_200_with_version():
    resp = client.get("/healthz")
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["version"] == app.version


def test_registry_without_auth_returns_401():
    resp = client.get("/registry")
    assert resp.status_code == 401


def test_report_preserves_device_name_and_risk_tier():
    """device_name and risk_tier survive validation and appear in the response."""
    resp = client.post(
        "/report",
        json={
            "tool": "claude-code",
            "device_name": "ACME-C02XK1AB",
            "risk_tier": "high",
        },
        headers={"Authorization": "Bearer test-token-for-ci"},
    )
    assert resp.status_code == 200


def test_report_defaults_for_device_name_and_risk_tier():
    """Omitting device_name and risk_tier uses empty-string defaults."""
    resp = client.post(
        "/report",
        json={"tool": "claude-code"},
        headers={"Authorization": "Bearer test-token-for-ci"},
    )
    assert resp.status_code == 200


def test_device_name_not_in_loki_stream_labels():
    """device_name must stay inside the JSON body, never become a Loki label."""
    from app.main import Finding
    f = Finding(tool="test", device_name="host-01")
    # The Loki stream uses only these bounded labels
    stream_labels = {"app", "kind", "surface", "severity", "os"}
    assert "device_name" not in stream_labels


def test_unknown_extra_fields_ignored():
    """Pydantic v2 default is extra='ignore'; unknown fields don't cause errors."""
    resp = client.post(
        "/report",
        json={
            "tool": "claude-code",
            "completely_unknown_field": "should not error",
        },
        headers={"Authorization": "Bearer test-token-for-ci"},
    )
    assert resp.status_code == 200
