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


def test_report_accepts_device_name_and_risk_tier():
    """Integration: the /report endpoint accepts a payload with the new fields."""
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


def test_model_preserves_device_name_and_risk_tier():
    """device_name and risk_tier survive Pydantic validation into model_dump."""
    from app.main import Finding
    f = Finding(tool="claude-code", device_name="ACME-C02XK1AB", risk_tier="high")
    d = f.model_dump()
    assert d["device_name"] == "ACME-C02XK1AB"
    assert d["risk_tier"] == "high"


def test_model_defaults_for_device_name_and_risk_tier():
    """Omitting device_name and risk_tier gives empty-string defaults."""
    from app.main import Finding
    f = Finding(tool="claude-code")
    d = f.model_dump()
    assert d["device_name"] == ""
    assert d["risk_tier"] == ""


def test_unbounded_fields_not_in_loki_stream_labels():
    """Unbounded fields must not be Loki stream labels."""
    from app.main import LOKI_FINDING_LABELS
    for field in ("device_name", "risk_tier", "tool", "device", "user", "account_domain"):
        assert field not in LOKI_FINDING_LABELS, f"{field} would cause label cardinality issues"


def test_unknown_extra_fields_dropped():
    """Pydantic v2 default is extra='ignore'; unknown fields are silently dropped."""
    from app.main import Finding
    f = Finding(tool="claude-code", completely_unknown_field="should vanish")
    assert "completely_unknown_field" not in f.model_dump()
