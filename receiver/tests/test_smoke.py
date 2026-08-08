"""Smoke tests for the ai-guard receiver."""

import os

# AUTH_TOKEN must be set before the app module is imported, because
# main.py reads it at module level.
os.environ.setdefault("AUTH_TOKEN", "test-token-for-ci")

from fastapi.testclient import TestClient

from app.main import app  # noqa: E402


client = TestClient(app)

AUTH = {"Authorization": "Bearer test-token-for-ci"}


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
        headers=AUTH,
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


# ---------------------------------------------- auth before the body is read --


def test_report_without_auth_is_rejected_before_the_body_is_validated():
    """A missing token must beat a broken body.

    The payload here is invalid: tool is required and absent. A 422 would mean
    the model was validated before the token was checked, which is the whole
    problem. The answer has to be 401.
    """
    resp = client.post("/report", json={"not_a_field": "x"})
    assert resp.status_code == 401


def test_oversized_body_is_rejected():
    big = {"tool": "claude-code", "evidence": "x" * 200_000}
    resp = client.post("/report", json=big, headers=AUTH)
    assert resp.status_code == 413


def test_oversized_body_without_auth_is_still_a_401():
    """Token first, size second, so an unauthenticated caller learns nothing
    about the size limit."""
    big = {"tool": "claude-code", "evidence": "x" * 200_000}
    resp = client.post("/report", json=big)
    assert resp.status_code == 401


def test_post_without_content_length_is_rejected():
    """A chunked body would slip past the size check, so it is refused."""
    resp = client.post(
        "/report",
        content=iter([b'{"tool":"claude-code"}']),
        headers={**AUTH, "Content-Type": "application/json"},
    )
    assert resp.status_code == 411


def test_over_long_field_is_rejected():
    resp = client.post("/report", json={"tool": "x" * 500}, headers=AUTH)
    assert resp.status_code == 422


def test_occurrence_count_must_be_positive():
    resp = client.post(
        "/report", json={"tool": "claude-code", "occurrence_count": 0}, headers=AUTH
    )
    assert resp.status_code == 422


def test_metrics_stays_open():
    """Unauthenticated on purpose: it carries only bounded label values."""
    assert client.get("/metrics").status_code == 200

def test_domain_tool_name_is_normalised_to_the_registry_id():
    """The extension reports the hostname it saw; everything else reports the
    registry id. Without this, one tool is two rows on every dashboard."""
    from app.main import _build_domain_map

    reg = {"tools": [{"id": "chatgpt", "domains": ["chatgpt.com", "openai.com"]}]}
    m = _build_domain_map(reg)
    assert m["chatgpt.com"] == "chatgpt"
    assert m["openai.com"] == "chatgpt"


def test_unknown_tool_names_are_left_alone():
    """A name the registry has never heard of is a registry gap worth seeing,
    not something to quietly fold into a neighbour."""
    from app.main import _build_domain_map

    m = _build_domain_map({"tools": [{"id": "chatgpt", "domains": ["chatgpt.com"]}]})
    assert "something-else.example" not in m


def test_domain_map_survives_a_missing_registry():
    """No registry means no normalisation, not a crash on every report."""
    from app.main import _build_domain_map

    assert _build_domain_map(None) == {}
    assert _build_domain_map({}) == {}