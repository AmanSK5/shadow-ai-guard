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
