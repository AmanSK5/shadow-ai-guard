"""Runtime configuration: the log store, alerting and the secret setting.

The property under test is DB-wins-when-set applied to where findings GO:
a store saved in the portal takes effect on the next finding with no
restart, the push endpoint is derived from the base so the base-vs-push
mixup cannot be made there, and the one secret is stored recoverable but
never echoed. Same harness shape as the rest of the suite.
"""

import os

os.environ.setdefault("AUTH_TOKEN", "test-token-for-ci")

import pytest
from fastapi.testclient import TestClient

from app import state as state_mod
from app.main import app

client = TestClient(app)

ADMIN = {"Authorization": "Bearer admin-test-token"}


@pytest.fixture
def managed(tmp_path, monkeypatch):
    from app import main

    st = state_mod.State(str(tmp_path / "state.db"))
    monkeypatch.setattr(main, "STATE", st)
    monkeypatch.setattr(main, "_EXPECTED_ADMIN", b"Bearer admin-test-token")
    return st


def _put(**kw):
    return client.put("/admin/settings", headers=ADMIN, json=kw)


# ---------------------------------------------------------- push resolution --


def test_a_saved_base_url_derives_the_push_endpoint(managed):
    """Deriving is the point: the portal asks for one base URL and the
    base-vs-push mixup stops being possible to make there."""
    from app import main

    _put(log_store_url="http://loki.monitoring.svc:3100")
    url, user, pw = main._effective_log_push()
    assert url == "http://loki.monitoring.svc:3100/loki/api/v1/push"
    assert (user, pw) == ("", "")


def test_an_explicit_push_override_wins_over_derivation(managed):
    _put(log_store_url="http://loki:3100",
         log_store_push_url="http://gateway:8080/custom/push")
    from app import main

    url, _, _ = main._effective_log_push()
    assert url == "http://gateway:8080/custom/push"


def test_the_url_source_supplies_the_credentials(managed, monkeypatch):
    """A portal-saved URL with env credentials would send the OLD store's
    password to the NEW store; whichever source supplies the URL supplies
    the auth pair, empty included."""
    from app import main

    monkeypatch.setattr(main, "LOKI_PUSH_URL", "http://old:3100/loki/api/v1/push")
    monkeypatch.setattr(main, "LOKI_USERNAME", "old-user")
    monkeypatch.setattr(main, "LOKI_PASSWORD", "old-pass")

    # No DB store: env URL with env creds, exactly as ever.
    assert main._effective_log_push() == (
        "http://old:3100/loki/api/v1/push", "old-user", "old-pass")

    # DB store without creds: no creds, not the env ones.
    _put(log_store_url="http://new:3100")
    assert main._effective_log_push() == (
        "http://new:3100/loki/api/v1/push", "", "")

    # DB store with its own pair.
    _put(log_store_username="123456", log_store_password="glc_token")
    assert main._effective_log_push() == (
        "http://new:3100/loki/api/v1/push", "123456", "glc_token")


def test_classic_mode_resolution_is_the_env(monkeypatch):
    from app import main

    monkeypatch.setattr(main, "LOKI_PUSH_URL", "http://env:3100/loki/api/v1/push")
    assert main._effective_log_push()[0] == "http://env:3100/loki/api/v1/push"


def test_alertmanager_follows_the_same_rule(managed, monkeypatch):
    from app import main

    monkeypatch.setattr(main, "ALERTMANAGER_URL", "http://env-am:9093")
    assert main._effective_alertmanager() == "http://env-am:9093"
    _put(alertmanager_url="http://portal-am:9093")
    assert main._effective_alertmanager() == "http://portal-am:9093"
    _put(alertmanager_url=None)
    assert main._effective_alertmanager() == "http://env-am:9093"


# ------------------------------------------------------------- the secret --


def test_the_password_is_never_echoed_by_the_settings_view(managed):
    _put(log_store_password="glc_hunter2")
    out = client.get("/admin/settings", headers=ADMIN).json()["settings"]
    assert out["log_store_password"] == {"set": True, "source": "db"}
    # Nowhere in the whole response, under any key.
    assert "glc_hunter2" not in client.get(
        "/admin/settings", headers=ADMIN).text


def test_the_secrets_route_is_the_one_place_the_plaintext_exists(managed):
    _put(log_store_url="http://loki:3100", log_store_username="u",
         log_store_password="glc_hunter2")
    out = client.get("/admin/settings/secrets", headers=ADMIN).json()
    assert out == {"log_store_url": "http://loki:3100",
                   "log_store_push_url": "",
                   "log_store_username": "u",
                   "log_store_password": "glc_hunter2"}
    assert client.get("/admin/settings/secrets").status_code == 401


def test_the_secret_value_never_reaches_the_event_log(managed):
    _put(log_store_password="glc_hunter2")
    rows = [r["detail"] for r in managed._db.execute("SELECT detail FROM events")]
    assert all("glc_hunter2" not in d for d in rows)


def test_url_settings_must_be_urls(managed):
    assert _put(log_store_url="loki:3100").status_code == 422
    assert _put(grafana_url="not a url").status_code == 422
    assert _put(alertmanager_url="ftp://am:9093").status_code == 422


# ------------------------------------------------------------- push test --


def test_the_push_test_names_the_write_only_token_trap(managed, monkeypatch):
    """The failure this button exists for: a 403 store where every finding
    is accepted with a 200 and never stored."""
    import httpx

    _put(log_store_url="http://loki:3100")

    class FakeResp:
        status_code = 403

    async def fake_post(self, url, **kw):
        return FakeResp()

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
    out = client.post("/admin/test/log-store-push", headers=ADMIN).json()
    assert out["ok"] is False
    assert "403" in out["detail"]
    assert "write access" in out["hint"]


def test_the_push_test_succeeds_and_redacts(managed, monkeypatch):
    import httpx

    _put(log_store_url="http://user:secretpw@loki:3100")

    class FakeResp:
        status_code = 204

    async def fake_post(self, url, **kw):
        return FakeResp()

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
    out = client.post("/admin/test/log-store-push", headers=ADMIN).json()
    assert out["ok"] is True
    assert "secretpw" not in out["url"]


def test_the_push_test_with_nothing_configured_is_a_400(managed):
    resp = client.post("/admin/test/log-store-push", headers=ADMIN)
    assert resp.status_code == 400
    assert "no log store" in resp.json()["detail"]
