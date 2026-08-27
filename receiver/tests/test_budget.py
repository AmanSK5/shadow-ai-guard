"""The budget store and its routes: subscriptions, members, connections,
and the vendor sync.

Same harness shape as test_settings. The properties held here are the
ones that matter: the vendor key never comes back out of any route, a
viewer can read and cannot write, a CSV import cannot wear the "api"
provenance, and a sync failure is a rendered answer rather than a 5xx.
"""

import json
import os

os.environ.setdefault("AUTH_TOKEN", "test-token-for-ci")

import httpx
import pytest
from fastapi.testclient import TestClient

from app import budget as budget_mod
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


@pytest.fixture
def viewer(managed):
    """A live viewer session riding a real account."""
    managed.create_admin("admin", "a-long-password")
    managed.create_user("watcher", "another-long-pass", "viewer", by="admin")
    out = managed.login("watcher", "another-long-pass")
    return {"Authorization": "Bearer " + out["token"]}


SUB = {"tool_id": "claude", "vendor": "Anthropic", "plan": "Team",
       "currency": "GBP", "renewal_date": "2027-01-01", "owner": "IT",
       "seat_tiers": [
           {"name": "standard", "seats": 10, "unit_price_monthly": 25},
           {"name": "premium", "seats": 5, "unit_price_monthly": 100},
       ]}


# ------------------------------------------------------------ mode gating --


def test_budget_routes_do_not_exist_in_classic_mode():
    assert client.get("/admin/budget", headers=ADMIN).status_code == 404
    assert client.put("/admin/budget/subscription", headers=ADMIN,
                      json=SUB).status_code == 404


def test_budget_requires_a_credential(managed):
    assert client.get("/admin/budget").status_code == 401


# --------------------------------------------------------- subscriptions --


def test_subscription_round_trip(managed):
    r = client.put("/admin/budget/subscription", headers=ADMIN, json=SUB)
    assert r.status_code == 200
    subs = r.json()["subscriptions"]
    assert len(subs) == 1
    assert subs[0]["tool_id"] == "claude"
    assert subs[0]["seat_tiers"][1] == {
        "name": "premium", "seats": 5, "unit_price_monthly": 100}
    assert subs[0]["members"] == []
    # The provider catalogue rides along for the wizard.
    assert "anthropic" in r.json()["providers"]


def test_subscription_validation(managed):
    bad = dict(SUB, renewal_date="soon")
    assert client.put("/admin/budget/subscription", headers=ADMIN,
                      json=bad).status_code == 422
    bad = dict(SUB, seat_tiers=[{"name": "a", "seats": 1},
                                {"name": "A", "seats": 2}])
    r = client.put("/admin/budget/subscription", headers=ADMIN, json=bad)
    assert r.status_code == 422
    assert "unique" in r.json()["detail"]
    bad = dict(SUB, tool_id="../etc")
    assert client.put("/admin/budget/subscription", headers=ADMIN,
                      json=bad).status_code == 422


def test_delete_takes_the_members_and_connection_with_it(managed):
    client.put("/admin/budget/subscription", headers=ADMIN, json=SUB)
    client.put("/admin/budget/members", headers=ADMIN, json={
        "tool_id": "claude", "source": "csv",
        "members": [{"email": "a@corp.example"}]})
    client.put("/admin/budget/connection", headers=ADMIN, json={
        "tool_id": "claude", "provider": "anthropic",
        "api_key": "sk-ant-api01-test"})
    r = client.post("/admin/budget/subscription/delete", headers=ADMIN,
                    json={"tool_id": "claude"})
    assert r.status_code == 200
    out = client.get("/admin/budget", headers=ADMIN).json()
    assert out["subscriptions"] == [] and out["connections"] == []
    assert managed.sync_connection_key("claude") is None


# --------------------------------------------------------------- members --


def test_members_replace_by_source_not_wholesale(managed):
    client.put("/admin/budget/subscription", headers=ADMIN, json=SUB)
    client.put("/admin/budget/members", headers=ADMIN, json={
        "tool_id": "claude", "source": "manual",
        "members": [{"email": "kept@corp.example", "name": "Kept"}]})
    client.put("/admin/budget/members", headers=ADMIN, json={
        "tool_id": "claude", "source": "csv",
        "members": [{"email": "old@corp.example"}]})
    # A re-import replaces the previous import and leaves manual rows.
    client.put("/admin/budget/members", headers=ADMIN, json={
        "tool_id": "claude", "source": "csv",
        "members": [{"email": "new@corp.example", "seat_tier": "premium"}]})
    ms = client.get("/admin/budget", headers=ADMIN).json()[
        "subscriptions"][0]["members"]
    emails = {m["email"]: m for m in ms}
    assert set(emails) == {"kept@corp.example", "new@corp.example"}
    assert emails["new@corp.example"]["seat_tier"] == "premium"
    assert emails["new@corp.example"]["source"] == "csv"


def test_members_validation(managed):
    r = client.put("/admin/budget/members", headers=ADMIN, json={
        "tool_id": "claude", "source": "csv",
        "members": [{"email": "not-an-email"}]})
    assert r.status_code == 422
    r = client.put("/admin/budget/members", headers=ADMIN, json={
        "tool_id": "claude", "source": "csv",
        "members": [{"email": "a@b.example"}, {"email": "A@B.example"}]})
    assert r.status_code == 422 and "duplicate" in r.json()["detail"]
    # "api" provenance belongs to sync alone: a CSV must not wear it.
    r = client.put("/admin/budget/members", headers=ADMIN, json={
        "tool_id": "claude", "source": "api",
        "members": [{"email": "a@b.example"}]})
    assert r.status_code == 422


# ------------------------------------------------------------ connections --


def test_the_key_never_comes_back_out(managed):
    client.put("/admin/budget/connection", headers=ADMIN, json={
        "tool_id": "claude", "provider": "anthropic",
        "api_key": "sk-ant-api01-SECRETSECRET"})
    body = json.dumps(client.get("/admin/budget", headers=ADMIN).json())
    assert "SECRETSECRET" not in body
    conn = client.get("/admin/budget", headers=ADMIN).json()["connections"][0]
    assert conn["key_set"] is True and conn["provider"] == "anthropic"
    # The audit trail keeps the rule too.
    events = json.dumps(client.get("/admin/events", headers=ADMIN).json())
    assert "SECRETSECRET" not in events


def test_connection_validation(managed):
    r = client.put("/admin/budget/connection", headers=ADMIN, json={
        "tool_id": "claude", "provider": "chatgpt-business",
        "api_key": "whatever-key"})
    assert r.status_code == 422
    r = client.put("/admin/budget/connection", headers=ADMIN, json={
        "tool_id": "claude", "provider": "anthropic",
        "api_key": "has a space"})
    assert r.status_code == 422


# -------------------------------------------------------------- role gate --


def test_viewer_reads_and_cannot_write(managed, viewer):
    client.put("/admin/budget/subscription", headers=ADMIN, json=SUB)
    assert client.get("/admin/budget", headers=viewer).status_code == 200
    assert client.put("/admin/budget/subscription", headers=viewer,
                      json=SUB).status_code == 403
    assert client.put("/admin/budget/members", headers=viewer, json={
        "tool_id": "claude", "source": "csv", "members": []}).status_code == 403
    assert client.put("/admin/budget/connection", headers=viewer, json={
        "tool_id": "claude", "provider": "anthropic",
        "api_key": "sk-ant-api01-x"}).status_code == 403
    assert client.post("/admin/budget/sync", headers=viewer,
                       json={"tool_id": "claude"}).status_code == 403


# ------------------------------------------------------------------ sync --


_REAL_ASYNC_CLIENT = httpx.AsyncClient


def _mock_async_client(handler):
    """A factory standing in for httpx.AsyncClient that answers from the
    handler instead of the network. Binds the real class first: the patch
    replaces httpx.AsyncClient itself, and a factory that resolved it at
    call time would call itself forever."""
    def factory(**kwargs):
        kwargs.pop("transport", None)
        return _REAL_ASYNC_CLIENT(
            transport=httpx.MockTransport(handler), **kwargs)
    return factory


def test_sync_anthropic_pages_and_stores(managed, monkeypatch):
    pages = {
        "": {"data": [{"email": "One@Corp.example", "name": "One",
                       "role": "user"}],
             "has_more": True, "last_id": "u1"},
        "u1": {"data": [{"email": "two@corp.example", "name": "Two",
                         "role": "claude_code_user"}],
               "has_more": False, "last_id": "u2"},
    }

    def handler(request):
        assert request.url.host == "api.anthropic.com"
        assert request.headers["x-api-key"] == "sk-ant-api01-k"
        after = request.url.params.get("after_id", "")
        return httpx.Response(200, json=pages[after])

    monkeypatch.setattr(budget_mod.httpx, "AsyncClient",
                        _mock_async_client(handler))
    client.put("/admin/budget/connection", headers=ADMIN, json={
        "tool_id": "claude", "provider": "anthropic",
        "api_key": "sk-ant-api01-k"})
    r = client.post("/admin/budget/sync", headers=ADMIN,
                    json={"tool_id": "claude"})
    assert r.json() == {"ok": True, "count": 2}

    client.put("/admin/budget/subscription", headers=ADMIN, json=SUB)
    out = client.get("/admin/budget", headers=ADMIN).json()
    ms = out["subscriptions"][0]["members"]
    assert [m["email"] for m in ms] == ["one@corp.example",
                                       "two@corp.example"]
    assert all(m["source"] == "api" for m in ms)
    conn = out["connections"][0]
    assert conn["last_sync_ok"] is True and conn["members_synced"] == 2


def test_sync_fireflies_maps_usage(managed, monkeypatch):
    def handler(request):
        assert request.url.host == "api.fireflies.ai"
        assert request.headers["Authorization"] == "Bearer ff-key-123"
        return httpx.Response(200, json={"data": {"users": [
            {"name": "Ash", "email": "ash@corp.example", "is_admin": True,
             "num_transcripts": 12, "minutes_consumed": 340.7},
        ]}})

    monkeypatch.setattr(budget_mod.httpx, "AsyncClient",
                        _mock_async_client(handler))
    client.put("/admin/budget/connection", headers=ADMIN, json={
        "tool_id": "fireflies", "provider": "fireflies",
        "api_key": "ff-key-123"})
    r = client.post("/admin/budget/sync", headers=ADMIN,
                    json={"tool_id": "fireflies"})
    assert r.json() == {"ok": True, "count": 1}
    client.put("/admin/budget/subscription", headers=ADMIN,
               json=dict(SUB, tool_id="fireflies"))
    m = client.get("/admin/budget", headers=ADMIN).json()[
        "subscriptions"][0]["members"][0]
    assert m["role"] == "admin"
    assert m["usage"] == {"transcripts": 12, "minutes": 341}


def test_sync_refusal_is_an_answer_not_a_500(managed, monkeypatch):
    def handler(request):
        return httpx.Response(401, json={"error": "invalid key"})

    monkeypatch.setattr(budget_mod.httpx, "AsyncClient",
                        _mock_async_client(handler))
    client.put("/admin/budget/connection", headers=ADMIN, json={
        "tool_id": "claude", "provider": "anthropic",
        "api_key": "sk-ant-api01-bad"})
    r = client.post("/admin/budget/sync", headers=ADMIN,
                    json={"tool_id": "claude"})
    assert r.status_code == 200
    assert r.json()["ok"] is False and "401" in r.json()["detail"]
    conn = client.get("/admin/budget", headers=ADMIN).json()["connections"][0]
    assert conn["last_sync_ok"] is False and "401" in conn["last_sync_detail"]


def test_sync_fireflies_graphql_error_is_surfaced(managed, monkeypatch):
    def handler(request):
        return httpx.Response(200, json={
            "errors": [{"message": "Invalid API key"}]})

    monkeypatch.setattr(budget_mod.httpx, "AsyncClient",
                        _mock_async_client(handler))
    client.put("/admin/budget/connection", headers=ADMIN, json={
        "tool_id": "fireflies", "provider": "fireflies",
        "api_key": "ff-key-bad"})
    r = client.post("/admin/budget/sync", headers=ADMIN,
                    json={"tool_id": "fireflies"})
    assert r.json()["ok"] is False
    assert "Invalid API key" in r.json()["detail"]


def test_sync_without_a_connection_is_a_404(managed):
    r = client.post("/admin/budget/sync", headers=ADMIN,
                    json={"tool_id": "claude"})
    assert r.status_code == 404


def test_fx_rates_relay_and_cache(managed, monkeypatch):
    calls = []

    def handler(request):
        calls.append(str(request.url))
        assert request.url.host == "api.frankfurter.dev"
        return httpx.Response(200, json={
            "amount": 1.0, "base": "GBP", "date": "2026-08-27",
            "rates": {"USD": 1.27, "EUR": 1.17, "bad": "x"}})

    monkeypatch.setattr(budget_mod.httpx, "AsyncClient",
                        _mock_async_client(handler))
    monkeypatch.setattr(budget_mod, "_fx_cache", {})
    out = client.get("/admin/budget/fx?to=gbp", headers=ADMIN).json()
    assert out["ok"] is True and out["base"] == "GBP"
    assert out["rates"]["USD"] == 1.27 and "bad" not in out["rates"]
    # Second read answers from the cache, not the network.
    client.get("/admin/budget/fx?to=gbp", headers=ADMIN)
    assert len(calls) == 1


def test_fx_refusals_are_answers(managed, monkeypatch):
    monkeypatch.setattr(budget_mod, "_fx_cache", {})

    def handler(request):
        return httpx.Response(404, json={"message": "not found"})

    monkeypatch.setattr(budget_mod.httpx, "AsyncClient",
                        _mock_async_client(handler))
    out = client.get("/admin/budget/fx?to=XXX", headers=ADMIN).json()
    assert out["ok"] is False and "no reference rate" in out["detail"]
    assert client.get("/admin/budget/fx?to=pounds",
                      headers=ADMIN).status_code == 422


def test_replaced_key_resets_sync_history(managed, monkeypatch):
    def handler(request):
        return httpx.Response(200, json={"data": [], "has_more": False})

    monkeypatch.setattr(budget_mod.httpx, "AsyncClient",
                        _mock_async_client(handler))
    client.put("/admin/budget/connection", headers=ADMIN, json={
        "tool_id": "claude", "provider": "anthropic",
        "api_key": "sk-ant-api01-one"})
    client.post("/admin/budget/sync", headers=ADMIN,
                json={"tool_id": "claude"})
    client.put("/admin/budget/connection", headers=ADMIN, json={
        "tool_id": "claude", "provider": "anthropic",
        "api_key": "sk-ant-api01-two"})
    conn = client.get("/admin/budget", headers=ADMIN).json()["connections"][0]
    assert conn["last_sync_at"] is None and conn["members_synced"] == 0
