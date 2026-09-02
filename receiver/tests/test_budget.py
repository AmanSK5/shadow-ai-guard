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
        "name": "premium", "seats": 5, "unit_price_monthly": 100,
        "covers": []}
    # A subscription always covers at least its own tool.
    assert subs[0]["covers"] == ["claude"]
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


def test_an_empty_field_never_erases_a_stored_one(managed, monkeypatch):
    """The APIs report no seat tiers, so a sync after an operator
    assigned tiers by import must keep them; symmetrically a tier-only
    CSV over a synced list keeps the synced names and roles."""
    def handler(request):
        return httpx.Response(200, json={"data": {"users": [
            {"name": "Ash", "email": "ash@corp.example", "is_admin": True,
             "num_transcripts": 5, "minutes_consumed": 60}]}})

    monkeypatch.setattr(budget_mod.httpx, "AsyncClient",
                        _mock_async_client(handler))
    client.put("/admin/budget/subscription", headers=ADMIN,
               json=dict(SUB, tool_id="fireflies"))
    client.put("/admin/budget/connection", headers=ADMIN, json={
        "tool_id": "fireflies", "provider": "fireflies",
        "api_key": "ff-key-123"})
    client.post("/admin/budget/sync", headers=ADMIN,
                json={"tool_id": "fireflies"})
    # Tier assigned by a tier-only import over the synced row...
    client.put("/admin/budget/members", headers=ADMIN, json={
        "tool_id": "fireflies", "source": "csv",
        "members": [{"email": "ash@corp.example", "seat_tier": "premium"}]})
    m = client.get("/admin/budget", headers=ADMIN).json()[
        "subscriptions"][0]["members"][0]
    # ...keeps the synced name, role and usage.
    assert m["seat_tier"] == "premium" and m["name"] == "Ash"
    assert m["role"] == "admin" and m["usage"]["transcripts"] == 5
    # ...and survives the next sync, which reports no tiers.
    client.post("/admin/budget/sync", headers=ADMIN,
                json={"tool_id": "fireflies"})
    m = client.get("/admin/budget", headers=ADMIN).json()[
        "subscriptions"][0]["members"][0]
    assert m["seat_tier"] == "premium" and m["source"] == "api"


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


# ---------------------------------------------------------------- covers --


def test_one_licence_cannot_be_two_subscriptions(managed):
    r = client.put("/admin/budget/subscription", headers=ADMIN,
                   json=dict(SUB, covers=["claude-code"]))
    assert r.status_code == 200
    assert r.json()["subscriptions"][0]["covers"] == ["claude",
                                                      "claude-code"]
    # Linking claude-code on its own now names the clash...
    r = client.put("/admin/budget/subscription", headers=ADMIN,
                   json=dict(SUB, tool_id="claude-code", covers=[]))
    assert r.status_code == 422
    assert "claude-code is already covered" in r.json()["detail"]
    # ...and so does covering it from a third subscription.
    r = client.put("/admin/budget/subscription", headers=ADMIN,
                   json=dict(SUB, tool_id="chatgpt", covers=["claude-code"]))
    assert r.status_code == 422


def test_tier_covers_must_be_a_subset(managed):
    bad = dict(SUB, covers=["claude-code"], seat_tiers=[
        {"name": "premium", "seats": 5, "unit_price_monthly": 100,
         "covers": ["claude", "codex-cli"]}])
    r = client.put("/admin/budget/subscription", headers=ADMIN, json=bad)
    assert r.status_code == 422 and "codex-cli" in r.json()["detail"]
    good = dict(SUB, covers=["claude-code"], seat_tiers=[
        {"name": "standard", "seats": 6, "unit_price_monthly": 19,
         "covers": ["claude"]},
        {"name": "premium", "seats": 7, "unit_price_monthly": 94,
         "covers": ["claude", "claude-code"]}])
    r = client.put("/admin/budget/subscription", headers=ADMIN, json=good)
    assert r.status_code == 200
    tiers = r.json()["subscriptions"][0]["seat_tiers"]
    assert tiers[0]["covers"] == ["claude"]
    assert tiers[1]["covers"] == ["claude", "claude-code"]


def test_covers_survives_a_database_from_before_it(tmp_path, monkeypatch):
    """A 0.12.x database gains the column on open and its rows read as
    covering their own tool."""
    from app import main

    db = str(tmp_path / "state.db")
    st = state_mod.State(db)
    with st._lock:
        st._db.execute("ALTER TABLE budget_subscriptions DROP COLUMN covers")
        st._db.execute(
            "INSERT INTO budget_subscriptions (tool_id, created_at,"
            " updated_at) VALUES ('claude', 'x', 'x')")
        st._db.commit()
    st2 = state_mod.State(db)
    sub = st2.list_budget()["subscriptions"][0]
    assert sub["covers"] == []


def test_every_provider_says_what_plan_it_needs():
    """The wizard now lists the connectors with their plan requirement, so a
    provider with no `plan` renders "not recorded" - which is honest but
    useless. Both entries carry one, and they carry different KINDS of claim:
    Anthropic documents that Team has no admin keys, so that is stated as
    fact; Fireflies does not document its tiers, so that one says what was
    tested rather than inventing a minimum an operator would plan around."""
    from app import budget

    for name, p in budget.PROVIDERS.items():
        assert p.get("plan"), name
        assert p.get("syncs"), name
        assert p.get("label"), name
    assert "Team plans have no admin API" in budget.PROVIDERS["anthropic"]["plan"]
    # Fireflies was first written as "verified on Enterprise, lower plans
    # untested", which was not research - it was the one plan we happened to
    # have used. Their knowledge base says API access exists at every plan
    # level, and the Business gate applies to the analytics query this
    # connector does not call.
    ff = budget.PROVIDERS["fireflies"]["plan"]
    assert "Any plan" in ff
    assert "untested" not in ff


def test_every_shipped_tool_says_what_its_vendor_offers():
    """"Not supported" is two different situations - the vendor offers
    nothing, or the vendor offers something and this receiver has not built
    it - and only the second is worth an operator raising an issue about. The
    map covers every tool the registry ships, so the wizard can say which.

    It is checked against the registry rather than a hand-count, because the
    two drifting apart is exactly how a tool ends up with no answer."""
    import pathlib

    import yaml

    from app import budget

    root = pathlib.Path(__file__).resolve().parents[2]
    reg = yaml.safe_load((root / "registry" / "registry.yaml").read_text())
    ids = {t["id"] for t in reg["tools"]}
    assert set(budget.MEMBER_APIS) == ids

    for tool, m in budget.MEMBER_APIS.items():
        assert m["api"] in ("rest", "scim", "none", "unknown"), tool
        assert m.get("how"), tool
        # A vendor that offers something must say on what plan; one that
        # offers nothing has no plan to state.
        if m["api"] in ("rest", "scim") and tool != "codex-cli":
            assert m.get("plan"), tool
        if m["api"] == "none":
            assert not m.get("plan"), tool

    # Every connector this receiver implements is claimed by at least one tool.
    claimed = {m["connector"] for m in budget.MEMBER_APIS.values()
               if m.get("connector")}
    assert claimed == set(budget.PROVIDERS)


def test_sync_cursor_uses_basic_auth_and_drops_removed(managed, monkeypatch):
    """Cursor authenticates with HTTP Basic - the key as the USERNAME with no
    password, which is what `curl -u YOUR_API_KEY:` means - rather than a
    bearer token, the one thing easy to get wrong from a docs page. Removed
    members keep appearing with isRemoved set; counting them would overstate
    what the licence pays for."""
    import base64

    def handler(request):
        assert request.url.host == "api.cursor.com"
        want = base64.b64encode(b"cur-key-123:").decode()
        assert request.headers["Authorization"] == "Basic " + want
        return httpx.Response(200, json=[
            {"email": "Ash@Corp.example", "name": "Ash", "role": "owner"},
            {"email": "bo@corp.example", "name": "Bo", "role": "member"},
            {"email": "gone@corp.example", "name": "Gone", "isRemoved": True},
            {"name": "no email at all"},
        ])

    monkeypatch.setattr(budget_mod.httpx, "AsyncClient",
                        _mock_async_client(handler))
    put = client.put("/admin/budget/connection", headers=ADMIN, json={
        "tool_id": "cursor", "provider": "cursor", "api_key": "cur-key-123"})
    assert put.status_code == 200, put.text
    r = client.post("/admin/budget/sync", headers=ADMIN,
                    json={"tool_id": "cursor"})
    assert r.json() == {"ok": True, "count": 2}


def test_sync_openai_pages_with_a_cursor(managed, monkeypatch):
    """Cursor-paginated on `after`, and the admin key goes in as a bearer.
    An ordinary project key is refused by the vendor, which is why the hint
    says admin key rather than API key."""
    pages = {
        "": {"data": [{"id": "user_1", "email": "One@Corp.example",
                       "name": "One", "role": "owner"}],
             "has_more": True, "last_id": "user_1"},
        "user_1": {"data": [{"id": "user_2", "email": "two@corp.example",
                             "name": "Two", "role": "reader"}],
                   "has_more": False},
    }

    def handler(request):
        assert request.url.host == "api.openai.com"
        assert request.headers["Authorization"] == "Bearer sk-admin-k"
        return httpx.Response(200, json=pages[request.url.params.get("after", "")])

    monkeypatch.setattr(budget_mod.httpx, "AsyncClient",
                        _mock_async_client(handler))
    client.put("/admin/budget/connection", headers=ADMIN, json={
        "tool_id": "openai-api-platform", "provider": "openai",
        "api_key": "sk-admin-k"})
    r = client.post("/admin/budget/sync", headers=ADMIN,
                    json={"tool_id": "openai-api-platform"})
    assert r.json() == {"ok": True, "count": 2}


def test_a_connector_written_from_docs_says_so():
    """Anthropic and Fireflies have been run against real orgs. OpenAI and
    Cursor have not - they are written from the vendors' documented endpoints
    and nothing more. That belongs in the data rather than in somebody's
    memory, because "it is in the dropdown" reads as "it works"."""
    assert budget_mod.PROVIDERS["openai"].get("unverified") is True
    assert budget_mod.PROVIDERS["cursor"].get("unverified") is True
    assert not budget_mod.PROVIDERS["anthropic"].get("unverified")
    assert not budget_mod.PROVIDERS["fireflies"].get("unverified")
    # Everything offered can be synced, and every syncer is offered.
    assert set(budget_mod.SYNCERS) == set(budget_mod.PROVIDERS)


def test_sync_chatgpt_reads_scim_users_and_pages(managed, monkeypatch):
    """SCIM was ruled out here at first as "an IdP integration, not a vendor
    API". That is wrong for ChatGPT: OpenAI issues the token from its own
    admin console and the endpoint answers a plain GET, so it is a bearer key
    like any other. What stays out is a vendor whose token is issued by
    support during onboarding - there is nothing to paste.

    Paging is SCIM's own: 1-based startIndex, totalResults says when to stop.
    A deactivated user is not holding a seat and must not be counted."""
    pages = {
        1: {"totalResults": 3, "startIndex": 1, "itemsPerPage": 2,
            "Resources": [
                {"userName": "Ash@Corp.example", "active": True,
                 "name": {"givenName": "Ash", "familyName": "One"},
                 "emails": [{"value": "Ash@Corp.example", "primary": True}]},
                {"userName": "gone@corp.example", "active": False,
                 "emails": [{"value": "gone@corp.example"}]},
            ]},
        3: {"totalResults": 3, "startIndex": 3, "itemsPerPage": 1,
            "Resources": [
                {"userName": "bo@corp.example", "active": True,
                 "name": {"formatted": "Bo Two"}},
            ]},
    }

    def handler(request):
        assert request.url.host == "api.openai.com"
        assert request.url.path == "/scim/v2/Users"
        assert request.headers["Authorization"] == "Bearer scim-tok-123"
        return httpx.Response(
            200, json=pages[int(request.url.params.get("startIndex", "1"))])

    monkeypatch.setattr(budget_mod.httpx, "AsyncClient",
                        _mock_async_client(handler))
    put = client.put("/admin/budget/connection", headers=ADMIN, json={
        "tool_id": "chatgpt", "provider": "chatgpt",
        "api_key": "scim-tok-123"})
    assert put.status_code == 200, put.text
    r = client.post("/admin/budget/sync", headers=ADMIN,
                    json={"tool_id": "chatgpt"})
    # Three resources, one deactivated.
    assert r.json() == {"ok": True, "count": 2}


def test_a_scim_answer_without_resources_is_named_not_guessed(managed,
                                                              monkeypatch):
    """Pointing this at a non-SCIM URL returns 200 and JSON that simply has no
    Resources. Treating that as "zero members" would wipe a member list; it
    has to refuse and say what it wanted."""
    def handler(request):
        return httpx.Response(200, json={"object": "list", "data": []})

    monkeypatch.setattr(budget_mod.httpx, "AsyncClient",
                        _mock_async_client(handler))
    client.put("/admin/budget/connection", headers=ADMIN, json={
        "tool_id": "chatgpt", "provider": "chatgpt", "api_key": "scim-tok-1"})
    r = client.post("/admin/budget/sync", headers=ADMIN,
                    json={"tool_id": "chatgpt"})
    body = r.json()
    assert body["ok"] is False
    assert "SCIM Resources" in body["detail"]


def test_codex_rides_the_chatgpt_workspace():
    """Codex CLI has no member list of its own, so it points at the ChatGPT
    connector rather than getting one - the "also covers" tick is what links
    the two."""
    assert budget_mod.MEMBER_APIS["codex-cli"]["connector"] == "chatgpt"
    assert budget_mod.MEMBER_APIS["chatgpt"]["connector"] == "chatgpt"
def test_sync_devin_splits_org_from_key_and_joins_roles(managed, monkeypatch):
    """Devin is the only vendor here that needs an organisation id in the
    path, and it publishes no endpoint that resolves a key to its own org -
    so the id travels with the key as "org-xxxx:cog_xxxx" and gets split
    here. Two things are easy to get wrong: sending the whole stored string
    as the bearer token, and picking one role when the API returns role
    ASSIGNMENTS, a list. Service users come back on this endpoint with no
    email and hold no paid seat, so they are not counted as people."""
    pages = {
        "": {"items": [
            {"user_id": "u1", "email": "Ash@Corp.example", "name": "Ash",
             "role_assignments": [
                 {"role": {"role_id": "r1", "role_name": "Admin"}},
                 {"role": {"role_id": "r2", "role_name": "Member"}}]},
            {"user_id": "svc", "email": None, "name": "ci-bot",
             "role_assignments": []},
        ], "has_next_page": True, "end_cursor": "c1"},
        "c1": {"items": [
            {"user_id": "u2", "email": "bo@corp.example", "name": "Bo",
             "role_assignments": [
                 {"role": {"role_id": "r2", "role_name": "Member"}}]},
        ], "has_next_page": False, "end_cursor": None},
    }

    def handler(request):
        assert request.url.host == "api.devin.ai"
        assert request.url.path == (
            "/v3beta1/organizations/org-abc123/members/users")
        # The org id must not have ridden along into the token.
        assert request.headers["Authorization"] == "Bearer cog_secret"
        return httpx.Response(
            200, json=pages[request.url.params.get("after", "")])

    monkeypatch.setattr(budget_mod.httpx, "AsyncClient",
                        _mock_async_client(handler))
    client.put("/admin/budget/connection", headers=ADMIN, json={
        "tool_id": "codeium", "provider": "devin",
        "api_key": "org-abc123:cog_secret"})
    r = client.post("/admin/budget/sync", headers=ADMIN,
                    json={"tool_id": "codeium"})
    assert r.json() == {"ok": True, "count": 2}

    # Members hang off the subscription, so read them back through one.
    client.put("/admin/budget/subscription", headers=ADMIN,
               json=dict(SUB, tool_id="codeium", vendor="Cognition"))
    sub, = [s for s in client.get("/admin/budget", headers=ADMIN)
            .json()["subscriptions"] if s["tool_id"] == "codeium"]
    members = {m["email"]: m for m in sub["members"]}
    assert set(members) == {"ash@corp.example", "bo@corp.example"}
    assert members["ash@corp.example"]["role"] == "Admin, Member"
    assert members["ash@corp.example"]["source"] == "api"


@pytest.mark.parametrize("key", ["cog_nokeyatall", "notanorg:cog_key",
                                 "org-abc/../evil:cog_key", ":cog_keyaa"])
def test_sync_devin_refuses_a_key_without_a_usable_org_id(managed, monkeypatch,
                                                          key):
    """The org id is the one path segment in this module that does not come
    from a constant, so it is checked before it reaches a URL: a malformed
    id is refused with an answer, not sent to api.devin.ai to find out."""
    def handler(request):  # pragma: no cover - must never be reached
        raise AssertionError("a malformed org id reached the network")

    monkeypatch.setattr(budget_mod.httpx, "AsyncClient",
                        _mock_async_client(handler))
    client.put("/admin/budget/connection", headers=ADMIN, json={
        "tool_id": "codeium", "provider": "devin", "api_key": key})
    r = client.post("/admin/budget/sync", headers=ADMIN,
                    json={"tool_id": "codeium"})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is False
    # The failure is the operator's answer, so it has to name the shape the
    # key should have taken rather than just refusing.
    assert "org-xxxx" in body["detail"]


# ------------------------------------------- two plans on the same tool --
#
# An organisation does not have "a Claude subscription": it has a Teams
# contract and a handful of individual Max seats, on different plans with
# different renewal dates. Keying on tool_id alone meant tracking one and
# being blind to the other, and the spend total was wrong either way without
# saying so.

def _sub(tool, plan, seats, price, **kw):
    return dict({"tool_id": tool, "plan": plan, "vendor": "Anthropic",
                 "currency": "GBP",
                 "seat_tiers": [{"name": "seat", "seats": seats,
                                 "unit_price_monthly": price}]}, **kw)


def test_one_tool_can_carry_several_plans(managed):
    for s in (_sub("claude", "Team", 40, 25),
              _sub("claude", "Max 20", 3, 90),
              _sub("claude", "Max 5", 6, 18)):
        r = client.put("/admin/budget/subscription", headers=ADMIN, json=s)
        assert r.status_code == 200, r.text
    subs = client.get("/admin/budget", headers=ADMIN).json()["subscriptions"]
    claude = [x for x in subs if x["tool_id"] == "claude"]
    assert sorted(x["plan_key"] for x in claude) == ["max-20", "max-5", "team"]
    assert sorted(x["plan"] for x in claude) == ["Max 20", "Max 5", "Team"]


def test_renaming_a_plan_updates_rather_than_duplicates(managed):
    client.put("/admin/budget/subscription", headers=ADMIN,
               json=_sub("claude", "Team", 40, 25))
    client.put("/admin/budget/subscription", headers=ADMIN,
               json=_sub("claude", "Teams", 40, 25, plan_key="team"))
    subs = client.get("/admin/budget", headers=ADMIN).json()["subscriptions"]
    claude = [x for x in subs if x["tool_id"] == "claude"]
    assert len(claude) == 1 and claude[0]["plan"] == "Teams"


def test_deleting_one_plan_leaves_the_others(managed):
    client.put("/admin/budget/subscription", headers=ADMIN,
               json=_sub("claude", "Team", 40, 25))
    client.put("/admin/budget/subscription", headers=ADMIN,
               json=_sub("claude", "Max 20", 3, 90))
    client.post("/admin/budget/subscription/delete", headers=ADMIN,
                json={"tool_id": "claude", "plan_key": "team"})
    subs = client.get("/admin/budget", headers=ADMIN).json()["subscriptions"]
    assert [x["plan_key"] for x in subs if x["tool_id"] == "claude"] == ["max-20"]


def test_members_belong_to_a_plan_not_a_tool(managed):
    client.put("/admin/budget/subscription", headers=ADMIN,
               json=_sub("claude", "Team", 40, 25))
    client.put("/admin/budget/subscription", headers=ADMIN,
               json=_sub("claude", "Max 20", 3, 90))
    client.put("/admin/budget/members", headers=ADMIN, json={
        "tool_id": "claude", "plan_key": "team", "source": "csv",
        "members": [{"email": "a@corp.example"}, {"email": "b@corp.example"}]})
    client.put("/admin/budget/members", headers=ADMIN, json={
        "tool_id": "claude", "plan_key": "max-20", "source": "csv",
        "members": [{"email": "c@corp.example"}]})
    subs = {x["plan_key"]: x for x in
            client.get("/admin/budget", headers=ADMIN).json()["subscriptions"]
            if x["tool_id"] == "claude"}
    assert [m["email"] for m in subs["team"]["members"]] == \
        ["a@corp.example", "b@corp.example"]
    assert [m["email"] for m in subs["max-20"]["members"]] == ["c@corp.example"]


def test_a_write_that_does_not_say_which_plan_is_refused_when_ambiguous(managed):
    """Guessing would silently move seats between contracts, and the money
    answer would still look plausible."""
    client.put("/admin/budget/subscription", headers=ADMIN,
               json=_sub("claude", "Team", 40, 25))
    client.put("/admin/budget/subscription", headers=ADMIN,
               json=_sub("claude", "Max 20", 3, 90))
    r = client.put("/admin/budget/members", headers=ADMIN, json={
        "tool_id": "claude", "source": "csv",
        "members": [{"email": "a@corp.example"}]})
    assert r.status_code == 422
    assert "say which plan" in r.json()["detail"]


def test_two_plans_on_one_tool_are_not_a_double_billed_licence(managed):
    """The covers rule still refuses one licence billed twice - but two
    plans for the same product are two licences, not one billed twice."""
    client.put("/admin/budget/subscription", headers=ADMIN,
               json=_sub("claude", "Team", 40, 25, covers=["claude-code"]))
    # Same tool, different plan: allowed.
    assert client.put("/admin/budget/subscription", headers=ADMIN,
                      json=_sub("claude", "Max 20", 3, 90)).status_code == 200
    # A different tool claiming a tool the Team licence already covers: not.
    r = client.put("/admin/budget/subscription", headers=ADMIN,
                   json=_sub("cursor", "Pro", 5, 20, covers=["claude-code"]))
    assert r.status_code == 422 and "already covered" in r.json()["detail"]
