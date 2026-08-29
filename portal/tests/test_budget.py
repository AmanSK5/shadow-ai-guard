"""The budget proxies and the page that draws them. Same direct-call
harness as the suite: the receiver owns storage and validation, so what
the portal must hold is thinner and worth stating exactly - each route
forwards the right verb to the right receiver path with the operator's
own session, classic mode refuses with the message that names the fix,
and the page ships with the view wired into the shell."""

import os
from pathlib import Path

os.environ.setdefault("PORTAL_AUTH", "none")

import pytest
from fastapi import HTTPException

from app import main

INDEX = (Path(__file__).parent.parent / "app" / "static"
         / "index.html").read_text()


@pytest.fixture
def receiver_spy(monkeypatch):
    """Managed mode with the receiver replaced by a recorder."""
    calls = []

    def fake(base, method, path, token, body=None):
        calls.append({"method": method, "path": path, "token": token,
                      "body": body})
        return {"ok": True}

    monkeypatch.setattr(main, "RECEIVER_URL", "http://receiver:8080")
    monkeypatch.setattr(main.managed, "receiver_request", fake)
    return calls


class _Req:
    cookies = {"aiguard_session": "aigt_test"}


# ----------------------------------------------------------- the proxies --


def test_each_route_forwards_the_right_verb_and_path(receiver_spy):
    token = main._admin_forward(_Req())

    main.api_budget(token=token)
    sub = main.BudgetSubscriptionWrite(
        tool_id="claude", vendor="Anthropic", plan="Team",
        seat_tiers=[main.BudgetSeatTier(name="premium", seats=5,
                                        unit_price_monthly=100)])
    main.api_budget_subscription(sub, token=token)
    main.api_budget_members(main.BudgetMembersWrite(
        tool_id="claude", source="csv",
        members=[main.BudgetMemberWrite(email="a@corp.example")]),
        token=token)
    main.api_budget_connection(main.BudgetConnectionWrite(
        tool_id="claude", provider="anthropic",
        api_key="sk-ant-api01-test"), token=token)
    main.api_budget_sync(main.BudgetToolRef(tool_id="claude"), token=token)
    main.api_budget_connection_delete(main.BudgetToolRef(tool_id="claude"),
                                      token=token)
    main.api_budget_subscription_delete(main.BudgetToolRef(tool_id="claude"),
                                        token=token)
    main.api_budget_fx("GBP", token=token)

    got = [(c["method"], c["path"]) for c in receiver_spy]
    assert got == [
        ("GET", "/admin/budget"),
        ("PUT", "/admin/budget/subscription"),
        ("PUT", "/admin/budget/members"),
        ("PUT", "/admin/budget/connection"),
        ("POST", "/admin/budget/sync"),
        ("POST", "/admin/budget/connection/delete"),
        ("POST", "/admin/budget/subscription/delete"),
        ("GET", "/admin/budget/fx?to=GBP"),
    ]
    # The operator's own session rides every call - the portal holds no
    # credential of its own for this.
    assert all(c["token"] == "aigt_test" for c in receiver_spy)


def test_the_body_reaches_the_receiver_intact(receiver_spy):
    token = main._admin_forward(_Req())
    main.api_budget_connection(main.BudgetConnectionWrite(
        tool_id="fireflies", provider="fireflies",
        api_key="ff-key-123"), token=token)
    body = receiver_spy[-1]["body"]
    assert body == {"tool_id": "fireflies", "provider": "fireflies",
                    "api_key": "ff-key-123"}


def test_classic_mode_refuses_and_names_the_fix(monkeypatch):
    monkeypatch.setattr(main, "RECEIVER_URL", "")
    with pytest.raises(HTTPException) as e:
        main._admin_forward(_Req())
    assert e.value.status_code == 503
    assert "RECEIVER_URL" in e.value.detail


# ---------------------------------------------------------------- the page --


def test_the_shell_ships_the_budget_view():
    # The nav entry, the view function, and the fragment round trip: a view
    # reachable only by typing its fragment is a view nobody finds.
    assert "['budget','Budget']" in INDEX
    assert "async function budget()" in INDEX
    assert "view === 'budget'" in INDEX


def test_the_wizard_names_the_honest_provider_set():
    # ChatGPT Business gets the guided import and the page says why - the
    # absence of an admin API on that plan is OpenAI's, and presenting it
    # as ai-guard's gap (or hiding it) would both be wrong.
    assert "no admin API" in INDEX
    # The roadmap note: automatic setup grows by request, on GitHub.
    assert "github.com/AmanSK5/shadow-ai-guard/issues" in INDEX


# ---------------------------------------------------------- the report --


def test_the_shell_ships_the_share_view():
    # Reachable from the page and by fragment, and rendered by its own
    # function - a report nobody can link to is a report nobody sends.
    assert "'budget-report'" in INDEX
    assert "function budgetReport()" in INDEX
    assert "data-act=\"b-report\"" in INDEX


def test_the_report_can_withhold_names_and_guards_the_csv():
    # The page names individuals and their personal account domains, so
    # withholding them is one control, in the page and in the export.
    assert "BRNAMES" in INDEX and "Withhold names" in INDEX
    assert "-anonymised.csv" in INDEX or "'-anonymised'" in INDEX
    # An exported address starting with = is a live formula in Excel.
    assert "B_FORMULA_LEAD" in INDEX and "function bCsvCell" in INDEX


def test_printing_drops_the_furniture():
    assert "@media print" in INDEX
    for hidden in ("aside", ".topbar", ".drawer", "[data-act]"):
        assert hidden in INDEX.split("@media print")[1][:600], hidden
