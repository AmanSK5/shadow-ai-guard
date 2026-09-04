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
    # plan_key rides along empty: the portal only carries it, and the
    # receiver decides what an empty one means (the tool's only
    # subscription, or a refusal when there are several).
    assert body == {"tool_id": "fireflies", "plan_key": "",
                    "provider": "fireflies",
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


def test_linking_a_tool_is_four_steps_with_a_review():
    """The budget wizard was already three steps; what it lacked was the
    language. Its only progress marker was the italic text "step 1 of 3", the
    seat tiers were three inputs whose only labels were placeholders that
    vanish once anything is typed, and it committed straight from the last
    step with nothing showing the licence, its covered tools and the cost
    together."""
    for needle in ("function bwRail(", "function bwBodyReview(",
                   "const BW_STEPS", "Review and link",
                   'class="tiers"', "<th>Tier</th>", "Price / seat",
                   "bw-tsum", "bw-money"):
        assert needle in INDEX, needle
    # The rail summary carries the money, not a step count: this is the one
    # wizard whose subject is a number.
    assert "Monthly spend" in INDEX
    assert "function bwLive()" in INDEX
    # Currency is read off the screen too, or every figure renders unitless
    # until the step is left.
    assert "function bWizCur()" in INDEX
    assert "step 1 of 3" not in INDEX and "step ${w.step} of 3" not in INDEX


def test_the_rail_does_not_tick_a_step_nobody_has_visited():
    """Both the tool and the member source are prefilled when the wizard
    opens, so keying "done" off the value alone ticked steps 1 and 2 green
    before the operator had looked at either."""
    assert "const passed = w.editing || w.step > st.k;" in INDEX


def test_linking_does_not_open_on_an_already_linked_tool():
    """b-open picked the first OBSERVED tool whichever it was, so on a
    deployment whose busiest tool is already linked it opened on that one -
    and pressing through to the end overwrote the subscription that existed,
    with nothing on screen saying so. Caught by driving the wizard and reading
    the review step, which named a tool the Budget view already listed."""
    assert "const taken = new Set();" in INDEX
    assert "const free = (REGTOOLS || []).slice()" in INDEX
    assert "filter(t => !taken.has(t.id));" in INDEX


def test_the_member_step_names_every_connector_and_its_plan():
    """Automatic sync exists for two of the thirty tools the registry ships,
    and the only way to find that out was to open the dropdown and not see
    yours. The step now lists the connectors with the plan each needs.

    The general note replaced a ChatGPT-specific one: naming a single absence
    made it look like the only one, when every tool without a connector is in
    exactly the same position."""
    assert "plan, and how" in INDEX
    # There used to be a SECOND table listing only the built connectors,
    # directly above a dropdown containing exactly those same connectors. It
    # said nothing the full table does not, and having both invited the
    # reading that the dropdown was the list of vendors rather than the list
    # of ones with code behind them.
    assert "The complete list of vendors" not in INDEX
    assert "plan it needs" not in INDEX
    assert "Anything not listed" in INDEX
    assert "under Automatic uses Import or Manual" in INDEX
    # The old copy spoke only about ChatGPT in the general slot.
    assert "const BPROVIDER_NONE = `ChatGPT Business" not in INDEX


def test_a_tool_with_no_licence_mates_says_so():
    """Atlassian Rovo shares a licence group with nothing, so "Also covers"
    rendered an empty chip row and a bare "more tools..." - which reads as a
    control that failed to load rather than one with nothing to offer."""
    assert "Nothing in the registry" in INDEX
    assert "choose from every tool" in INDEX


def test_the_member_step_answers_why_a_tool_is_missing():
    """Naming only the two built connectors left the operator of the other
    twenty-eight with no answer. The step now separates "the vendor offers
    nothing" from "the vendor offers something nobody has connected", which is
    the only one of the two worth opening an issue about."""
    for needle in ("member_apis", "Vendor API, no connector yet",
                   "No seat list exists", "Not documented",
                   "an admin API nobody has connected yet",
                   "tools with a sync written"):
        assert needle in INDEX, needle
    # A connector written from a docs page is not a connector anybody has
    # run. Being in the dropdown reads as "this works", so the ones that have
    # never touched a real tenant say so where the key gets pasted.
    assert "unverified" in INDEX
    assert "has never been run against a real organisation" in INDEX


def test_import_and_manual_speak_about_the_tool_being_linked():
    """Import and Manual carried a paragraph about ChatGPT whichever tool you
    were linking. It went stale the moment a ChatGPT connector existed: it
    told an Enterprise workspace to use Import when Automatic had just started
    working for it. The answer is per-tool and already in member_apis, so the
    note is built from that instead of from one vendor's example."""
    assert "BPROVIDER_CHATGPT" not in INDEX
    assert "ChatGPT Business (Team) is the usual surprise" not in INDEX
    for needle in ("can sync automatically",
                   "vendor does expose a members API",
                   "has no organisation or seat list to read",
                   "does not document a members API"):
        assert needle in INDEX, needle


def test_a_tool_you_defined_is_not_reported_as_undocumented():
    """member_apis covers the tools this release ships with. A tool the
    operator defined has no row, and an absent row is not a finding - falling
    through to the "not documented" branch made the page state, about a tool
    invented five minutes earlier, that its vendor documents no members API.
    Nobody had looked. "We have no record" and "we looked and there is
    nothing" are different sentences."""
    assert "is a tool you defined" in INDEX
    assert "there is no record here of" in INDEX
    # And the table says which tools it is actually about.
    assert "SHIPPED tools" in INDEX
    assert "tools you define yourself are not in here" in INDEX


def test_the_budget_page_lists_providers_as_a_list_not_a_chain():
    """The empty state joined every provider with " and ". At two vendors that
    read fine; at seven it was one breathless sentence. The trailing line
    about ChatGPT Business went with it - it is one plan of one vendor, it
    stopped being the only notable absence, and the wizard's own step now says
    what applies to the tool being linked."""
    assert "ChatGPT Business has no admin API on that plan" not in INDEX
    assert "labels.slice(0, -1).join(', ')" in INDEX


def test_a_new_plan_hands_its_key_to_what_follows():
    """Linking a second plan on a tool with "CSV" as the source opened the
    import with no plan key: the wizard passed on its own empty one, and the
    receiver - rightly - refuses to guess between two plans. The wizard now
    reads the key the receiver derived back from the save's answer and hands
    it to the connection, the first sync and the import alike."""
    html = (main.STATIC / "index.html").read_text()
    save = html.split("if (act === 'b-save') {", 1)[1].split("if (act === 'b-sync')", 1)[0]
    assert "const mine = (saved.subscriptions || []).find(x => x.tool_id === w.tool_id" in save
    assert "if (mine) pk = mine.plan_key || 'default';" in save
    assert "plan_key: w.plan_key || ''" not in save.split("let pk =", 1)[1]
    assert save.count("plan_key: pk") == 3


def test_the_import_asks_which_plan_when_it_does_not_know():
    """The screen names the plan it is importing into, and when it has no key
    on a tool with several plans it asks rather than letting the import fail
    with the receiver's refusal after the paste."""
    html = (main.STATIC / "index.html").read_text()
    view = html.split("function budgetImport() {", 1)[1].split("\nfunction ", 1)[0]
    assert "const askPlan = !BCSV.plan_key && plans.length > 1;" in view
    assert 'id="b-csv-plan"' in view
    assert "parsed.members.length && !askPlan" in view
    assert "e.target.id === 'b-csv-plan' && BCSV" in html
