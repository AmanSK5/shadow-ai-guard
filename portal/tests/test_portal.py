"""Tests for the ai-guard portal.

Most of these cover derive.py rather than the HTTP layer, because the
derivation is where the portal can be quietly wrong. A route that returns the
wrong status code is obvious; a graph that merges two machines into one, or
reports a source as silent when it is reporting, looks exactly like a correct
answer.

Every case here corresponds to something that was actually wrong at some point
during the build, or to a property the design depends on.
"""

import json
import os

# PORTAL_AUTH must be set before the app module is imported: main.py refuses to
# start without authentication, and that refusal happens at module level.
os.environ.setdefault("PORTAL_AUTH", "none")

from app import derive  # noqa: E402


# Sources set by something other than a scanner: the three endpoint collectors,
# and the browser extension's two. Kept beside the test that uses it so adding
# a source and forgetting this list fails loudly rather than quietly widening
# the exclusion.
NON_SCANNER_SOURCES = {
    "collector-macos",
    "collector-linux",
    "collector-windows",
    "browser_extension",
    "paste_guard",
}


def finding(**kw):
    """A finding with sensible defaults, so each test states only what it is
    about."""
    f = {
        "tool": "claude-code",
        "surface": "cli",
        "os": "macos",
        "account_domain": "",
        "device": "SERIAL1",
        "device_name": "machine-1",
        "user": "someone",
        "evidence": "~/.claude.json",
        "severity": "info",
        "source": "collector-macos",
    }
    f.update(kw)
    return f


REGISTRY = {
    "tools": [
        {"id": "chatgpt", "domains": ["chatgpt.com", "chat.openai.com"]},
        {"id": "claude", "domains": ["claude.ai"]},
    ]
}


# --------------------------------------------------------------- tool names --

def test_a_domain_resolves_to_the_registry_tool_id():
    """The browser extension reports the hostname it saw; everything else
    reports the registry id. Without this, one tool is two nodes."""
    m = derive.load_domain_map_from(REGISTRY)
    assert derive.normalise_tool("chatgpt.com", m) == "chatgpt"
    assert derive.normalise_tool("claude.ai", m) == "claude"


def test_a_name_the_registry_does_not_know_is_left_alone():
    """A registry gap is worth seeing. Folding an unknown name into a
    neighbour would hide it and inflate that neighbour's count."""
    m = derive.load_domain_map_from(REGISTRY)
    assert derive.normalise_tool("something-new.example", m) == "something-new.example"


def test_a_canonical_id_is_not_rewritten():
    m = derive.load_domain_map_from(REGISTRY)
    assert derive.normalise_tool("claude-code", m) == "claude-code"


# ------------------------------------------------------------------- graph --

def test_surfaces_are_counted_separately_for_one_tool():
    """The same tool in a browser, a desktop app and a CLI are different
    exposures. Merging them into one number loses the distinction the platform
    exists for."""
    g = derive.graph_from([
        finding(tool="chatgpt.com", surface="browser", device="A", source="paste_guard"),
        finding(tool="chatgpt", surface="desktop", device="B", source="jamf_app"),
        finding(tool="chatgpt", surface="cli", device="C"),
    ], derive.load_domain_map_from(REGISTRY))

    tool = g["tools"]["chatgpt"]
    assert len(tool["devices"]) == 3
    per = {k: len(v) for k, v in tool["devices_by_surface"].items()}
    assert per == {"browser": 1, "desktop": 1, "cli": 1}


def test_bridge_targets_are_not_tools():
    """sentinelone_bridge reports where an AI tool reached. Slack and GitHub
    in a tool inventory is the destination of an integration being mistaken
    for the integration."""
    g = derive.graph_from([
        finding(tool="Slack", surface="cloud", source="sentinelone_bridge"),
        finding(tool="claude-code"),
    ], {})

    assert "Slack" not in g["tools"]
    assert "Slack" in g["bridges"]
    assert "claude-code" in g["tools"]


def test_the_guard_and_the_collector_are_not_tools_anyone_uses():
    g = derive.graph_from([
        finding(tool="paste-guard", surface="browser", source="paste_guard"),
        finding(tool="ai-guard-collector", surface="endpoint",
                evidence="heartbeat version=0.2.0 tools=0"),
    ], {})
    assert g["tools"] == {}


def test_a_cloud_finding_becomes_an_identity_not_a_device():
    """Entra and Exchange know people, not machines. A finding with no device
    and a username is an identity; a local username on an endpoint is not."""
    g = derive.graph_from([
        finding(tool="fireflies", surface="cloud", device="", device_name="",
                user="someone@example.com", source="entra_sign_in"),
    ], {})

    assert g["identities"]["someone@example.com"]["tools"] == ["fireflies"]
    assert g["devices"] == {}


def test_a_finding_with_neither_device_nor_user_is_unattributed():
    """Counted and named rather than dropped: a finding that cannot be
    attributed is still evidence something is there."""
    g = derive.graph_from([
        finding(tool="chatgpt", surface="cloud", device="", device_name="",
                user="", source="exchange_email"),
    ], {})

    assert len(g["unattributed"]) == 1
    assert g["unattributed"][0]["source"] == "exchange_email"


def test_a_personal_account_is_flagged_on_the_device():
    g = derive.graph_from([
        finding(account_domain="gmail.com", severity="warn"),
    ], {})
    assert g["devices"]["SERIAL1"]["personal_accounts"] == ["gmail.com"]


# ---------------------------------------------------------------- coverage --

def test_coverage_is_judged_on_surface_not_on_source():
    """source is not reliably populated: the macOS collector sent none until
    recently and the browser extension predates the field. Judging on source
    alone flagged every Mac in a fleet as uncovered while its cli findings sat
    in the same graph."""
    g = derive.graph_from([
        finding(surface="desktop", source="jamf_app", user=""),
        finding(surface="cli", source=""),   # a collector, saying nothing about itself
    ], {})

    d = g["devices"]["SERIAL1"]
    assert d["collector_seen"] is True
    assert d["scanner_seen"] is True


def test_a_heartbeat_proves_coverage_on_a_machine_with_no_ai_tools():
    """A scan that finds nothing and a collector that never ran produce the
    same thing on a dashboard: silence."""
    g = derive.graph_from([
        finding(tool="claude", surface="desktop", source="jamf_app", user=""),
        finding(tool="ai-guard-collector", surface="endpoint",
                evidence="heartbeat version=0.2.0 tools=0"),
    ], {})

    d = g["devices"]["SERIAL1"]
    assert d["collector_seen"] is True
    assert d["collector_version"] == "0.2.0"


def test_a_machine_only_an_inventory_knows_is_a_coverage_gap():
    g = derive.graph_from([
        finding(tool="microsoft-copilot", surface="desktop", device="NOAGENT",
                device_name="", user="", os="windows", source="intune_app"),
    ], {})

    d = g["devices"]["NOAGENT"]
    assert d["scanner_seen"] is True
    assert d["collector_seen"] is False


# ---------------------------------------------------------------- identity --

def test_an_identity_map_attaches_a_person_to_a_device():
    g = derive.graph_from(
        [finding(user="jane.doe")],
        {},
        {"SERIAL1": "jane.doe@example.com"},
    )
    assert g["devices"]["SERIAL1"]["person"] == "jane.doe@example.com"


def test_an_identity_map_can_key_on_the_local_username():
    """Which key a deployer can supply depends on what they run: an MDM keys
    on the serial, a spreadsheet is more likely to key on the login name."""
    g = derive.graph_from(
        [finding(user="jdoe")],
        {},
        {"jdoe": "jane.doe@example.com"},
    )
    assert g["devices"]["SERIAL1"]["person"] == "jane.doe@example.com"


def test_a_device_with_no_mapping_stays_unattributed():
    """A first-class state, not an error. A team with no MDM still learns
    which machines run what."""
    g = derive.graph_from([finding()], {}, {})
    assert g["devices"]["SERIAL1"]["person"] == ""


def test_suggestions_are_proposed_and_never_applied():
    """These are string matches. A mapping the platform invented and then
    acted on is how the wrong name ends up on a report."""
    devices, identities, _t, _b, _u = derive.build([
        finding(user="jane.doe"),
        finding(tool="fireflies", surface="cloud", device="", device_name="",
                user="jane.doe@example.com", source="entra_sign_in"),
    ], {}, {})

    matched, unmatched = derive.suggest_identity_rows(devices, identities)
    assert matched[0]["identity"] == "jane.doe@example.com"
    # Proposed only: nothing was attached.
    assert devices["SERIAL1"]["person"] == ""


# ------------------------------------------------------------------ status --

def test_status_separates_reporting_from_silent():
    st = derive.status_from([finding(source="collector-macos")])
    by_source = {r["source"]: r for r in st["sources"]}
    assert by_source["collector-macos"]["reporting"] is True
    assert by_source["entra_sign_in"]["reporting"] is False


def test_every_expected_source_says_what_it_needs():
    """A status page that says "not reporting" and nothing else leaves the
    reader exactly where they were."""
    st = derive.status_from([])
    assert all(r["needs"] for r in st["sources"])
    assert all(r["doc"] for r in st["sources"])


def test_an_unrecognised_source_is_surfaced_rather_than_ignored():
    """This is what caught demo/seed.sh seeding scanner-entra, a value no
    deployment produces."""
    st = derive.status_from([finding(source="not-a-real-source")])
    assert "not-a-real-source" in st["unexpected"]


def test_the_expected_sources_match_what_the_scanners_emit():
    """The portal's list is hardcoded and the real values live in
    DetectionSource. They drifted once already: the list said entra_signin
    where the scanner emits entra_sign_in, so a reporting source showed as
    silent - the exact false signal this view exists to remove.

    The enum is read from source rather than imported, so this runs without
    the scanner package installed. A cross-component check that only runs
    when someone happens to have both installed is a check that does not run.
    """
    import ast
    import pathlib
    import pytest

    base = (pathlib.Path(__file__).resolve().parents[2]
            / "scanner" / "ai_guard" / "scanners" / "base.py")
    if not base.exists():
        pytest.skip("scanner source not present next to the portal")

    tree = ast.parse(base.read_text())
    emitted = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "DetectionSource":
            for item in node.body:
                if isinstance(item, ast.Assign) and isinstance(item.value, ast.Constant):
                    emitted.add(item.value.value)

    assert emitted, "could not read any DetectionSource values from %s" % base

    listed = {r["source"] for r in derive.status_from([])["sources"]}
    # Collectors and the browser extension set their source directly rather
    # than through DetectionSource, because neither is a scanner. They are
    # named here rather than pattern-matched: a rule like "anything starting
    # with collector-" would silently absorb a typo, which is the failure this
    # test exists to catch.
    listed -= NON_SCANNER_SOURCES

    missing = emitted - listed
    assert not missing, (
        "DetectionSource values the portal's setup view does not list, so they "
        "would show as unrecognised rather than as a source to configure: %s"
        % sorted(missing)
    )

    stale = listed - emitted
    assert not stale, (
        "sources the portal lists that no scanner emits, so they would show as "
        "permanently not reporting: %s" % sorted(stale)
    )

def test_every_non_scanner_source_is_actually_listed():
    """The exclusion list above is a hardcoded copy, and a hardcoded copy that
    nothing checks is the thing this file keeps catching elsewhere. If a name
    here is not in the portal's setup view, the exclusion is hiding a source
    that would show as unrecognised in a real deployment."""
    listed = {r["source"] for r in derive.status_from([])["sources"]}
    missing = NON_SCANNER_SOURCES - listed
    assert not missing, (
        "excluded from the scanner cross-check but not listed in the setup "
        "view either, so they would appear as unrecognised: %s" % sorted(missing)
    )

# --------------------------------------------------------- tool/account pairs


def test_device_keeps_tool_and_account_paired():
    """The flat tools and accounts sets on a device cannot say which tool the
    personal account belongs to, which is the question the pairing exists to
    answer."""
    g = derive.graph_from([
        finding(tool="chatgpt", surface="browser", account_domain="gmail.com",
                severity="warn", source="browser_extension"),
        finding(tool="claude-code", account_domain="example.com"),
    ])
    pairs = g["devices"]["SERIAL1"]["tool_accounts"]
    assert pairs["chatgpt"] == ["gmail.com"]
    assert pairs["claude-code"] == ["example.com"]


def test_tool_with_no_account_still_appears_in_the_pairing():
    """A software inventory finding proves the app is installed and says
    nothing about who is signed in. That is a third state, distinct from a
    work account, and dropping it would hide it in the one view meant to show
    which tools lack an account."""
    g = derive.graph_from([finding(tool="codeium", surface="desktop",
                                   account_domain="", source="jamf_app")])
    pairs = g["devices"]["SERIAL1"]["tool_accounts"]
    assert "codeium" in pairs
    assert pairs["codeium"] == []


# ------------------------------------------------------- personal account rows


def test_personal_accounts_exclude_work_accounts_and_bridges():
    """severity is the reporter's judgement, made where the corporate domain
    list actually lives. Bridge findings are destinations an integration
    reached, not accounts anyone signed into."""
    rows = derive.graph_from([
        finding(account_domain="gmail.com", severity="warn"),
        finding(account_domain="example.com", severity="info"),
        finding(tool="slack", surface="network", account_domain="gmail.com",
                severity="warn", source="sentinelone_bridge"),
    ])["personal_accounts"]
    assert len(rows) == 1
    assert rows[0]["account_domain"] == "gmail.com"
    assert rows[0]["tool"] == "claude-code"


def test_personal_accounts_aggregate_first_and_last_seen():
    """Repeated findings for the same account on the same tool are one row.
    Counting them separately would make a throttled heartbeat look like
    repeated signups."""
    rows = derive.graph_from([
        finding(account_domain="gmail.com", severity="warn",
                reported_at="2026-08-09T17:31:00Z"),
        finding(account_domain="gmail.com", severity="warn",
                reported_at="2026-07-28T09:12:00Z"),
    ])["personal_accounts"]
    assert len(rows) == 1
    assert rows[0]["findings"] == 2
    assert rows[0]["first_seen"] == "2026-07-28T09:12:00Z"
    assert rows[0]["last_seen"] == "2026-08-09T17:31:00Z"


def test_personal_accounts_separate_rows_per_tool_and_device():
    """One person signing into two tools is two things to follow up, not one
    account with a longer attribute list."""
    rows = derive.graph_from([
        finding(tool="chatgpt", surface="browser", account_domain="gmail.com",
                severity="warn", source="browser_extension"),
        finding(tool="claude", surface="browser", account_domain="gmail.com",
                severity="warn", source="browser_extension"),
        finding(tool="chatgpt", surface="browser", device="SERIAL2",
                account_domain="gmail.com", severity="warn",
                source="browser_extension"),
    ])["personal_accounts"]
    assert len(rows) == 3


# ----------------------------------------------------------- overview widgets


def _widgets_for(spec):
    """The parser reads module-level config, so set it and reload."""
    import importlib
    import os
    os.environ["PORTAL_AUTH"] = "none"
    os.environ["OVERVIEW_WIDGETS"] = spec
    import app.main as main
    importlib.reload(main)
    return main._widgets()


def test_unknown_widget_is_reported_not_dropped():
    """A widget that silently does not appear looks identical to one that
    appeared with nothing to show, which sends someone debugging their data
    instead of their config."""
    out = _widgets_for("stat_row,not_a_widget")
    assert out[0] == {"kind": "stat_row"}
    assert out[1]["kind"] == "error"
    assert "not_a_widget" in out[1]["error"]
    assert "stat_row" in out[1]["error"], "the error should list what is valid"


def test_no_widget_config_gives_a_usable_default():
    """An empty landing page is a worse first impression than an opinionated
    one, and a deployer who has not chosen yet has not chosen 'nothing'."""
    out = _widgets_for("")
    assert out
    assert all(w["kind"] != "error" for w in out)


def test_grafana_widget_keeps_its_reference():
    out = _widgets_for("grafana:ai-usage-over-time")
    assert out == [{"kind": "grafana", "ref": "ai-usage-over-time"}]


# ------------------------------------------------------------- MCP servers


def test_mcp_counts_servers_not_tools():
    """An MCP server is the unit of exposure: it holds its own credentials and
    reaches what it was pointed at whether or not the configuring tool is
    open. One server reached by two tools is one thing to assess."""
    rows = derive.graph_from([
        finding(tool="claude-code-mcp", surface="mcp", device="S1",
                evidence=".claude.json mcpServers: figma,context7"),
        finding(tool="cursor-mcp", surface="mcp", device="S2",
                evidence=".cursor/mcp.json mcpServers: figma"),
    ])["mcp_servers"]
    by = {r["server"]: r for r in rows}
    assert set(by) == {"figma", "context7"}
    assert len(by["figma"]["devices"]) == 2
    assert by["figma"]["tools"] == ["claude-code-mcp", "cursor-mcp"]


def test_mcp_reads_the_legacy_tool_name_format():
    """Loki holds findings from before the server list moved out of the tool
    name, for as long as the lookback window. Reading only the current format
    would make the estate look like it shrank on the day of the fix."""
    rows = derive.graph_from([
        finding(tool="claude-code-mcp:figma,context7", surface="mcp",
                device="S1", evidence=".claude.json mcpServers"),
    ])["mcp_servers"]
    by = {r["server"]: r for r in rows}
    assert set(by) == {"figma", "context7"}
    assert by["figma"]["tools"] == ["claude-code-mcp"], \
        "the tool should be the base name, not the name with servers appended"


def test_mcp_finding_with_no_server_list_is_still_counted():
    """Something configured MCP and the detail did not survive. Dropping it
    would understate the estate, which is the failure mode this whole project
    is about."""
    rows = derive.graph_from([
        finding(tool="claude-code-mcp", surface="mcp", device="S1",
                evidence="config file present"),
    ])["mcp_servers"]
    assert len(rows) == 1
    assert rows[0]["server"] == "(unnamed)"
