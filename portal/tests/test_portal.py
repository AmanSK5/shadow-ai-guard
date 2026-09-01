"""Tests for the ai-guard portal.

Most of these cover derive.py rather than the HTTP layer, because the
derivation is where the portal can be quietly wrong. A route that returns the
wrong status code is obvious; a graph that merges two machines into one, or
reports a source as silent when it is reporting, looks exactly like a correct
answer.

Every case here corresponds to something that was actually wrong at some point
during the build, or to a property the design depends on.
"""

import os
import time

# PORTAL_AUTH must be set before the app module is imported: main.py refuses to
# start without authentication, and that refusal happens at module level.
os.environ.setdefault("PORTAL_AUTH", "none")

import pytest

from app import derive

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
    from app import main
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


def test_the_widget_lists_in_python_and_javascript_agree():
    """KNOWN_WIDGETS and the browser's WIDGETS object must name the same set.

    They are two lists that have to agree with nothing enforcing it, and the
    failure is asymmetric and confusing in both directions. A widget in the
    browser but not in KNOWN_WIDGETS renders an error card telling the operator
    their config is wrong when it is not. One in KNOWN_WIDGETS but not in the
    browser passes validation and then draws nothing, which looks like a data
    problem rather than a missing renderer.

    This happened: paste_guard was added to the browser and not to the server,
    and the error card blamed the deployment for naming a widget that existed.
    """
    import re
    from pathlib import Path

    from app.main import KNOWN_WIDGETS

    src = (Path(__file__).parent.parent / "app" / "static" / "index.html").read_text()
    block = re.search(r"const WIDGETS = \{(.*?)\n\};", src, re.DOTALL).group(1)
    # Top-level keys only: two-space indent, then a name and a colon.
    in_browser = set(re.findall(r"^  ([a-z_]+): ", block, re.MULTILINE))

    # grafana and error are dispatch targets rather than things an operator
    # names in OVERVIEW_WIDGETS, so they are not expected in KNOWN_WIDGETS.
    in_browser -= {"grafana", "error"}

    assert in_browser == set(KNOWN_WIDGETS), (
        "only in the browser: %s | only in KNOWN_WIDGETS: %s"
        % (sorted(in_browser - set(KNOWN_WIDGETS)),
           sorted(set(KNOWN_WIDGETS) - in_browser)))


class TestLokiReadAuth:
    """The portal has to authenticate to the log store the receiver writes to.

    The receiver had LOKI_USERNAME/LOKI_PASSWORD for its writes and the portal
    only had a bearer token. Against Grafana Cloud, which wants basic auth,
    that meant the receiver stored findings successfully and the portal got a
    401 reading back the ones it had just stored. Writes working and reads not
    is not a working deployment, and no piece of configuration named the gap:
    both variables were present in the environment, and only one container
    used them.
    """

    def _header(self, **kw):
        """The Authorization header fetch_from_loki would send."""
        from unittest.mock import patch

        from app import derive

        captured = {}

        class _Resp:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self): return b'{"data":{"result":[]}}'

        def _urlopen(req, timeout=None):
            captured["auth"] = req.get_header("Authorization")
            return _Resp()

        with patch.object(derive.urllib.request, "urlopen", _urlopen), \
                patch.object(derive.json, "load", lambda f: {"data": {"result": []}}):
            derive.fetch_from_loki("http://loki:3100", 1, **kw)
        return captured.get("auth")

    def test_basic_auth_is_sent_when_a_username_is_set(self):
        """The literal header, not a re-derivation of the code under test.

        Grafana Cloud's username is a numeric instance id, which is worth
        having in the fixture: it looks like a mistake to anyone who has not
        seen one, and a reader who assumes it should be an email is the reader
        this test is for. Invented, not a real one.
        """
        assert self._header(username="1234567", password="secret") == \
            "Basic MTIzNDU2NzpzZWNyZXQ="

    def test_a_bearer_token_still_works(self):
        assert self._header(token="abc123") == "Bearer abc123"

    def test_no_credentials_sends_no_header(self):
        assert self._header() is None

    def test_basic_auth_wins_when_both_are_set(self):
        """A gateway wanting a bearer token in front of a Loki wanting basic
        auth is a real arrangement, but only one Authorization header can be
        sent. Basic is the one the log store itself needs."""
        h = self._header(username="u", password="p", token="t")

        assert h.startswith("Basic ")


class TestNoUntrustedValueReachesExecutableContext:
    """Findings are attacker-influenced, and the portal renders them.

    Anyone holding the reporting token can put arbitrary text in a device name,
    a username or a tool id, and that token is distributed to every collector
    and to the browser extension. So a finding is untrusted input that an
    authenticated operator later views, and the portal's origin has the session
    that can read the whole estate.

    This started as a stored XSS. esc() escaped & < > and " but not ', and
    values were interpolated into onclick="open_('device','...')", a
    single-quoted JS string inside a double-quoted attribute. A device named

        x'),alert(1),open_('a

    closed the string and ran what followed. The inline handlers are gone, but
    the tests below hold both halves: nothing may put a value in an executable
    context, and the escape must cover the quote either way.

    Asserted against the file rather than a rendered page, because there is no
    DOM here. That is a real limit: it catches the shape of the bug and not
    every instance of it.
    """

    def _src(self):
        from pathlib import Path
        return (Path(__file__).parent.parent / "app" / "static" / "index.html").read_text()

    def test_the_escape_covers_the_single_quote(self):
        """The specific gap. Everything else was already escaped.

        Asserts on the replacement each character maps to rather than on the
        character appearing in the source, because quoting a quote inside a
        regex inside a JS string inside a Python literal is four layers of
        escaping and the test starts failing for reasons of its own.
        """
        import re

        line = re.search(r"const esc = s =>.*", self._src()).group(0)

        for entity in ("&amp;", "&lt;", "&gt;", "&quot;", "&#39;"):
            assert entity in line, "esc() does not produce %s" % entity

    def test_no_inline_event_handlers(self):
        """A value in an attribute is data. A value in onclick is code, and the
        only thing between them is an escape function remembering a character.

        Delegation removes the category rather than escaping around it, so a
        new row added later cannot reintroduce this by copying a pattern.
        """
        import re

        # Comments explaining why they are gone are allowed to name them.
        code = re.sub(r"^\s*//.*$", "", self._src(), flags=re.MULTILINE)

        for attr in ("onclick=", "onerror=", "onload=", "onmouseover="):
            assert attr not in code, "an inline %s handler is back" % attr

    def test_arrays_from_findings_are_joined_through_the_escape(self):
        """local_users, sources, accounts and tools were joined straight into
        HTML with no escaping at all. local_users is the sharpest: it is a
        username read off the device by the collector.

        Checks `.join(` specifically, which is the shape that was broken and
        the shape a new field would most likely copy. An earlier version tried
        to match any interpolation mentioning these fields and produced a false
        positive on a nested template, because a regex cannot find the end of a
        JavaScript expression. A narrow check that holds is worth more than a
        broad one that has to be argued with.
        """
        import re

        for line in self._src().split("\n"):
            if line.lstrip().startswith("//"):
                continue
            for m in re.finditer(
                    r"\$\{\(?[a-z]\.(\w+)\s*\|\|\s*\[\]\)[\w.()]*?\.join\(", line):
                assert "esc(" in m.group(0), (
                    "%s is joined into HTML unescaped: %s" % (m.group(1), line.strip()))


class TestSecurityHeaders:
    """Headers that limit what a rendering bug can do.

    A second line rather than the fix. The fix is that findings are escaped
    and nothing reaches an executable context; these limit the damage when
    that is next got wrong, which on a page rendering attacker-influenced text
    is a question of when.
    """

    def _headers(self, path="/healthz"):
        import asyncio

        from app import main as pm

        async def _call():
            captured = {}

            class _Req:
                url = type("U", (), {"path": path})()

            class _Resp:
                headers = {}
                def __init__(self): self.headers = {}

            async def _next(req):
                return _Resp()

            r = await pm.security_headers(_Req(), _next)
            captured.update(r.headers)
            return captured

        return asyncio.run(_call())

    def test_connect_src_is_self(self):
        """The one that matters most here. The estate data this page reads is
        the thing worth stealing, and an injection that runs but cannot reach
        another origin is a far smaller problem than one that can."""
        assert "connect-src 'self'" in self._headers()["Content-Security-Policy"]

    def test_the_page_cannot_be_framed(self):
        """It names who runs what on which machine."""
        h = self._headers()

        assert "frame-ancestors 'none'" in h["Content-Security-Policy"]
        assert h["X-Frame-Options"] == "DENY"

    def test_responses_are_not_cached(self):
        """They name people, devices and accounts, and a shared machine's disk
        cache is not where that belongs."""
        assert self._headers()["Cache-Control"] == "no-store"

    def test_content_type_is_not_sniffed(self):
        assert self._headers()["X-Content-Type-Options"] == "nosniff"

    def test_no_referrer_is_sent(self):
        """A portal URL can carry a device or a tool id in its fragment."""
        assert self._headers()["Referrer-Policy"] == "no-referrer"


class TestIdentityMapRoundTrip:
    """The suggested map has to load back as what it says.

    suggest-identities is the documented way to start an identity map: download
    it, review it, feed it back. It writes the local username it matched on as
    an inline comment so a reviewer can see why each row was proposed.

    The parser split on the first comma and kept everything after it, so the
    comment became part of the identity. Following the documented workflow
    without editing put "jo.bloggs  # via local user Jo.Bloggs" on every report
    naming that person, and it would have looked like the platform mangling
    names rather than reading its own output wrongly.
    """

    def _round_trip(self, matched, unmatched=()):
        import os
        import tempfile

        from app.derive import load_identity_map, suggest_identity_csv

        with tempfile.NamedTemporaryFile(
                "w", suffix=".csv", delete=False) as fh:
            fh.write(suggest_identity_csv(list(matched), list(unmatched)))
            path = fh.name
        try:
            return load_identity_map(path)
        finally:
            os.unlink(path)

    def test_the_inline_comment_is_not_part_of_the_identity(self):
        out = self._round_trip(
            [{"key": "ABC123", "identity": "jo.bloggs", "via": "Jo.Bloggs"}])

        assert out == {"ABC123": "jo.bloggs"}

    def test_unmatched_devices_are_not_loaded(self):
        """They are written commented out, as prompts to fill in."""
        out = self._round_trip(
            [], [{"key": "D2", "local_users": ["someone"]}])

        assert out == {}

    def test_a_formula_in_a_proposal_is_guarded(self):
        """These proposals come from local usernames read off machines."""
        from app.derive import suggest_identity_csv

        text = suggest_identity_csv(
            [{"key": "=cmd", "identity": "=calc", "via": "x"}], [])

        assert "'=cmd,'=calc" in text

    def test_a_newline_in_a_key_cannot_plant_a_row(self):
        """The injection this format invited.

        The file is line oriented and was built by joining strings, so a device
        key containing a newline wrote a second record. Anyone able to report a
        finding could propose an identity mapping nobody wrote, and a deployer
        who accepted the file would then see later findings attributed to
        whoever the attacker named. Wrong attribution is the one failure this
        platform must not have: the whole point of an identity map is putting a
        person's name on a report.

        The formula guard added earlier did nothing about it. A spreadsheet
        formula and an injected record are different problems that happen to
        share a file, and fixing the one that was reported is not the same as
        fixing the file.
        """
        out = self._round_trip([{
            "key": "device-a\nVICTIM,attacker",
            "identity": "x", "via": "alice",
        }])

        assert "VICTIM" not in out
        assert out == {}

    def test_a_rejected_row_says_so(self):
        """A row missing without explanation looks the same as a device nobody
        could name, and the operator reviewing this file is the control the
        whole format relies on."""
        from app.derive import suggest_identity_csv

        text = suggest_identity_csv(
            [{"key": "a\nb", "identity": "x", "via": "v"}], [])

        assert "1 device left out" in text

    def test_a_newline_in_an_unmatched_key_stays_in_its_comment(self):
        """The unmatched block is commented out, which made it look safe. A
        comment is only a comment until a value inside it ends the line."""
        out = self._round_trip(
            [], [{"key": "d\nEVIL,attacker", "local_users": ["x"]}])

        assert out == {}

    def test_a_comma_in_an_identity_does_not_split_the_row(self):
        """csv.writer would quote it and csv.reader would read it back, but a
        key with a comma is not a device serial, and a file needing quotes is
        harder to hand-edit, which is what this format is for."""
        from app.derive import suggest_identity_csv

        text = suggest_identity_csv(
            [{"key": "a,b", "identity": "x", "via": "v"}], [])

        assert "left out" in text

    def test_a_file_written_by_hand_still_loads(self):
        """The parser moved from splitting on the first comma to csv.reader,
        and deployments already have files written the old way. A format change
        that silently drops half an identity map would attribute reports to
        nobody and look like a data problem.
        """
        import os
        import tempfile

        from app.derive import load_identity_map

        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as fh:
            fh.write("# key,identity\n"
                     "ABC123,jo.bloggs\n"
                     "DEF456,  ann.smith\n"
                     "  GHI789,bob.jones\n"
                     "# a comment line\n"
                     "JKL012,carol.white  # a hand-written note\n"
                     "\n"
                     "MNO345,dave.brown\n")
            path = fh.name
        try:
            out = load_identity_map(path)
        finally:
            os.unlink(path)

        assert out == {
            "ABC123": "jo.bloggs", "DEF456": "ann.smith",
            "GHI789": "bob.jones", "JKL012": "carol.white",
            "MNO345": "dave.brown",
        }


class TestLokiUrlScheme:
    """urlopen honours more schemes than anyone configuring a log store means.

    file:, ftp: and anything else with a handler registered are all accepted,
    so a mistyped LOKI_URL could read a local file and have it parsed as a Loki
    response. Operator-supplied rather than attacker-supplied, so this is less
    an attack path than a way for a typo to do something surprising quietly.
    """

    def test_a_file_url_is_refused(self):
        import pytest
        from app.main import require_http_url

        with pytest.raises(SystemExit, match="must be http"):
            require_http_url("LOKI_URL", "file:///etc/passwd")

    def test_an_ftp_url_is_refused(self):
        import pytest
        from app.main import require_http_url

        with pytest.raises(SystemExit):
            require_http_url("LOKI_URL", "ftp://example.com/x")

    def test_http_and_https_pass_through(self):
        """The check has to let through what it exists to carry."""
        from app.main import require_http_url

        assert require_http_url("LOKI_URL", "http://loki:3100") == "http://loki:3100"
        assert require_http_url("LOKI_URL", "https://x.example") == "https://x.example"

    def test_unset_is_allowed(self):
        """Loki is optional: the portal starts and says it has no data rather
        than refusing to run."""
        from app.main import require_http_url

        assert require_http_url("LOKI_URL", "") == ""

    def test_the_message_names_the_variable(self):
        """Somebody reading a crashed container's last line needs to know which
        of several URLs was wrong."""
        import pytest
        from app.main import require_http_url

        with pytest.raises(SystemExit, match="LOKI_URL"):
            require_http_url("LOKI_URL", "file:///x")
def test_an_editor_that_bundles_ai_is_installed_not_in_use():
    """Windsurf/Devin Desktop and Cursor are VS Code forks: someone can run
    one all day without ever invoking a model. Counting an inventory hit as
    AI usage is how "23 tools in use" comes to mean "23 editors installed" -
    the same mistake as identifying Notion AI by notion.so. The scanner marks
    those findings ambient; nothing here should read them as use."""
    g = derive.graph_from([
        # Found by Intune, and reaching the update/telemetry host on launch.
        finding(tool="codeium", surface="desktop", device="A",
                source="intune_app", signal="ambient"),
        finding(tool="codeium", surface="network", device="B",
                source="sentinelone_dns", signal="ambient"),
    ], {})

    t = g["tools"]["codeium"]
    assert t["usage"] == "installed"
    assert len(t["devices"]) == 2      # the editor is on two machines
    assert t["devices_active"] == []   # nobody has been shown using the AI


def test_one_hit_on_the_completion_backend_makes_it_in_use():
    """The whole point of splitting the domains: traffic to the host that
    only answers when a model runs is the thing that turns "installed" into
    "used", and it counts the machine it came from - not every machine the
    editor happens to sit on."""
    g = derive.graph_from([
        finding(tool="codeium", surface="desktop", device="A",
                source="intune_app", signal="ambient"),
        finding(tool="codeium", surface="network", device="B",
                source="sentinelone_dns", signal="active"),
    ], {})

    t = g["tools"]["codeium"]
    assert t["usage"] == "in-use"
    assert len(t["devices"]) == 2
    assert t["devices_active"] == ["B"]


def test_a_finding_with_no_signal_still_counts_as_use():
    """Every finding written before the field existed, and every scanner not
    yet upgraded, sends no signal at all. Reading that as ambient would empty
    the in-use column across an entire estate on upgrade day, which looks
    exactly like everyone stopping work."""
    g = derive.graph_from([
        finding(tool="claude", surface="desktop", device="A", source="jamf_app"),
    ], {})

    assert g["tools"]["claude"]["usage"] == "in-use"
    assert g["tools"]["claude"]["devices_active"] == ["A"]


# ------------------------------------------------- device alias matching --
#
# `_device_aliases` used to compare every device key against every other,
# which was 99% of a graph build and quadratic in device count: 1.2s at four
# thousand devices, 33s at twenty thousand, 113s at forty. It is now an
# indexed lookup. These tests exist so that stays true AND stays identical -
# a faster function that merges a different set of machines would be worse
# than the slow one.


def _aliases_by_definition(devices):
    """The relation `_device_aliases` computes, written the obvious way.

    This IS the specification: a bare key merges into another key that is
    the same string with a prefix and a separator in front. Deliberately
    the slow pairwise form, so it can be read and believed. The shipped
    implementation has to agree with it on every input.
    """
    keys = [k for k in devices if k]
    lowered = {k: k.lower() for k in keys}
    out, ambiguous = {}, set()
    for bare in keys:
        low = lowered[bare]
        if len(low) < derive._MIN_ALIAS_KEY:
            continue
        for other in keys:
            if other == bare:
                continue
            o = lowered[other]
            if len(o) <= len(low):
                continue
            if any(o.endswith(sep + low) for sep in derive._ALIAS_SEPARATORS):
                if bare in out:
                    ambiguous.add(bare)
                out[bare] = other
    for k in ambiguous:
        out.pop(k, None)
    return {b: c for b, c in out.items() if c not in out}


@pytest.mark.parametrize("keys,why", [
    (["SERIAL1234", "LAP-SERIAL1234", "MAC-SERIAL1234"],
     "ambiguous: the tail of two prefixed keys, so neither merge is safe"),
    (["ABCDEF", "LAP-ABCDEF", "SITE-LAP-ABCDEF"],
     "a chain: merging A into B while B merges into C would strand A"),
    (["abcdef", "LAP-ABCDEF"], "case differs between sources"),
    (["SHORT", "LAP-SHORT"], "under the minimum: too short to be an identifier"),
    (["-ABCDEF", "ABCDEF"], "a separator with nothing in front of it"),
    (["", "LAP-ABCDEF", "ABCDEF"], "an empty key among real ones"),
    (["ASSET.ABC123", "ABC123", "WS_ABC123X"], "mixed separators"),
])
def test_the_alias_matcher_agrees_with_its_definition_on_hard_cases(keys, why):
    devices = {k: {} for k in keys}
    assert derive._device_aliases(devices) == _aliases_by_definition(devices), why


def test_the_alias_matcher_agrees_with_its_definition_on_random_estates():
    """Property test rather than examples. The rewrite is only worth having
    if it is indistinguishable from the definition, and the way to believe
    that is to try inputs nobody thought about."""
    import random
    import string

    rng = random.Random(20260901)
    seps = derive._ALIAS_SEPARATORS
    for _ in range(300):
        keys = set()
        for _ in range(rng.randint(4, 90)):
            core = "".join(rng.choice(string.ascii_uppercase + string.digits)
                           for _ in range(rng.randint(3, 9)))
            roll = rng.random()
            if roll < 0.45:
                keys.add(rng.choice(["LAP", "MAC", "WS", "ASSET", "IT"])
                         + rng.choice(seps) + core)
            elif roll < 0.6:
                keys.add(core.lower())
            else:
                keys.add(core)
        devices = {k: {} for k in keys}
        assert derive._device_aliases(devices) == _aliases_by_definition(devices), (
            "diverged on %r" % sorted(keys))


def test_a_large_estate_does_not_take_quadratic_time():
    """The guard against the regression that caused this.

    Twenty thousand device keys took the pairwise form roughly thirty
    seconds; indexed it is milliseconds. The bound is deliberately loose -
    this is here to catch a return to quadratic, which would miss it by two
    orders of magnitude, not to police a percentage drift on a shared CI
    runner.
    """
    import time

    devices = {}
    for i in range(20_000):
        devices["SERIAL%06d" % i] = {}
        if i % 3 == 0:
            devices["LAP-SERIAL%06d" % i] = {}

    started = time.perf_counter()
    out = derive._device_aliases(devices)
    elapsed = time.perf_counter() - started

    # Every third key is a bare form with exactly one prefixed partner.
    assert len(out) == len(range(0, 20_000, 3))
    assert elapsed < 5.0, "took %.1fs: the pairwise scan is back" % elapsed


# --------------------------------------------------------- the graph cache --


def test_a_slow_build_is_still_cached_afterwards():
    """The cache used to stamp an entry with the time the build STARTED, so
    an entry was born as old as the build that made it. On any deployment
    where a build took longer than CACHE_TTL that made it expired on
    arrival: the cache returned nothing, ever, and every page load paid full
    cost. The symptom is a portal that is uniformly slow rather than slow
    once, which reads like a sizing problem and is not one."""
    from app import main

    clock = {"t": 1000.0}
    real_time = main.time.time
    main.time.time = lambda: clock["t"]
    builds = {"n": 0}

    def slow_build():
        builds["n"] += 1
        clock["t"] += 40.0          # a build longer than the 30s TTL
        return {"v": builds["n"]}

    try:
        main._cache.pop("graph", None)
        main._cached("graph", 168, slow_build)
        clock["t"] += 1             # a second later, somebody loads the page
        value, _ = main._cached("graph", 168, slow_build)
    finally:
        main.time.time = real_time
        main._cache.pop("graph", None)

    assert builds["n"] == 1, "rebuilt a value it had just finished building"
    assert value == {"v": 1}


def test_two_readers_at_once_produce_one_build():
    """These endpoints are sync defs, so FastAPI runs them in a threadpool
    and two people refreshing genuinely overlap. Without single-flight that
    is two full reads of the same window for one answer - which is the shape
    that turns a busy morning into a slow portal."""
    import threading

    from app import main

    builds = {"n": 0}
    started = threading.Event()

    def slow_build():
        builds["n"] += 1
        started.set()
        time.sleep(0.3)             # long enough for the others to arrive
        return {"v": "shared"}

    main._cache.pop("graph", None)
    results = []
    threads = [threading.Thread(
        target=lambda: results.append(main._cached("graph", 168, slow_build)[0]))
        for _ in range(4)]
    try:
        threads[0].start()
        started.wait(timeout=5)     # make sure the first is inside the builder
        for t in threads[1:]:
            t.start()
        for t in threads:
            t.join(timeout=10)
    finally:
        main._cache.pop("graph", None)

    assert builds["n"] == 1, "%d builds for four concurrent readers" % builds["n"]
    assert results == [{"v": "shared"}] * 4


def test_one_refresh_drops_every_view_and_the_findings_behind_them():
    """Refresh means go and look again, for the whole page.

    Dropping only the view being asked for would rebuild it from a findings
    list that is still cached, so the button would redraw identical numbers
    and look like it had worked. Dropping ALL of them means the front end
    only has to say refresh once - and it has to, because saying it on each
    of the four made every request throw away the findings the previous one
    had just fetched, which cost four reads of identical data for one click.
    """
    from app import main

    now = time.time()
    for key in main._DERIVED_KEYS + ("findings",):
        main._cache[key] = {"value": 1, "at": now, "hours": 168}

    main._invalidate_all()

    assert not [k for k in main._DERIVED_KEYS if k in main._cache]
    assert "findings" not in main._cache


def test_a_refresh_burst_reads_the_log_store_once():
    """The regression this exists to stop.

    One click fetches graph, status, paste-guard and register. Only the
    first carries refresh; the rest must rebuild from the findings it
    fetched, not go back to the log store. Once a read costs seconds, the
    difference between one and four is the difference between a portal
    people use and one they wait for.
    """
    from app import main

    reads = {"n": 0}

    def fake_findings(hours, request=None):
        reads["n"] += 1
        return []

    real = main._findings
    main._findings = fake_findings
    try:
        main._invalidate_all()
        # graph arrives with refresh=true and clears everything.
        main._invalidate_all()
        main._findings_cached(168)          # graph
        main._findings_cached(168)          # status
        main._findings_cached(168)          # paste-guard
        main._findings_cached(168)          # register
    finally:
        main._findings = real
        main._invalidate_all()

    assert reads["n"] == 1, "%d reads for one refresh" % reads["n"]
