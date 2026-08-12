"""The register lists what the registry knows, not only what was seen.

A register built from observations alone is the same mistake as a dashboard
that counts reporting sources and not silent ones: an estate looks complete
because the thing you cannot see is also the thing you did not list.

Two directions of gap, and the register has to show both.

A tool in the registry that nothing reported is not evidence it is unused. It
may be in use somewhere nothing reports from, and it may simply not have been
used in the lookback window. It gets a row with empty counts.

A tool observed that is NOT in the registry is the more urgent one: something
is in use that governance has never considered. It gets a row and a flag.

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

def test_a_registry_tool_with_no_findings_is_still_listed():
    """The regression. Building from findings alone would drop this row."""
    rows = register_from([_f()], REGISTRY, DOMAIN_MAP)

    grok = _row(rows, "grok")
    assert grok["in_registry"] is True
    assert grok["observed"] is False
    assert grok["devices"] == 0
    assert grok["first_seen"] == ""


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


def test_csv_includes_unobserved_tools():
    """The export has to carry the same gaps as the page. A CSV of observed
    tools only, handed to someone reviewing coverage, is the exact thing this
    register exists to stop."""
    rows = register_from([_f()], REGISTRY, DOMAIN_MAP)
    out = register_csv(rows)
    assert "grok" in out


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
