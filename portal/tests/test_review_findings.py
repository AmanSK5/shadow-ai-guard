"""The contradictions a full review of a live deployment turned up.

Every case here was reported as "these two numbers describe the same
thing and disagree", against real data none of the existing tests
carried: an estate large enough for a person to be seen on two surfaces,
a corporate domain added after an agent last shipped, a vendor whose
users sign in on the vendor's own domain, a device that upgraded the
guard mid-window.

The fixture is synthetic and reproduces the shape, not the size. Where a
finding had exact counts they are asserted against the arithmetic the
report gave, so a regression fails with the same sum the reviewer
noticed rather than a vague inequality.
"""

import os

os.environ.setdefault("PORTAL_AUTH", "none")

from app import derive, evidence, paste_guard

CORP = ["corp.example", "corp-two.example"]

REG = {"tools": [
    {"id": "chatgpt", "name": "ChatGPT", "domains": ["chatgpt.com"]},
    {"id": "claude", "name": "Claude", "domains": ["claude.ai"]},
    {"id": "fireflies", "name": "Fireflies", "domains": ["fireflies.ai"]},
]}


def _f(**kw):
    f = {"tool": "chatgpt", "surface": "browser", "os": "macos",
         "account_domain": "", "device": "DEV-1", "user": "",
         "evidence": "", "severity": "info", "source": "collector-macos",
         "reported_at": "2026-08-27T10:00:00Z", "device_name": ""}
    f.update(kw)
    return f


def _personal(**kw):
    return _f(severity="warn", **kw)


# ------------------------------------------------- personal accounts --


def test_a_configured_corporate_domain_is_not_a_personal_account():
    """The reporter judges severity against the domain list it held at
    the time, and a browser extension bakes that list into its policy -
    so a domain added in Settings afterwards keeps arriving flagged.
    The review found one of the operator's OWN corporate domains listed
    under personal accounts, and travelling into the shareable budget
    report."""
    findings = [
        _personal(account_domain="corp-two.example", device="DEV-1"),
        _personal(account_domain="gmail.example", device="DEV-2"),
    ]
    rows = derive.personal_accounts_from(findings, {}, CORP)
    assert [r["account_domain"] for r in rows] == ["gmail.example"]


def test_subdomains_and_spelling_of_a_corporate_domain_are_covered():
    findings = [
        _personal(account_domain="mail.corp.example", device="D1"),
        _personal(account_domain="CORP.EXAMPLE", device="D2"),
        _personal(account_domain="www.corp.example", device="D3"),
        # Not a subdomain - a different registrable domain that merely
        # ends with the same letters.
        _personal(account_domain="notcorp.example", device="D4"),
    ]
    rows = derive.personal_accounts_from(findings, {}, ["corp.example"])
    assert [r["device"] for r in rows] == ["D4"]


def test_a_tools_own_domain_is_not_personal_use_of_that_tool():
    """Four rows on the meeting-notes vendor's own domain were counted
    as personal-account use of the licence being paid for, and were all
    four of that licence's personal-account uses in the finance report."""
    findings = [
        _personal(tool="fireflies", account_domain="fireflies.ai",
                  device="D1"),
        _personal(tool="fireflies", account_domain="gmail.example",
                  device="D2"),
        # The same domain on a DIFFERENT tool is still personal: signing
        # into ChatGPT with a fireflies.ai account is not a work account.
        _personal(tool="chatgpt", account_domain="fireflies.ai",
                  device="D3"),
    ]
    rows = derive.personal_accounts_from(
        findings, {}, CORP, derive.tool_domains_from(REG))
    assert sorted((r["tool"], r["device"]) for r in rows) == [
        ("chatgpt", "D3"), ("fireflies", "D2")]


def test_the_exclusions_reach_the_evidence_document_too():
    """The ISO document and the page must not disagree about how many
    personal accounts the estate has."""
    findings = [
        _personal(account_domain="corp-two.example", device="D1"),
        _personal(tool="fireflies", account_domain="fireflies.ai",
                  device="D2"),
        _personal(account_domain="gmail.example", device="D3"),
    ]
    rows = derive.personal_accounts_from(
        findings, {}, CORP, derive.tool_domains_from(REG))
    doc = evidence.evidence_from([], {}, rows, [], {}, hours=168)
    assert len(rows) == 1
    assert doc["personal_accounts"] == 1


# ------------------------------------------------------ paste guard --


def _heartbeat(device, version, at):
    return _f(tool="paste-guard", source="paste_guard", surface="browser",
              device=device, reported_at=at, severity="info",
              evidence="heartbeat version=%s mode=warn reason=installed"
                       % version)


def test_a_device_that_upgraded_appears_in_one_version_bucket():
    """"39 devices running the guard" sat directly above a version split
    summing to 41: two devices had reported two versions inside the
    window and were counted in both buckets."""
    findings = [
        _heartbeat("D1", "1.3.0", "2026-08-20T10:00:00Z"),
        _heartbeat("D1", "1.4.0", "2026-08-27T10:00:00Z"),
        _heartbeat("D2", "1.3.0", "2026-08-27T10:00:00Z"),
    ]
    out = paste_guard.paste_guard_from(findings, {})
    assert out["guard_devices"] == 2
    assert sum(v["devices"] for v in out["guard_versions"]) == 2
    # The latest heartbeat wins: the fleet is where it is now, not
    # everywhere it has been.
    assert {v["version"]: v["devices"] for v in out["guard_versions"]} == {
        "1.4.0": 1, "1.3.0": 1}
    assert sum(m["devices"] for m in out["guard_modes"]) == 2


def test_an_override_is_not_a_second_paste():
    """guard.js reports the interception and then a second finding when
    the person proceeds, so "8 paste events, 4 overridden" on the ISO
    page described four pastes."""
    findings = [
        _f(source="paste_guard", severity="warn",
           evidence="paste warned: aws_access_key"),
        _f(source="paste_guard", severity="warn",
           evidence="paste overridden: aws_access_key"),
        _f(source="paste_guard", severity="warn",
           evidence="paste blocked: private_key"),
    ]
    out = paste_guard.paste_guard_from(findings, {})
    assert (out["warned"], out["overridden"], out["blocked"]) == (1, 1, 1)
    # One warned interception plus one blocked one. The override is the
    # outcome of a warning already counted.
    assert out["events"] == 2
    assert sum(r["events"] for r in out["rows"]) == 2
    doc = evidence.evidence_from([], {}, [], [], out, hours=168)
    assert doc["paste_events"] == 2
    assert doc["paste_overridden"] == 1


# ------------------------------------------------------ mcp servers --


def test_servers_differing_only_in_case_are_one_server():
    findings = [
        _f(surface="mcp", device="D1",
           evidence=".claude.json mcpServers: Figma"),
        _f(surface="mcp", device="D2",
           evidence=".claude.json mcpServers: figma"),
    ]
    rows = derive.mcp_from(findings)
    assert len(rows) == 1
    assert rows[0]["devices"] == ["D1", "D2"]
    # The spelling somebody actually wrote is the one shown.
    assert rows[0]["server"] == "Figma"
