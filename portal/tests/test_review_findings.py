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

import json
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


# ------------------------------------------------- one machine, one device --


def test_a_machine_reported_under_two_keys_is_one_device():
    """The endpoint collector reports an asset-tagged serial and the
    browser extension reports the bare one, so one laptop arrived as two
    devices: two cards under one hostname, tools split across both, and
    the review counted 69 cards over 65 distinct names."""
    findings = [
        _f(device="TGT-ABC123", device_name="LAPTOP-1", tool="claude-code",
           surface="cli", source="collector-macos"),
        _f(device="ABC123", device_name="LAPTOP-1", tool="chatgpt",
           surface="browser", source="browser_extension"),
    ]
    devices, identities, tools, _b, _u = derive.build(findings, {}, {})
    assert list(devices) == ["TGT-ABC123"]
    d = devices["TGT-ABC123"]
    assert d["tools"] == {"claude-code", "chatgpt"}
    assert d["aliases"] == {"ABC123"}
    assert d["findings"] == 2
    # The tool edges follow the surviving key, or a tool page would link
    # to a device that no longer exists.
    assert tools["chatgpt"]["devices"] == {"TGT-ABC123"}


def test_the_person_the_estate_already_knows_is_not_no_identity():
    """15 of 34 personal-account rows read "no identity" for machines the
    Devices view named on the row above - the browser extension reports
    no user, and the join never asked the device."""
    findings = [
        _f(device="TGT-ABC123", user="alice", tool="claude-code",
           surface="cli", source="collector-macos"),
        _f(device="ABC123", tool="chatgpt", surface="browser",
           severity="warn", account_domain="gmail.example",
           source="browser_extension"),
    ]
    graph = derive.graph_from(findings, {}, {"TGT-ABC123": "alice"})
    rows = graph["personal_accounts"]
    assert len(rows) == 1
    assert rows[0]["user"] == "alice"
    # And it says the attribution came from the machine, not the source.
    assert rows[0]["user_via"] == "device"
    assert rows[0]["device"] == "TGT-ABC123"


def test_an_ambiguous_or_short_key_is_left_alone():
    """Merging the wrong two machines is worse than showing two cards."""
    findings = [
        _f(device="AB1", tool="claude"),          # too short to be an id
        _f(device="TGT-AB1", tool="claude"),
        _f(device="SERIAL7", tool="claude"),      # tail of two prefixed keys
        _f(device="TGT-SERIAL7", tool="claude"),
        _f(device="TNG-SERIAL7", tool="claude"),
    ]
    devices, _i, _t, _b, _u = derive.build(findings, {}, {})
    assert set(devices) == {"AB1", "TGT-AB1", "SERIAL7",
                            "TGT-SERIAL7", "TNG-SERIAL7"}


# ---------------------------------------- one definition of a tool in use --


def test_an_mcp_finding_is_the_tool_it_configures():
    """The register folds <tool>-mcp into its parent and the estate views
    did not, so the two pages disagreed about how many tools exist: "23
    in use, 0 not in registry" beside "26 tools", three of which were in
    no registry."""
    findings = [
        _f(tool="claude-code", surface="cli", device="D1"),
        _f(tool="claude-code-mcp", surface="mcp", device="D1",
           evidence=".claude.json mcpServers: figma"),
        _f(tool="cursor-mcp:figma", surface="mcp", device="D2",
           evidence=".cursor/mcp.json mcpServers"),
    ]
    graph = derive.graph_from(findings, {}, {})
    assert set(graph["tools"]) == {"claude-code", "cursor"}
    # The surface still lands, so "claude-code, seen on cli and mcp" is
    # still sayable - it is the pseudo-tool that goes, not the evidence.
    assert set(graph["tools"]["claude-code"]["surfaces"]) == {"cli", "mcp"}
    # And the servers keep their own view, keyed as the collectors report.
    assert [r["server"] for r in graph["mcp_servers"]] == ["figma"]


# ------------------------------------- a failed read is not a clean estate --


def test_the_shell_says_so_when_the_read_failed():
    """Five viewer accounts on the reviewed deployment were refused by
    the log store and shown zeros under "None seen. That is a result,
    not an absence of one." - the product reporting a clean estate it
    had never looked at."""
    index = (os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    html = open(os.path.join(index, "app", "static", "index.html")).read()
    # A banner above every view, not on the one page that checked.
    assert "function loadBanner()" in html
    assert "this page is not an answer" in html
    assert "const tb = tabbar() + loadBanner();" in html
    # The confident lines are gated on the read having worked.
    assert "const dataOk = () => !loadError;" in html
    for gated in ("None seen. That is a result",
                  "also has a collector reporting",
                  "Nothing outstanding in this window",
                  "That is a real answer for a small estate"):
        before = html.split(gated)[0]
        assert "dataOk()" in before[-400:], gated
    # And it names the fix a self-hoster would otherwise have to find.
    assert "RECEIVER_ADMIN_TOKEN" in html


# ------------------------------------------------- the identity map, in app --


def test_a_hostname_that_names_its_owner_is_proposed():
    """Five devices on the reviewed estate had their owner's name in the
    hostname - two of those people already in the identity list - and sat
    unattributed because the only rule looked at local usernames."""
    devices = {
        "D1": {"local_users": set(), "device_name": "Jo-Bloggs-MacBook-Pro"},
        "D2": {"local_users": set(), "device_name": "DESKTOP-9Z1"},
        # Too short a name to match inside a label by anything but luck.
        "D3": {"local_users": set(), "device_name": "ALIENWARE-15"},
    }
    matched, unmatched = derive.suggest_identity_rows(
        devices, {"jo.bloggs": {}, "al": {}})
    assert [(m["key"], m["identity"]) for m in matched] == [("D1", "jo.bloggs")]
    assert {u["key"] for u in unmatched} == {"D2", "D3"}
    # The proposal says why, so a reviewer can judge it.
    assert "hostname" in matched[0]["via"]


def test_two_people_matching_one_hostname_propose_neither():
    devices = {"D1": {"local_users": set(),
                      "device_name": "jo.bloggs-and-sam.smith-shared"}}
    matched, unmatched = derive.suggest_identity_rows(
        devices, {"jo.bloggs": {}, "sam.smith": {}})
    assert matched == []
    assert [u["key"] for u in unmatched] == ["D1"]


def test_a_local_username_still_wins_over_the_hostname():
    devices = {"D1": {"local_users": {"sam.smith"},
                      "device_name": "Jo-Bloggs-MacBook"}}
    matched, _u = derive.suggest_identity_rows(
        devices, {"jo.bloggs": {}, "sam.smith": {}})
    assert matched[0]["identity"] == "sam.smith"


# ------------------------------------- reading without the operator's seat --


def test_a_viewer_falls_back_to_the_portals_own_log_store():
    """The 403 message has always said "or set LOKI_URL by env" as the
    fix, and raising instead meant that advice did not work: a portal
    with its own store still refused every read-only account."""
    from unittest.mock import patch

    from app import main as pm
    from app import managed as mg

    def refuse(*a, **k):
        raise mg.ReceiverError(403, "read-only")

    with patch.object(pm, "LOGIN_MODE", True), \
            patch.object(pm, "RECEIVER_URL", "http://receiver:8080"), \
            patch.object(pm, "RECEIVER_ADMIN_TOKEN", ""), \
            patch.object(pm, "LOKI_URL", "http://loki:3100"), \
            patch.object(pm, "LOKI_USERNAME", "reader"), \
            patch.object(pm.managed, "receiver_request", refuse):
        pm._log_store_cache.update(at=0.0, data=None)

        class Req:
            cookies = {"aiguard_session": "aigt_viewer"}

        url, user, _pw, source = pm._log_store(Req())
    assert (url, user, source) == ("http://loki:3100", "reader", "env")


def test_without_any_store_of_its_own_it_still_says_what_to_configure():
    from unittest.mock import patch

    import pytest
    from fastapi import HTTPException

    from app import main as pm
    from app import managed as mg

    def refuse(*a, **k):
        raise mg.ReceiverError(403, "read-only")

    with patch.object(pm, "LOGIN_MODE", True), \
            patch.object(pm, "RECEIVER_URL", "http://receiver:8080"), \
            patch.object(pm, "RECEIVER_ADMIN_TOKEN", ""), \
            patch.object(pm, "LOKI_URL", ""), \
            patch.object(pm.managed, "receiver_request", refuse):
        pm._log_store_cache.update(at=0.0, data=None)

        class Req:
            cookies = {"aiguard_session": "aigt_viewer"}

        with pytest.raises(HTTPException) as e:
            pm._log_store(Req())
    assert e.value.status_code == 403
    assert "RECEIVER_ADMIN_TOKEN" in e.value.detail


def test_diagnostics_counts_tools_not_tools_with_domains(tmp_path, monkeypatch):
    """Reported as "the registry is 28 here and 32 there", and it cost a
    reviewer and a maintainer real time hunting a stale file. Both
    numbers were right: this row counted only the tools carrying a
    domain, and called it "Tools"."""
    from app import main as pm

    reg = tmp_path / "registry.json"
    reg.write_text(json.dumps({"version": 1, "tools": [
        {"id": "chatgpt", "name": "ChatGPT", "domains": ["chatgpt.com"]},
        {"id": "claude", "name": "Claude", "domains": ["claude.ai"]},
        # Found by its config file, not by a domain - and still a tool.
        {"id": "claude-code", "name": "Claude Code", "domains": []},
    ]}))
    monkeypatch.setattr(pm, "REGISTRY_PATH", str(reg))
    runtime = pm.diagnostics(_=None)["runtime"]
    assert runtime["registry_tools"] == 3
    assert runtime["registry_tools_with_domains"] == 2
    assert runtime["registry_loaded"] is True
