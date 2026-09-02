"""The candidates queue: observed-but-undefined tools, awaiting a human.

The properties under test: a reporting credential can suggest a tool but
never define one; the receiver re-validates every field rather than
trusting the scanner that posted it; a dismissal is a stored decision that
a rerun cannot reopen; and adding a registry entry resolves the candidate
that suggested it, closing the discovery loop without a second decision.
"""

import os

os.environ.setdefault("AUTH_TOKEN", "test-token-for-ci")

import pytest
from fastapi.testclient import TestClient

from app import main
from app import state as state_mod
from app.main import app

client = TestClient(app)

AUTH = {"Authorization": "Bearer test-token-for-ci"}
ADMIN = {"Authorization": "Bearer admin-test-token"}

CANDIDATE = {
    "kind": "domain",
    "name": "Mystery AI",
    "vendor": "Mystery Labs",
    "category": "assistant",
    "confidence": "high",
    "domains": ["mystery-ai.example"],
    "devices": 3,
    "evidence": "seen in fleet DNS over 7d",
}


@pytest.fixture
def managed(tmp_path, monkeypatch):
    st = state_mod.State(str(tmp_path / "state.db"))
    monkeypatch.setattr(main, "STATE", st)
    monkeypatch.setattr(main, "_EXPECTED_ADMIN", b"Bearer admin-test-token")
    yield st


def _post(body=None, headers=AUTH):
    return client.post("/candidates", headers=headers,
                       json=body or {"candidates": [CANDIDATE]})


# ---------------------------------------------------------------- the loop --


def test_a_posted_candidate_reaches_the_admin_queue(managed):
    resp = _post()
    assert resp.status_code == 200 and resp.json() == {"accepted": 1}
    (c,) = client.get("/admin/candidates", headers=ADMIN).json()["candidates"]
    assert c["key"] == "domain:mystery-ai"
    assert c["name"] == "Mystery AI"
    assert c["domains"] == ["mystery-ai.example"]
    assert c["devices"] == 3
    assert c["source"] == "shared-token"
    assert c["resolved"] is False
    assert c["dismissed_at"] is None


def test_a_rerun_refreshes_counts_but_not_first_seen(managed):
    _post()
    first = client.get("/admin/candidates", headers=ADMIN).json()["candidates"][0]
    _post({"candidates": [{**CANDIDATE, "devices": 9, "confidence": "medium"}]})
    (c,) = client.get("/admin/candidates", headers=ADMIN).json()["candidates"]
    assert c["devices"] == 9 and c["confidence"] == "medium"
    assert c["first_seen"] == first["first_seen"]


def test_dismissal_survives_the_next_run(managed):
    _post()
    resp = client.post("/admin/candidates/domain:mystery-ai/dismiss",
                       headers=ADMIN)
    assert resp.status_code == 200
    _post({"candidates": [{**CANDIDATE, "devices": 12}]})
    (c,) = client.get("/admin/candidates", headers=ADMIN).json()["candidates"]
    assert c["dismissed_at"] is not None
    assert c["devices"] == 12  # still tracked, still dismissed


def test_dismissing_twice_is_a_404_not_a_second_decision(managed):
    _post()
    client.post("/admin/candidates/domain:mystery-ai/dismiss", headers=ADMIN)
    resp = client.post("/admin/candidates/domain:mystery-ai/dismiss",
                       headers=ADMIN)
    assert resp.status_code == 404


def test_adding_the_registry_entry_resolves_the_candidate(managed):
    """The closing of the loop: define the tool the candidate suggested and
    the candidate stops being a question."""
    _post()
    entry = {
        "id": "mystery-ai", "name": "Mystery AI", "vendor": "Mystery Labs",
        "category": "assistant", "domains": ["mystery-ai.example"],
    }
    resp = client.put("/admin/registry-entries", headers=ADMIN,
                      json={"entries": [entry]})
    assert resp.status_code == 200, resp.text
    (c,) = client.get("/admin/candidates", headers=ADMIN).json()["candidates"]
    assert c["resolved"] is True


# ----------------------------------------------------------------- the gate --


def test_the_key_is_computed_not_taken(managed):
    """Capitalisation variants land on one row, and a caller cannot supply
    its own key at all (extra fields are refused)."""
    _post({"candidates": [{**CANDIDATE, "name": "MYSTERY ai"}]})
    _post()
    got = client.get("/admin/candidates", headers=ADMIN).json()["candidates"]
    assert len(got) == 1
    assert _post({"candidates": [{**CANDIDATE, "key": "evil"}]}).status_code == 422


def test_the_receiver_validates_what_the_scanner_claims_it_validated(managed):
    bad = [
        {**CANDIDATE, "name": "<script>alert(1)</script>"},
        {**CANDIDATE, "vendor": "a\nb"},
        {**CANDIDATE, "kind": "surprise"},
        {**CANDIDATE, "confidence": "sure"},
        {**CANDIDATE, "domains": ["Mystery-AI.Example"]},
        {**CANDIDATE, "domains": ["bad domain"]},
    ]
    for c in bad:
        assert _post({"candidates": [c]}).status_code == 422, c
    assert client.get("/admin/candidates",
                      headers=ADMIN).json()["candidates"] == []


def test_a_reporting_credential_cannot_read_or_dismiss(managed):
    _post()
    assert client.get("/admin/candidates", headers=AUTH).status_code == 401
    assert client.post("/admin/candidates/domain:mystery-ai/dismiss",
                       headers=AUTH).status_code == 401


def test_unauthenticated_posts_are_refused(managed):
    assert _post(headers={}).status_code == 401


def test_classic_mode_has_no_candidates_surface():
    assert _post().status_code == 404
    assert client.get("/admin/candidates", headers=ADMIN).status_code == 404


# ------------------------------------------- MCP servers from the endpoint --
# The collectors are registry-driven and cannot report an unknown tool -
# except the MCP scan, which sends the raw server names from a machine's
# config files as evidence. Those names feed the same queue.


def _report_mcp(device="mac-1", evidence=".claude.json mcpServers: figma,internal-db",
                tool="claude-code-mcp"):
    return client.post("/report", headers=AUTH, json={
        "tool": tool, "surface": "mcp", "device": device,
        "severity": "info", "evidence": evidence})


def _queue():
    return {c["key"]: c
            for c in client.get("/admin/candidates",
                                headers=ADMIN).json()["candidates"]}


def test_an_unknown_mcp_server_becomes_a_candidate(managed):
    assert _report_mcp().status_code == 200
    q = _queue()
    assert set(q) == {"mcp_server:figma", "mcp_server:internal-db"}
    c = q["mcp_server:figma"]
    assert c["kind"] == "mcp_server" and c["name"] == "figma"
    assert c["source"] == "endpoint" and c["devices"] == 1
    assert "claude-code-mcp config" in c["evidence"]
    assert c["resolved"] is False


def test_devices_count_distinct_machines_not_reports(managed):
    _report_mcp(device="mac-1")
    _report_mcp(device="mac-1")  # a re-scan is not a second machine
    assert _queue()["mcp_server:figma"]["devices"] == 1
    _report_mcp(device="mac-2")
    assert _queue()["mcp_server:figma"]["devices"] == 2


def test_a_server_named_after_a_registry_tool_is_not_a_discovery(
        managed, monkeypatch):
    monkeypatch.setattr(main, "_REGISTRY_IDS", {"figma"})
    _report_mcp()
    assert set(_queue()) == {"mcp_server:internal-db"}


def test_the_legacy_tool_name_format_is_read_too(managed):
    _report_mcp(tool="claude-code-mcp:figma", evidence="")
    assert "mcp_server:figma" in _queue()


def test_an_odd_server_name_is_skipped_not_a_bounced_finding(managed):
    resp = _report_mcp(evidence=".x mcpServers: <script>,figma")
    assert resp.status_code == 200
    assert set(_queue()) == {"mcp_server:figma"}


def test_an_entry_with_the_servers_slug_resolves_it(managed):
    _report_mcp()
    managed.upsert_registry_entry("internal-db", {"id": "internal-db"})
    q = _queue()
    assert q["mcp_server:internal-db"]["resolved"] is True
    assert q["mcp_server:figma"]["resolved"] is False


def test_a_dismissed_server_keeps_its_record_and_its_decision(managed):
    _report_mcp(device="mac-1")
    client.post("/admin/candidates/mcp_server:figma/dismiss", headers=ADMIN)
    _report_mcp(device="mac-2")
    c = _queue()["mcp_server:figma"]
    assert c["dismissed_at"] is not None
    assert c["devices"] == 2


# ---------------------------------------------------------------- processes --
#
# The surface that never got a queue. An unrecognised process reaching a model
# was drawn on the Agentic AI view as "no tool we know" and then discarded, so
# the only way it ever became known was somebody spotting it on a page and
# editing the registry by hand. The estate observed it; the estate should ask.

def _dns(process, host="api.anthropic.com", device="D1"):
    return {"tool": "claude", "surface": "network", "os": "macos",
            "account_domain": "", "device": device, "user": "",
            "evidence": "DNS lookup for %s (via %s)" % (host, process),
            "severity": "info", "reported_at": "2026-09-02T10:00:00Z"}


def test_a_process_the_registry_cannot_name_becomes_a_candidate(managed, monkeypatch):
    monkeypatch.setattr(main, "_KNOWN_PROCESSES", {"claude", "google chrome"})
    r = client.post("/report", json=_dns("nightly-digest"), headers=AUTH)
    assert r.status_code == 200
    rows = client.get("/admin/candidates", headers=ADMIN).json()["candidates"]
    got = [c for c in rows if c["kind"] == "process"]
    assert [c["name"] for c in got] == ["nightly-digest"]
    # The evidence travels with it: a human decides what it is, and cannot
    # do that from a bare name. Compared whole rather than by substring -
    # a substring test on something URL-shaped passes on a value that merely
    # contains it somewhere.
    assert got[0]["evidence"] == ("DNS lookup for api.anthropic.com"
                                  " (via nightly-digest)")


@pytest.mark.parametrize("proc,why", [
    ("claude", "a binary the registry names is the tool, not a question"),
    ("Google Chrome Helper", "a browser is the ordinary case"),
    ("systemd-resolved", "a resolver names nothing to ask about"),
    ("Update.exe", "Squirrel's updater names the framework, not the app"),
])
def test_the_things_that_are_not_questions_are_not_queued(managed, monkeypatch, proc, why):
    monkeypatch.setattr(main, "_KNOWN_PROCESSES", {"claude", "google chrome"})
    client.post("/report", json=_dns(proc), headers=AUTH)
    rows = client.get("/admin/candidates", headers=ADMIN).json()["candidates"]
    assert [c for c in rows if c["kind"] == "process"] == [], why


def test_the_same_process_on_many_devices_is_one_question(managed, monkeypatch):
    """A review queue that asks the same question once per machine is a
    queue nobody reads."""
    monkeypatch.setattr(main, "_KNOWN_PROCESSES", {"claude"})
    for d in ("D1", "D2", "D3"):
        client.post("/report", json=_dns("nightly-digest", device=d), headers=AUTH)
    rows = client.get("/admin/candidates", headers=ADMIN).json()["candidates"]
    assert len([c for c in rows if c["kind"] == "process"]) == 1


def test_a_process_candidate_survives_the_receivers_own_validation(managed, monkeypatch):
    """Names that fail the candidate text rule are skipped rather than
    refused: they are evidence on a valid finding, and a finding must never
    bounce because a process has an odd name."""
    monkeypatch.setattr(main, "_KNOWN_PROCESSES", {"claude"})
    r = client.post("/report", json=_dns("weird\x01name"), headers=AUTH)
    assert r.status_code == 200
    rows = client.get("/admin/candidates", headers=ADMIN).json()["candidates"]
    assert [c for c in rows if c["kind"] == "process"] == []


def test_a_name_that_identifies_no_program_is_recorded_as_such(managed, monkeypatch):
    """Distinct from a dismissal. Dismissing curl says "not a tool" and curl
    is still a real process worth showing; saying firezone-client-tunnel
    names nothing is a fact about the NAME, and every view that reads a
    process name needs it."""
    # A name NOT on the shipped floor - firezone-client-tunnel is on it now,
    # so it never becomes a candidate and could not exercise this path. The
    # long tail is what this disposition is for.
    monkeypatch.setattr(main, "_KNOWN_PROCESSES", {"claude"})
    client.post("/report", json=_dns("acme-zt-tunnel"), headers=AUTH)
    key = "process:acme-zt-tunnel"
    r = client.post("/admin/candidates/%s/not-attributable" % key, headers=ADMIN)
    assert r.status_code == 200
    got = client.get("/admin/candidates/not-attributable", headers=ADMIN).json()
    assert got["names"] == ["acme-zt-tunnel"]


def test_a_ruled_out_name_is_not_asked_about_again(managed, monkeypatch):
    """A review queue that re-asks a settled question is one nobody reads."""
    monkeypatch.setattr(main, "_KNOWN_PROCESSES", {"claude"})
    client.post("/report", json=_dns("corp-tunnel"), headers=AUTH)
    client.post("/admin/candidates/process:corp-tunnel/not-attributable",
                headers=ADMIN)
    # Same process, seen again on another device.
    client.post("/report", json=_dns("corp-tunnel", device="D2"), headers=AUTH)
    rows = client.get("/admin/candidates", headers=ADMIN).json()["candidates"]
    open_rows = [c for c in rows
                 if c["kind"] == "process" and not c.get("dismissed_at")]
    assert open_rows == []


def test_only_a_process_can_be_called_unattributable(managed):
    """The claim is about a name identifying no program. A domain is not a
    name in that sense, and neither is an MCP server."""
    client.post("/candidates", headers=AUTH,
                json={"candidates": [dict(CANDIDATE)]})
    rows = client.get("/admin/candidates", headers=ADMIN).json()["candidates"]
    key = rows[0]["key"]
    r = client.post("/admin/candidates/%s/not-attributable" % key, headers=ADMIN)
    assert r.status_code == 422
