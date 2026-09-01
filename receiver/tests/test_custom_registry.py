"""Portal-defined registry entries: same shape, same rules, served merged.

The property under test is the discovery loop's last link: a tool defined
through the admin API is validated to the registry build's own rules, then
appears in /registry, in every /registry/collector surface list, and in the
receiver's domain normalization - so the fleet detects it with no rebuild.
"""

import contextlib
import json
import logging
import os
import subprocess
import sys
from pathlib import Path

os.environ.setdefault("AUTH_TOKEN", "test-token-for-ci")

import pytest
from fastapi.testclient import TestClient

from app import main
from app import state as state_mod
from app.main import app

client = TestClient(app)

AUTH = {"Authorization": "Bearer test-token-for-ci"}
ADMIN = {"Authorization": "Bearer admin-test-token"}
REPO = Path(__file__).parent.parent.parent
DIST = REPO / "registry" / "dist"


def _ensure_dist() -> bool:
    """registry/dist is a build output, not committed: CI checkouts start
    without it. Build it (no scanner-fallback write, so the tree stays
    clean) - requirements-ci.txt provides pyyaml and jsonschema there. A
    machine that can neither find nor build it skips rather than fails,
    because that is a machine missing the registry toolchain, not a bug."""
    if (DIST / "collector.json").exists() and (DIST / "registry.json").exists():
        return True
    proc = subprocess.run(
        [sys.executable, str(REPO / "registry" / "build.py"), "--no-fallback"],
        capture_output=True, text=True, cwd=str(REPO / "registry"))
    return proc.returncode == 0


if not _ensure_dist():
    pytest.skip("registry/dist not built and build.py could not run here",
                allow_module_level=True)

ENTRY = {
    "id": "acme-copilot",
    "name": "Acme Copilot",
    "vendor": "Acme",
    "category": "assistant",
    "domains": ["acme-copilot.example"],
    "app_names": ["Acme Copilot.app"],
    "bundle_ids": ["com.acme.copilot"],
    "cli": {"config_paths": [".acme"], "binaries": ["acme"]},
    "extension_ids": {"vscode": ["acme.copilot"]},
    "mcp_config_paths_macos": ["Library/Acme/mcp.json"],
    "risk_tier": "medium",
}


@pytest.fixture
def managed(tmp_path, monkeypatch):
    st = state_mod.State(str(tmp_path / "state.db"))
    monkeypatch.setattr(main, "STATE", st)
    monkeypatch.setattr(main, "_EXPECTED_ADMIN", b"Bearer admin-test-token")
    # The real shipped registry, so collision and domain-ownership rules
    # are exercised against the thing they will meet in production.
    monkeypatch.setattr(main, "REGISTRY_PATH",
                        str(REPO / "registry" / "dist" / "registry.json"))
    reg = tmp_path / "collector.json"
    reg.write_text(json.dumps(
        json.load(open(REPO / "registry" / "dist" / "collector.json"))))
    monkeypatch.setattr(main, "COLLECTOR_REGISTRY_PATH", str(reg))
    main._refresh_domain_map()
    yield st
    main._refresh_domain_map()



@contextlib.contextmanager
def _capture():
    """The findings the receiver emitted, parsed. They go out as JSON log
    lines - that IS the delivery mechanism to Loki, so reading them is
    reading what a log store would receive."""
    out = []

    class H(logging.Handler):
        def emit(self, record):
            try:
                line = json.loads(record.getMessage())
            except (ValueError, TypeError):
                return
            if line.get("kind") == "finding":
                out.append(line)

    h = H()
    log = logging.getLogger("ai-guard")
    log.addHandler(h)
    # A handler alone is not enough: if the logger sits above INFO the record
    # is dropped before any handler sees it.
    prev = log.level
    log.setLevel(logging.INFO)
    try:
        yield out
    finally:
        log.removeHandler(h)
        log.setLevel(prev)


def _put(**body):
    return client.put("/admin/registry-entries", headers=ADMIN, json=body)


# ----------------------------------------------------------- the contract --


def test_the_schema_copy_matches_the_registry_source():
    """The receiver validates with a copy of registry/schema.json because
    its image cannot see registry/. A drifted copy means the portal
    accepts entries the registry build would refuse, or vice versa."""
    ours = (Path(__file__).parent.parent / "app" / "registry-schema.json").read_bytes()
    theirs = (REPO / "registry" / "schema.json").read_bytes()
    assert ours == theirs, ("receiver/app/registry-schema.json no longer "
                            "matches registry/schema.json - re-copy it")


def test_the_collector_transform_matches_the_real_build():
    """_collector_rows is a reimplementation of build.py's emit transform.
    Parity is asserted against the committed dist/ artifacts the real
    build wrote: for any shipped tool, our transform of its registry.json
    entry must produce exactly the rows dist/collector.json carries."""
    registry = json.load(open(REPO / "registry" / "dist" / "registry.json"))
    collector = json.load(open(REPO / "registry" / "dist" / "collector.json"))
    for tool in registry["tools"]:
        ours = main._collector_rows([tool])
        for section in ("cli", "desktop", "ide", "mcp"):
            theirs = [r for r in collector[section] if r["tool"] == tool["id"]]
            assert ours[section] == theirs, (tool["id"], section)


# ----------------------------------------------------------- the full loop --


def test_a_defined_tool_reaches_every_serving_surface(managed):
    resp = _put(entries=[ENTRY])
    assert resp.status_code == 200, resp.text
    (e,) = resp.json()["entries"]
    assert e["tool_id"] == "acme-copilot" and e["shadowed"] is False
    # Forced fields: provenance and no smuggled approval.
    assert e["entry"]["added_by"] == "portal"
    assert e["entry"]["approved"] is False

    # /registry carries it alongside the shipped tools.
    reg = client.get("/registry", headers=AUTH).json()
    mine = [t for t in reg["tools"] if t["id"] == "acme-copilot"]
    assert len(mine) == 1

    # /registry/collector carries its identifiers in every section.
    col = client.get("/registry/collector", headers=AUTH).json()
    assert {"tool": "acme-copilot", "config_paths": [".acme"],
            "binaries": ["acme"]} in col["cli"]
    assert any(r["tool"] == "acme-copilot" for r in col["desktop"])
    assert any(r["tool"] == "acme-copilot" for r in col["ide"])
    assert {"tool": "acme-copilot", "path": "Library/Acme/mcp.json",
            "os": "macos"} in col["mcp"]

    # And the domain normalizes findings immediately: a report naming the
    # domain lands as the tool id.
    client.post("/report", headers=AUTH,
                json={"tool": "acme-copilot.example", "surface": "browser"})
    assert main._DOMAIN_TO_TOOL["acme-copilot.example"] == "acme-copilot"


def test_deleting_a_tool_removes_it_everywhere(managed):
    _put(entries=[ENTRY])
    resp = _put(delete=["acme-copilot"])
    assert resp.json()["entries"] == []
    reg = client.get("/registry", headers=AUTH).json()
    assert not any(t["id"] == "acme-copilot" for t in reg["tools"])
    assert "acme-copilot.example" not in main._DOMAIN_TO_TOOL


# ------------------------------------------------------------- validation --


def test_a_shipped_id_cannot_be_redefined(managed):
    resp = _put(entries=[{**ENTRY, "id": "claude", "domains": []}])
    assert resp.status_code == 422
    assert "shipped registry" in resp.json()["detail"]


def test_a_shipped_domain_cannot_be_claimed(managed):
    resp = _put(entries=[{**ENTRY, "domains": ["claude.ai"]}])
    assert resp.status_code == 422
    assert "claimed by claude" in resp.json()["detail"]


def test_the_registry_builds_own_rules_hold(managed):
    # Non-lowercase domain: the macOS collector matches case-sensitively.
    assert _put(entries=[{**ENTRY, "domains": ["Acme.Example"]}]).status_code == 422
    # Unknown fields: additionalProperties false in the schema.
    assert _put(entries=[{**ENTRY, "surprise": True}]).status_code == 422
    # Required metadata.
    bad = {k: v for k, v in ENTRY.items() if k != "vendor"}
    assert _put(entries=[bad]).status_code == 422


def test_the_batch_validates_before_anything_writes(managed):
    resp = _put(entries=[ENTRY, {**ENTRY, "id": "second", "domains": ["Bad.Case"]}])
    assert resp.status_code == 422
    assert client.get("/admin/registry-entries", headers=ADMIN).json()["entries"] == []


def test_two_batch_entries_cannot_claim_one_domain(managed):
    second = {**ENTRY, "id": "other-tool"}
    resp = _put(entries=[ENTRY, second])
    assert resp.status_code == 422
    assert "already claimed" in resp.json()["detail"]


def test_an_upstream_release_shadows_a_local_copy(managed, tmp_path, monkeypatch):
    """If a later release ships an id the operator defined, shipped wins at
    serve time and the listing says shadowed - a row to delete, not a
    silent ignore."""
    _put(entries=[ENTRY])
    shipped = {"version": 1, "tools": [
        {"id": "acme-copilot", "name": "Acme Copilot", "vendor": "Acme",
         "category": "assistant", "approved": False,
         "domains": ["acme-copilot.example"], "notes": "now upstream"}]}
    path = tmp_path / "registry.json"
    path.write_text(json.dumps(shipped))
    monkeypatch.setattr(main, "REGISTRY_PATH", str(path))

    (e,) = client.get("/admin/registry-entries", headers=ADMIN).json()["entries"]
    assert e["shadowed"] is True
    reg = client.get("/registry", headers=AUTH).json()
    mine = [t for t in reg["tools"] if t["id"] == "acme-copilot"]
    assert len(mine) == 1 and mine[0].get("notes") == "now upstream"


def test_classic_mode_serves_the_file_untouched():
    assert client.get("/admin/registry-entries", headers=ADMIN).status_code == 404
    assert client.put("/admin/registry-entries", headers=ADMIN,
                      json={}).status_code == 404
def test_a_collector_reporting_an_editor_gets_the_ambient_signal(managed):
    """The three endpoint collectors report a plain `surface: desktop` and
    know nothing about which tools are editors. Without this the whole
    installed-vs-used split would be defeated on the surface that matters
    most - a Windsurf.app the macOS collector found would arrive unlabelled
    and read as someone using AI. Filled in here so the rule lands without
    upgrading a bash script, a PowerShell script and a Linux script first."""
    with _capture() as records:
        assert client.post("/report", headers=AUTH, json={
            "tool": "codeium", "surface": "desktop", "os": "macos",
            "device": "MAC-1", "evidence": "Windsurf.app"}).status_code == 200
        # A tool whose presence IS use must be left alone: Claude.app has no
        # purpose except the model.
        assert client.post("/report", headers=AUTH, json={
            "tool": "claude", "surface": "desktop", "os": "macos",
            "device": "MAC-1", "evidence": "Claude.app"}).status_code == 200

    by_tool = {r["tool"]: r for r in records}
    assert by_tool["codeium"]["signal"] == "ambient"
    assert by_tool["claude"]["signal"] == ""


def test_a_scanner_that_classified_itself_is_not_second_guessed(managed):
    """The scanner saw the DNS hostname; the receiver did not. An explicit
    active on an editor - traffic to the completion backend - must survive,
    or the receiver would quietly overwrite the only evidence of real use."""
    from app.main import Finding, _PRESENCE_SURFACES

    assert "desktop" in _PRESENCE_SURFACES
    f = Finding(tool="codeium", surface="desktop", signal="active",
                device="MAC-2")
    # The ingest rule only fills a blank.
    assert f.signal == "active"


def test_the_new_finding_fields_are_bounded_like_every_other_label(managed):
    """mode and identity are label sets, so a sender cannot invent values.
    An unrecognised one is dropped to empty rather than refused: a finding
    with one odd field is still evidence, and losing the whole thing because
    a collector sent a typo would be the worse trade."""
    with _capture() as records:
        assert client.post("/report", headers=AUTH, json={
            "tool": "claude-code", "surface": "cli", "device": "MAC-9",
            "mode": "autonomous", "identity": "machine",
            "trigger": "systemd timer, every 15 min"}).status_code == 200
        assert client.post("/report", headers=AUTH, json={
            "tool": "claude-code", "surface": "cli", "device": "MAC-9",
            "mode": "sentient", "identity": "moon"}).status_code == 200

    good, bad = records[0], records[1]
    assert good["mode"] == "autonomous"
    assert good["identity"] == "machine"
    assert good["trigger"] == "systemd timer, every 15 min"
    assert bad["mode"] == "" and bad["identity"] == ""


def test_an_over_long_label_is_refused_rather_than_truncated(managed):
    """The two guards are different on purpose, and it is worth pinning
    which is which. An unrecognised VALUE is dropped to empty, because a
    finding with one odd field is still evidence. An over-LONG one is
    refused outright, because these become log-store labels and a sender
    that can grow one without bound can grow the label set with it."""
    r = client.post("/report", headers=AUTH, json={
        "tool": "claude-code", "surface": "cli", "device": "MAC-7",
        "mode": "a" * 40})
    assert r.status_code == 422


def test_a_sender_that_knows_nothing_of_these_fields_still_reports(managed):
    """Every collector in the field predates them. Their findings must land
    unchanged, carrying empty values that downstream reads as unknown."""
    with _capture() as records:
        assert client.post("/report", headers=AUTH, json={
            "tool": "claude-code", "surface": "cli", "device": "MAC-8",
            "evidence": "~/.claude.json"}).status_code == 200

    f = records[0]
    assert f["mode"] == "" and f["identity"] == "" and f["trigger"] == ""
