"""Portal-defined registry entries: same shape, same rules, served merged.

The property under test is the discovery loop's last link: a tool defined
through the admin API is validated to the registry build's own rules, then
appears in /registry, in every /registry/collector surface list, and in the
receiver's domain normalization - so the fleet detects it with no rebuild.
"""

import json
import os
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
