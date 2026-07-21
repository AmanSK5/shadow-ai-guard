#!/usr/bin/env python3
"""Validate registry.yaml and emit per-consumer artifacts into dist/.

Usage:
  python build.py --check          # validate only (CI merge-request gate)
  python build.py                  # validate + write dist/*.json

Artifacts:
  dist/registry.json    full registry, served by the receiver at /registry
  dist/extension.json   domains + login selectors for the browser extension
  dist/collector.json   cli/desktop/ide/mcp identifiers for endpoint scripts
  dist/scanner.json     domains + email senders + extension ids for the CLI scanner
"""

import argparse
import json
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

HERE = Path(__file__).parent
DIST = HERE / "dist"


def load():
    registry = yaml.safe_load((HERE / "registry.yaml").read_text())
    schema = json.loads((HERE / "schema.json").read_text())
    return registry, schema


def validate(registry, schema):
    errors = list(Draft202012Validator(schema).iter_errors(registry))
    ids = [t["id"] for t in registry.get("tools", [])]
    dupes = {i for i in ids if ids.count(i) > 1}
    ok = True
    for e in errors:
        print(f"schema: {'/'.join(str(p) for p in e.path)}: {e.message}", file=sys.stderr)
        ok = False
    if dupes:
        print(f"duplicate tool ids: {sorted(dupes)}", file=sys.stderr)
        ok = False
    # every domain must be lowercase and unique across the registry
    seen = {}
    for t in registry.get("tools", []):
        for d in t.get("domains", []):
            if d != d.lower():
                print(f"{t['id']}: domain not lowercase: {d}", file=sys.stderr)
                ok = False
            if d in seen and seen[d] != t["id"]:
                print(f"domain {d} claimed by both {seen[d]} and {t['id']}", file=sys.stderr)
                ok = False
            seen[d] = t["id"]
    return ok


def emit(registry):
    DIST.mkdir(exist_ok=True)
    tools = registry["tools"]

    (DIST / "registry.json").write_text(json.dumps(registry, indent=2))

    extension = {
        "version": registry["version"],
        "sites": [
            {
                "tool": t["id"],
                "domains": t.get("domains", []),
                "login_selector": t.get("login_selector"),
                "approved": t["approved"],
            }
            for t in tools
            if t.get("domains")
        ],
    }
    (DIST / "extension.json").write_text(json.dumps(extension, indent=2))

    collector = {
        "version": registry["version"],
        "cli": [
            {"tool": t["id"], **t["cli"]}
            for t in tools
            if t.get("cli")
        ],
        "desktop": [
            {"tool": t["id"], "app_names": t["app_names"], "bundle_ids": t.get("bundle_ids", [])}
            for t in tools
            if t.get("app_names")
        ],
        "ide": [
            {"tool": t["id"], "extension_ids": t["extension_ids"]}
            for t in tools
            if t.get("extension_ids")
        ],
        # Tool-associated, not a flat set: the collector labels each MCP
        # finding "<tool>-mcp:<servers>" and cannot do that from a bare path.
        # os says which collector should look for it; Claude Desktop's config
        # lives under Library on macOS and AppData on Windows.
        "mcp": [
            {"tool": t["id"], "path": p, "os": os_}
            for t in tools
            for key, os_ in (
                ("mcp_config_paths", "any"),
                ("mcp_config_paths_macos", "macos"),
                ("mcp_config_paths_windows", "windows"),
                ("mcp_config_paths_linux", "linux"),
            )
            for p in t.get(key, [])
        ],
    }
    (DIST / "collector.json").write_text(json.dumps(collector, indent=2))

    # scanner.json is consumed by ai_guard.registry.Registry, which was written
    # against the CLI's ai_services.yaml. Emit that exact shape so the scanner
    # can load its registry from the receiver's /registry endpoint at runtime
    # rather than carrying a copy baked into the image.
    scanner = {
        "services": [
            {
                "name": t["name"],
                "vendor": t["vendor"],
                "category": t["category"],
                "risk_tier": t.get("risk_tier", "medium"),
                "approved": t["approved"],
                "domains": t.get("domains", []),
                "entra_app_ids": t.get("entra_app_ids", []),
                "email_domains": t.get("email_senders", []),
                "desktop_apps": {
                    "macos": t.get("bundle_ids", []) + t.get("app_names", []),
                    "windows": t.get("exe_names", []),
                },
                "browser_extensions": {
                    b: ids
                    for b, ids in t.get("extension_ids", {}).items()
                    if b in ("chrome", "edge")
                },
                "mcp_identifiers": t.get("mcp_identifiers", []),
                "notes": t.get("notes", ""),
            }
            for t in tools
        ],
        "bridge_targets": registry.get("bridge_targets", []),
        "allowed_processes": registry.get("allowed_processes", []),
        "discover_exclude_domains": registry.get("discover_exclude_domains", []),
        "registry_version": str(registry["version"]),
    }
    (DIST / "scanner.json").write_text(json.dumps(scanner, indent=2))

    print(f"wrote {len(tools)} tools -> {DIST}/{{registry,extension,collector,scanner}}.json")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="validate only, no artifacts")
    args = ap.parse_args()

    registry, schema = load()
    if not validate(registry, schema):
        sys.exit(1)
    print(f"registry.yaml valid: {len(registry['tools'])} tools")
    if not args.check:
        emit(registry)


if __name__ == "__main__":
    main()