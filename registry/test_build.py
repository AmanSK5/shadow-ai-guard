"""Tests for registry/build.py.

Covers the generated-output duplicate that --check cannot catch, since
--check validates the source YAML only and does not run emit().
"""

import json
import shutil
import sys
import tempfile
from pathlib import Path

# build.py is not a package, so add its directory to the path.
sys.path.insert(0, str(Path(__file__).parent))
import build  # noqa: E402


def test_emitted_mcp_entries_have_no_duplicates():
    """Each (tool, path, os) triple should appear at most once in collector.json."""
    registry, schema = build.load()
    assert build.validate(registry, schema), "registry.yaml itself is invalid"

    tmpdir = Path(tempfile.mkdtemp())
    try:
        orig_dist = build.DIST
        build.DIST = tmpdir
        build.emit(registry)
        build.DIST = orig_dist

        with open(tmpdir / "collector.json") as f:
            collector = json.load(f)

        mcp_entries = collector.get("mcp", [])
        seen = set()
        for entry in mcp_entries:
            key = (entry["tool"], entry["path"], entry["os"])
            assert key not in seen, (
                f"Duplicate MCP entry: tool={key[0]}, path={key[1]}, os={key[2]}"
            )
            seen.add(key)
    finally:
        shutil.rmtree(tmpdir)
def _tool(registry, tid):
    return next(t for t in registry["tools"] if t["id"] == tid)


def test_inference_domains_must_be_real_domains_of_that_tool():
    """A typo here fails silently in the worst direction: the host matches
    nothing, so the tool is never credited with being used and quietly reads
    as installed-only forever. JSON Schema cannot express a subset, so
    build.py checks it and this checks build.py."""
    import copy

    registry, schema = build.load()
    assert build.validate(registry, schema)

    bad = copy.deepcopy(registry)
    _tool(bad, "codeium")["inference_domains"].append("typo.example")
    assert not build.validate(bad, schema)


def test_inference_domains_without_form_ide_is_refused():
    """On any other shape the field is inert, and inert configuration reads
    as working - someone would set it and believe presence had stopped
    counting as use."""
    import copy

    registry, schema = build.load()
    bad = copy.deepcopy(registry)
    _tool(bad, "tabnine")["inference_domains"] = ["api.tabnine.com"]
    assert not build.validate(bad, schema)


def test_the_vs_code_forks_are_marked_and_their_backends_named():
    """Cursor and Windsurf/Devin Desktop are the two entries where presence
    does not imply use. If either loses its form or its inference domains,
    an editor rollout silently starts reporting as an AI rollout again."""
    registry, _ = build.load()
    for tid, backend in (("cursor", "api2.cursor.sh"),
                         ("codeium", "server.codeium.com")):
        t = _tool(registry, tid)
        assert t.get("form") == "ide", tid
        # Set algebra rather than `x in y`: these are host lists, and the
        # membership form reads to CodeQL as a URL substring check.
        inference = set(t.get("inference_domains", []))
        assert {backend} <= inference, tid
        # And the hosts an editor reaches on launch anyway must NOT be there.
        assert inference.isdisjoint({"cursor.com", "windsurf.com"}), tid


def test_the_scanner_view_carries_the_distinction():
    """The scanner is the only component that sees a DNS hit next to the
    registry entry, so it is the only one that can classify. If these fields
    stop being emitted, every fork silently reverts to presence-is-use."""
    import tempfile
    from pathlib import Path as _P

    registry, _ = build.load()
    tmp = _P(tempfile.mkdtemp())
    orig = build.DIST
    try:
        build.DIST = tmp
        build.emit(registry, write_fallback=False)
    finally:
        build.DIST = orig
    services = {s["name"]: s for s in json.loads(
        (tmp / "scanner.json").read_text())["services"]}
    ws = services["Windsurf / Devin (Cognition)"]
    assert ws["form"] == "ide"
    assert {"server.codeium.com"} <= set(ws["inference_domains"])
    assert services["Claude"]["form"] == ""
