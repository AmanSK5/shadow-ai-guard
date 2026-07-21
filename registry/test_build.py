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
