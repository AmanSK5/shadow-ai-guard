"""Integration test for demo mode.

Runs `ai-guard scan --demo` and asserts the output contains expected
user names and at least one BLOCKED, APPROVED, and EDUCATE finding.
"""

import subprocess
import sys


def test_demo_scan_output():
    """Run demo scan and verify expected content in output."""
    result = subprocess.run(
        [sys.executable, "-m", "ai_guard.cli", "scan", "--demo"],
        capture_output=True,
        text=True,
        cwd=str(_project_root()),
    )

    output = result.stdout + result.stderr
    assert result.returncode == 0, f"Demo scan failed:\n{output}"

    # Banner
    assert "demo mode" in output.lower(), "Missing demo mode banner"

    # Expected users appear in output
    expected_users = [
        "charizard@demo-corp.example",
        "blastoise@demo-corp.example",
        "venusaur@demo-corp.example",
        "pikachu@demo-corp.example",
        "gengar@demo-corp.example",
    ]
    for user in expected_users:
        assert user in output, f"Expected user {user} not found in output"

    # mewtwo should NOT appear (clean control case)
    assert "mewtwo" not in output.lower(), "mewtwo should not appear — clean control case"

    # Policy actions
    assert "BLOCKED" in output, "Expected at least one BLOCKED finding"
    assert "APPROVED" in output, "Expected at least one APPROVED finding"

    # EDUCATE is the default — it shows as the base risk tier without
    # BLOCKED/APPROVED prefix. Verify at least one finding that is neither.
    # Grammarly and Notion AI should be medium risk without policy override.
    assert "Grammarly" in output, "Expected Grammarly (educate-tier) in output"
    assert "Notion AI" in output, "Expected Notion AI (educate-tier) in output"


def test_demo_scan_device_names_json():
    """Verify device name mapping in JSON output."""
    import json
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        out_path = f.name

    result = subprocess.run(
        [sys.executable, "-m", "ai_guard.cli", "scan", "--demo", "-f", "json", "-o", out_path],
        capture_output=True,
        text=True,
        cwd=str(_project_root()),
    )

    assert result.returncode == 0, f"Demo JSON scan failed:\n{result.stdout + result.stderr}"

    with open(out_path) as f:
        data = json.load(f)

    devices = {f["device_name"] for f in data["findings"] if f.get("device_name")}

    assert "DEMO-LAPTOP-01" in devices, "Missing DEMO-LAPTOP-01 (charizard)"
    assert "DEMO-LAPTOP-03" in devices, "Missing DEMO-LAPTOP-03 (venusaur)"
    assert "DEMO-LAPTOP-04" in devices, "Missing DEMO-LAPTOP-04 (pikachu)"

    import os
    os.unlink(out_path)


def _project_root():
    from pathlib import Path
    return Path(__file__).parent.parent
