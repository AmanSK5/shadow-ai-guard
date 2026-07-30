"""The upstream registry carries no approval decisions.

approved: true means "sanctioned here", and here is wherever the registry is
deployed. Shipping it set upstream does two unhelpful things: it publishes
the maintainer's own sanctioning position, and it silently downgrades a
deployer's findings for those tools from warn to info before they have
decided anything.

Approvals belong in a deployment's own copy of registry.yaml, not in the one
everyone clones.
"""

from pathlib import Path

import yaml

HERE = Path(__file__).parent


def _registry():
    return yaml.safe_load((HERE / "registry.yaml").read_text())


def test_no_tool_ships_approved():
    approved = [t["name"] for t in _registry()["tools"] if t.get("approved")]
    assert not approved, (
        "approved: true in the upstream registry for: "
        + ", ".join(approved)
        + ". Sanctioning is a deployment decision, so it belongs in your own "
        "copy rather than the one everyone clones."
    )


def test_every_tool_states_an_approval_position():
    """approved is required by the schema, so this guards against a tool
    arriving with the field absent and defaulting to something."""
    missing = [t["name"] for t in _registry()["tools"] if "approved" not in t]
    assert not missing, f"no approved field on: {', '.join(missing)}"