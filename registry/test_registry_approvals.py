"""The upstream registry carries no approval decisions.

approved: true means "sanctioned here", and here is wherever the registry is
deployed. Shipping it set upstream publishes the maintainer's own sanctioning
position on tools they do not deploy, which is not theirs to have. Approval is
organisation-specific.

It does not change what anyone is alerted about. Approval has no effect on
finding severity: severity is decided by the reporter at the point of detection
and depends on the account domain. This docstring used to claim otherwise, as
did the registry header and the schema description, and the claim was wrong in
all three places for long enough to mislead someone reading the code. Severity
and governance are independent dimensions and should stay that way, because an
approval that could lower severity would make "approved" mean "safe".
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