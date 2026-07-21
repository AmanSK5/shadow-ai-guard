"""Tests for DRY_RUN environment variable parsing.

Covers the bug where bool(os.environ.get("DRY_RUN")) treated any non-empty
string (including "false", "0", "no") as truthy, silently disabling
finding delivery.

Both scanner/entrypoint.py and discovery/discover.py use the same inline
expression. This test validates the expression directly.
"""

import os

import pytest


def _parse_dry_run():
    """The expression used in entrypoint.py and discover.py."""
    return os.environ.get("DRY_RUN", "").strip().lower() in {"1", "true", "yes", "on"}


@pytest.mark.parametrize(
    "env_value, expected",
    [
        (None, False),       # unset
        ("", False),         # empty string
        ("false", False),    # explicit false
        ("False", False),    # capitalised false
        ("FALSE", False),    # all-caps false
        ("0", False),        # zero
        ("no", False),       # no
        ("off", False),      # off
        ("true", True),      # truthy
        ("True", True),      # capitalised
        ("TRUE", True),      # all-caps
        ("1", True),         # one
        ("yes", True),       # yes
        ("on", True),        # on
        ("  true  ", True),  # whitespace-padded
    ],
)
def test_dry_run_parsing(monkeypatch, env_value, expected):
    if env_value is None:
        monkeypatch.delenv("DRY_RUN", raising=False)
    else:
        monkeypatch.setenv("DRY_RUN", env_value)
    assert _parse_dry_run() is expected
