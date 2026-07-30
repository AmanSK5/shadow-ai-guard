"""Registry paths must stay inside the user's home.

The collectors run as root or SYSTEM and join these values to a home
directory before reading them. Schema validation is the gate that stops a
bad path reaching a fleet; the collectors enforce it again at runtime,
because a privileged process should not trust its input even when something
upstream already checked it.
"""

import copy
import json
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

HERE = Path(__file__).parent


@pytest.fixture(scope="module")
def validator():
    schema = json.loads((HERE / "schema.json").read_text())
    return Draft202012Validator(schema)


@pytest.fixture(scope="module")
def registry():
    return yaml.safe_load((HERE / "registry.yaml").read_text())


def _with_cli_path(registry, path):
    r = copy.deepcopy(registry)
    for tool in r["tools"]:
        if "cli" in tool and "config_paths" in tool["cli"]:
            tool["cli"]["config_paths"] = [path]
            return r
    pytest.skip("no tool with cli.config_paths in the registry")


def test_the_real_registry_validates(validator, registry):
    assert list(validator.iter_errors(registry)) == []


@pytest.mark.parametrize(
    "path",
    [
        "/etc/shadow",
        "/Users/someone-else/.ssh/id_rsa",
        "../../../etc/passwd",
        ".ssh/../../../root/.ssh/authorized_keys",
        "C:/Windows/System32/config/SAM",
        "\\\\server\\share\\secrets",
        "x" * 300,
        "with\ttab",
    ],
)
def test_paths_outside_home_are_rejected(validator, registry, path):
    assert list(validator.iter_errors(_with_cli_path(registry, path)))


@pytest.mark.parametrize(
    "path",
    [
        ".claude.json",
        ".config/Claude/claude_desktop_config.json",
        "Library/Application Support/Claude/claude_desktop_config.json",
        "AppData/Roaming/Claude/claude_desktop_config.json",
        ".ollama/models",
    ],
)
def test_ordinary_relative_paths_are_accepted(validator, registry, path):
    assert list(validator.iter_errors(_with_cli_path(registry, path))) == []


def test_mcp_paths_are_checked_too(validator, registry):
    """Every path field gets the same treatment, not just the CLI ones."""
    r = copy.deepcopy(registry)
    r["tools"][0]["mcp_config_paths_macos"] = ["../../../../etc/passwd"]
    assert list(validator.iter_errors(r))