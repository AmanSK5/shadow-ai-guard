"""Matching an application to a registry service.

The failure that matters here is not a missed detection, it is a confident
wrong one: a finding that names the wrong tool gets acted on.
"""

import pytest

from ai_guard.scanners.entra import _match_service_by_name


class _Svc:
    def __init__(self, name, vendor=""):
        self.name = name
        self.vendor = vendor


class _Registry:
    def __init__(self, services):
        self.services = services


@pytest.fixture
def registry():
    return _Registry(
        [
            _Svc("Claude", "Anthropic"),
            _Svc("Claude Code", "Anthropic"),
            _Svc("Microsoft Copilot (Free)", "Microsoft"),
            _Svc("Microsoft 365 Copilot", "Microsoft"),
            _Svc("Continue", "Continue Dev"),
            _Svc("Fireflies.ai", "Fireflies"),
            _Svc("Gemini", "Google"),
            _Svc("Grok", "xAI"),
        ]
    )


@pytest.mark.parametrize(
    "display_name,expected",
    [
        ("Fireflies.ai", "Fireflies.ai"),
        ("Claude", "Claude"),
        ("Microsoft 365 Copilot", "Microsoft 365 Copilot"),
        ("Microsoft Copilot (Free)", "Microsoft Copilot (Free)"),
    ],
)
def test_known_applications_match(registry, display_name, expected):
    assert _match_service_by_name(registry, display_name).name == expected


def test_the_longest_name_wins(registry):
    """Claude appears before Claude Code in the registry. A first-match loop
    would label an app called Claude Code as Claude."""
    assert _match_service_by_name(registry, "Claude Code").name == "Claude Code"


@pytest.mark.parametrize(
    "display_name",
    [
        "Microsoft Teams",
        "Microsoft Intune",
        "Microsoft Defender for Endpoint",
        "Google Cloud Platform",
        "Azure DevOps",
    ],
)
def test_other_applications_by_a_registry_vendor_do_not_match(registry, display_name):
    """The vendor is not consulted. Matching one meant every application
    published by Microsoft or Google matched whichever of their tools the
    registry listed first."""
    assert _match_service_by_name(registry, display_name) is None


@pytest.mark.parametrize(
    "display_name",
    ["Continuous Delivery Tool", "Grokster Media Player", "Geminids Tracker"],
)
def test_a_name_inside_a_longer_word_does_not_match(registry, display_name):
    assert _match_service_by_name(registry, display_name) is None


@pytest.mark.parametrize("display_name", ["", None])
def test_empty_display_name_matches_nothing(registry, display_name):
    assert _match_service_by_name(registry, display_name) is None