"""Intune reports display names; the registry holds executables.

detectedApps returns whatever the installer wrote, and one inventory carries
four naming schemes at once:

    display name            Claude
    versioned display name  LM Studio 0.3.20
    package id              Exafunction.Windsurf
    executable              ChatGPT.exe

The registry's windows lists are exe_names. Intune says Claude, the registry
says claude.exe, and an exact lookup matches neither. Twenty one AI app records
produced one finding, and the only hit was Microsoft.Copilot because the
registry happened to hold a package id for it.

Both sides are normalised instead. The comparison is equality after
normalising, deliberately not prefix: see test_prefix_matching_is_not_used.
"""

import asyncio

import pytest

from ai_guard.config import ScannerConfig
from ai_guard.registry import AIService
from ai_guard.scanners.intune import (
    IntuneScanner,
    _normalise_app_name,
    _windows_names,
)


@pytest.mark.parametrize(
    "raw,expected",
    [
        # Executables and bundles: the suffix is not part of the name.
        ("ChatGPT.exe", "chatgpt"),
        ("Claude.app", "claude"),
        # Package ids: last segment is the product, first is the publisher.
        ("Exafunction.Windsurf", "windsurf"),
        ("Microsoft.Copilot", "copilot"),
        # Versioned display names, including the build-suffixed form.
        ("LM Studio 0.3.20", "lm studio"),
        ("LM Studio 0.4.20+1", "lm studio"),
        ("Cursor v1.2.3", "cursor"),
        # Plain display names survive untouched apart from case.
        ("Claude", "claude"),
        ("Claude Code", "claude code"),
        # A dotted name with a space is a display name, not a package id.
        ("Adobe Acrobat 2.0", "adobe acrobat"),
        # Nothing in, nothing out.
        ("", ""),
        (None, ""),
    ],
)
def test_normalise_app_name(raw, expected):
    assert _normalise_app_name(raw) == expected


def test_leading_digit_in_a_product_name_is_not_a_version():
    """The version pattern needs whitespace before the digit.

    Otherwise 1Password normalises to the empty string and matches everything
    or nothing, depending on which side of the comparison it lands.
    """
    assert _normalise_app_name("1Password") == "1password"


def test_windows_names_reads_the_macos_list_too():
    """21 of the shipped registry's 30 tools have no windows list at all.

    Reading only the windows list was why Intune returned one finding. A tool
    is usually called the same thing on either platform once .app and .exe are
    gone, so both lists are read and normalised.
    """
    svc = AIService(
        name="Claude",
        vendor="Anthropic",
        category="chatbot",
        risk_tier="high",
        desktop_apps={"macos": ["Claude.app"]},
    )
    assert _windows_names(svc) == ["claude"]


def test_windows_names_deduplicates_across_platforms():
    svc = AIService(
        name="Cursor",
        vendor="Anysphere",
        category="copilot",
        risk_tier="medium",
        desktop_apps={"windows": ["Cursor.exe"], "macos": ["Cursor.app"]},
    )
    assert _windows_names(svc) == ["cursor"]


# ─────────────────────────────────────────────
# End to end through the scanner
# ─────────────────────────────────────────────

CLAUDE = AIService(
    name="Claude",
    vendor="Anthropic",
    category="chatbot",
    risk_tier="high",
    desktop_apps={"macos": ["Claude.app"]},
)
WINDSURF = AIService(
    name="Windsurf",
    vendor="Codeium",
    category="copilot",
    risk_tier="medium",
    desktop_apps={"windows": ["Windsurf.exe"]},
)
LM_STUDIO = AIService(
    name="LM Studio",
    vendor="LM Studio",
    category="chatbot",
    risk_tier="high",
    desktop_apps={"windows": ["LM Studio.exe"]},
)
# Detected through its CLI config, so it carries no desktop app names at all.
CLAUDE_CODE = AIService(
    name="Claude Code",
    vendor="Anthropic",
    category="agent",
    risk_tier="high",
    desktop_apps={},
)


class FakeRegistry:
    services = [CLAUDE, WINDSURF, LM_STUDIO, CLAUDE_CODE]

    def match_desktop_app(self, app_name):
        # Exact lookup on the registry's own strings, which is what the real
        # registry does. It misses every Intune display name, which is the
        # whole reason the normalised path exists.
        for svc in self.services:
            for names in svc.desktop_apps.values():
                if app_name in names:
                    return svc
        return None


def _run(apps, devices=None):
    devices = devices if devices is not None else []
    scanner = IntuneScanner(
        FakeRegistry(),
        ScannerConfig(enabled=True, options={"app_lookup_delay_seconds": 0}),
    )

    async def fake_paginate(client, url, max_pages=20):
        if "detectedApps?" in url:
            return apps
        return devices

    import ai_guard.scanners.intune as mod

    original = mod.paginate
    mod.paginate = fake_paginate
    try:
        return asyncio.run(scanner._scan_discovered_apps(client=None))
    finally:
        mod.paginate = original


def _app(display_name, count=1, app_id="a1"):
    return {"id": app_id, "displayName": display_name, "deviceCount": count}


def test_display_name_matches_a_macos_only_registry_entry():
    findings, _ = _run([_app("Claude")])
    assert len(findings) == 1
    assert findings[0].service.name == "Claude"


def test_package_id_matches():
    findings, _ = _run([_app("Exafunction.Windsurf")])
    assert len(findings) == 1
    assert findings[0].service.name == "Windsurf"


def test_versioned_display_name_matches():
    findings, _ = _run([_app("LM Studio 0.3.20")])
    assert len(findings) == 1
    assert findings[0].service.name == "LM Studio"


def test_prefix_matching_is_not_used():
    """The rule is equality after normalising, and this is why.

    Prefix matching would attribute an installed "Claude Code" to Claude,
    because claude-code is detected through its CLI config and carries no
    desktop app names of its own. A finding against the wrong tool is worse
    than no finding: it is a confident answer that sends someone to the wrong
    owner.
    """
    findings, _ = _run([_app("Claude Code")])
    assert findings == []


def test_unrelated_app_does_not_match():
    findings, _ = _run([_app("iCloud Drive")])
    assert findings == []


def test_substring_does_not_match():
    """The old fuzzy fallback was `known_app.lower() in app_name.lower()`.

    "Claude" is a substring of "Claude Sync Helper", which is not Claude.
    """
    findings, _ = _run([_app("Claude Sync Helper")])
    assert findings == []


def test_longest_known_name_wins():
    """Two services whose normalised names could both be reached.

    Only one can be right, and the more specific one is.
    """
    cursor = AIService(
        name="Cursor",
        vendor="Anysphere",
        category="copilot",
        risk_tier="medium",
        desktop_apps={"windows": ["Cursor.exe"]},
    )
    cursor_tab = AIService(
        name="Cursor Tab",
        vendor="Anysphere",
        category="copilot",
        risk_tier="low",
        desktop_apps={"windows": ["Cursor Tab.exe"]},
    )

    class TwoServices:
        services = [cursor, cursor_tab]

        def match_desktop_app(self, app_name):
            return None

    scanner = IntuneScanner(
        TwoServices(),
        ScannerConfig(enabled=True, options={"app_lookup_delay_seconds": 0}),
    )

    async def fake_paginate(client, url, max_pages=20):
        return [_app("Cursor Tab")] if "detectedApps?" in url else []

    import ai_guard.scanners.intune as mod

    original = mod.paginate
    mod.paginate = fake_paginate
    try:
        findings, _ = asyncio.run(scanner._scan_discovered_apps(client=None))
    finally:
        mod.paginate = original

    assert len(findings) == 1
    assert findings[0].service.name == "Cursor Tab"


def test_exact_registry_hit_still_wins_without_normalising():
    """The normalised path is a fallback, not a replacement."""
    findings, _ = _run([_app("Claude.app")])
    assert len(findings) == 1
    assert findings[0].service.name == "Claude"
