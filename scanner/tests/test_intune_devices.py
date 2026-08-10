"""Intune per-device attribution.

The failure mode this guards against: the app registration has
DeviceManagementApps.Read.All but not DeviceManagementManagedDevices.Read.All,
every device lookup 403s, and the scanner quietly reports aggregate counts
that look exactly like a successful scan of an estate where nobody can be
attributed. A permissions gap should not be indistinguishable from a result.
"""

import asyncio

import pytest

from ai_guard.config import ScannerConfig
from ai_guard.registry import AIService
from ai_guard.scanners import intune as intune_mod
from ai_guard.scanners.intune import IntuneScanner

SERVICE = AIService(
    name="ChatGPT",
    vendor="OpenAI",
    category="chatbot",
    risk_tier="high",
    desktop_apps={"windows": ["ChatGPT.exe"]},
)


class FakeRegistry:
    services = [SERVICE]

    def match_desktop_app(self, app_name):
        return SERVICE if app_name == "ChatGPT.exe" else None


APPS = [{"id": "app-1", "displayName": "ChatGPT.exe", "deviceCount": 12}]

DEVICES = [
    {"deviceName": "LAPTOP-01", "userPrincipalName": "alice@example.com", "id": "d1"},
    {"deviceName": "LAPTOP-02", "userPrincipalName": "bob@example.com", "id": "d2"},
]


def _scanner():
    return IntuneScanner(FakeRegistry(), ScannerConfig(enabled=True))


def _patch_paginate(monkeypatch, device_result):
    """device_result is either a list of devices or an Exception to raise."""

    async def fake_paginate(client, url, max_pages=20):
        if "detectedApps?" in url:
            return APPS
        if isinstance(device_result, Exception):
            raise device_result
        return device_result

    monkeypatch.setattr(intune_mod, "paginate", fake_paginate)


def test_device_lookup_failure_is_surfaced(monkeypatch):
    """A 403 must produce a scan error, not a silent aggregate."""
    _patch_paginate(monkeypatch, PermissionError("403 Forbidden"))
    findings, errors = asyncio.run(_scanner()._scan_discovered_apps(client=None))

    assert errors, "a failed device lookup must be reported"
    assert "attribution failed" in errors[0].lower()
    assert "DeviceManagementManagedDevices.Read.All" in errors[0]


def test_failed_attribution_is_visible_on_the_finding(monkeypatch):
    """The finding itself must say attribution was attempted and failed."""
    _patch_paginate(monkeypatch, PermissionError("403 Forbidden"))
    findings, _ = asyncio.run(_scanner()._scan_discovered_apps(client=None))

    assert len(findings) == 1
    assert findings[0].raw_evidence["attribution_failed"] is True
    assert "unavailable" in findings[0].detail


def test_genuinely_empty_is_not_reported_as_an_error(monkeypatch):
    """An app on no managed devices is a result, not a failure."""
    _patch_paginate(monkeypatch, [])
    findings, errors = asyncio.run(_scanner()._scan_discovered_apps(client=None))

    assert errors == []
    assert len(findings) == 1
    assert findings[0].raw_evidence["attribution_failed"] is False
    assert "unavailable" not in findings[0].detail


def test_successful_lookup_produces_per_device_findings(monkeypatch):
    """Note this exercises the fallback: _scan_discovered_apps is called
    without a device map, so findings carry the sub-resource's device name
    rather than a serial. Serial identity is covered in
    test_intune_device_map.py, which builds the map first as scan() does.
    """
    _patch_paginate(monkeypatch, DEVICES)
    findings, errors = asyncio.run(_scanner()._scan_discovered_apps(client=None))

    assert errors == []
    assert len(findings) == 2
    assert {f.user_upn for f in findings} == {
        "alice@example.com",
        "bob@example.com",
    }
    assert {f.device_name for f in findings} == {"LAPTOP-01", "LAPTOP-02"}


def test_device_lookup_is_paginated(monkeypatch):
    """The device list must go through paginate, not a bare single GET.

    A popular app can exceed one page; a truncated device list understates
    exposure, which is the failure the detectedApps query already guards
    against.
    """
    seen_urls = []

    async def fake_paginate(client, url, max_pages=20):
        seen_urls.append(url)
        return APPS if "detectedApps?" in url else DEVICES

    monkeypatch.setattr(intune_mod, "paginate", fake_paginate)
    asyncio.run(_scanner()._scan_discovered_apps(client=None))

    assert any("managedDevices" in u for u in seen_urls), (
        "device lookup should use the paginating helper"
    )
