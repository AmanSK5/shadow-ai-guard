"""Intune device attributes come from the devices resource, not the app lookup.

The failure mode this guards against is specific and it answers 200.

`GET /deviceManagement/detectedApps/{id}/managedDevices` honours $select for
deviceName and id and stubs everything else: null for strings, year one for
lastSyncDateTime. Nothing errors. A stale-device filter reading that timestamp
finds every device older than any cutoff and skips the entire fleet, and a
scanner keyed on that serialNumber gets null for every machine.

Observed: apps resolved their devices, device records came back, none survived
the filter, and Intune reported two aggregate findings from a fleet whose
machines had checked in that morning.

So device attributes are read from /deviceManagement/managedDevices, fetched
once into an id-keyed map, and the sub-resource is asked only for the two fields
it answers honestly.
"""

import asyncio

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


APPS = [{"id": "app-1", "displayName": "ChatGPT.exe", "deviceCount": 2}]

# What the sub-resource actually returns. deviceName and id are real; the rest
# is stubbed despite the 200. This is the trap, written out as a fixture.
STUBBED_SUB_RESOURCE = [
    {
        "deviceName": "LAPTOP-01",
        "id": "d1",
        "userPrincipalName": None,
        "serialNumber": None,
        "lastSyncDateTime": "0001-01-01T00:00:00Z",
    },
    {
        "deviceName": "LAPTOP-02",
        "id": "d2",
        "userPrincipalName": None,
        "serialNumber": None,
        "lastSyncDateTime": "0001-01-01T00:00:00Z",
    },
]

# What the devices resource returns for the same two machines: real serials,
# real users, and sync times from this morning.
INVENTORY = [
    {
        "id": "d1",
        "deviceName": "LAPTOP-01",
        "serialNumber": "PF2ABCDE",
        "userPrincipalName": "alice@example.com",
        "lastSyncDateTime": "2026-08-10T06:14:00Z",
        "operatingSystem": "Windows",
    },
    {
        "id": "d2",
        "deviceName": "LAPTOP-02",
        "serialNumber": "PF3FGHIJ",
        "userPrincipalName": "bob@example.com",
        "lastSyncDateTime": "2026-08-10T07:02:00Z",
        "operatingSystem": "Windows",
    },
]


def _scanner(**options):
    # No delay: the default is a real one second sleep per app after the first,
    # which is right against Graph and wasted in a test.
    options.setdefault("app_lookup_delay_seconds", 0)
    return IntuneScanner(
        FakeRegistry(), ScannerConfig(enabled=True, options=options)
    )


def _patch(monkeypatch, inventory=INVENTORY, sub=STUBBED_SUB_RESOURCE):
    """Route each URL to the resource it actually represents.

    inventory or sub may be an Exception, which is raised instead.
    """
    seen_urls = []

    async def fake_paginate(client, url, max_pages=20):
        seen_urls.append(url)
        if "detectedApps?" in url:
            return APPS
        if "managedDevices?" in url and "detectedApps" not in url:
            if isinstance(inventory, Exception):
                raise inventory
            return inventory
        if isinstance(sub, Exception):
            raise sub
        return sub

    monkeypatch.setattr(intune_mod, "paginate", fake_paginate)
    return seen_urls


async def _run(scanner):
    """Build the device map then scan, which is what scan() does in order."""
    scanner._devices = await scanner._build_device_map(client=None)
    return await scanner._scan_discovered_apps(client=None)


def test_stubbed_timestamps_do_not_skip_the_fleet(monkeypatch):
    """The regression. Year one from the sub-resource must not be trusted.

    Both devices synced this morning. Reading lastSyncDateTime from the app
    lookup would date them to 0001-01-01, older than any cutoff, and drop both.
    """
    _patch(monkeypatch)
    findings, errors = asyncio.run(_run(_scanner(stale_device_days=90)))

    assert errors == []
    assert len(findings) == 2, (
        "devices that synced today were skipped as stale, which means a "
        "timestamp is being read from the sub-resource"
    )


def test_serial_is_the_device_identity(monkeypatch):
    """Device identity is the hardware serial, matching jamf.py.

    The Windows collector on these machines reports its BIOS serial. A finding
    keyed on LAPTOP-01 cannot be joined to one keyed on PF2ABCDE, so the
    same machine appears twice on any view that groups by device.
    """
    _patch(monkeypatch)
    findings, _ = asyncio.run(_run(_scanner()))

    assert {f.device_name for f in findings} == {"PF2ABCDE", "PF3FGHIJ"}


def test_friendly_name_is_kept_as_evidence(monkeypatch):
    """Keying on the serial must not cost the human-readable name."""
    _patch(monkeypatch)
    findings, _ = asyncio.run(_run(_scanner()))

    assert {f.raw_evidence["device_name"] for f in findings} == {
        "LAPTOP-01",
        "LAPTOP-02",
    }


def test_upn_comes_from_the_inventory_not_the_stub(monkeypatch):
    """The sub-resource returns null for userPrincipalName on some tenants."""
    _patch(monkeypatch)
    findings, _ = asyncio.run(_run(_scanner()))

    assert {f.user_upn for f in findings} == {
        "alice@example.com",
        "bob@example.com",
    }


def test_stale_device_is_skipped_on_the_inventory_timestamp(monkeypatch):
    """The filter still has to work. One device last synced in 2019."""
    old = [dict(INVENTORY[0]), dict(INVENTORY[1])]
    old[0]["lastSyncDateTime"] = "2019-01-01T00:00:00Z"
    _patch(monkeypatch, inventory=old)
    findings, errors = asyncio.run(_run(_scanner(stale_device_days=90)))

    assert errors == []
    assert {f.device_name for f in findings} == {"PF3FGHIJ"}


def test_stale_filter_can_be_disabled(monkeypatch):
    old = [dict(INVENTORY[0]), dict(INVENTORY[1])]
    old[0]["lastSyncDateTime"] = "2019-01-01T00:00:00Z"
    _patch(monkeypatch, inventory=old)
    findings, _ = asyncio.run(_run(_scanner(stale_device_days=0)))

    assert len(findings) == 2


def test_unparseable_timestamp_does_not_drop_a_device(monkeypatch):
    """An unexpected format means do not filter, not discard.

    Dropping a device because Graph returned something unfamiliar would hide a
    real machine, which is the same class of error as the trap above.
    """
    odd = [dict(INVENTORY[0]), dict(INVENTORY[1])]
    odd[0]["lastSyncDateTime"] = "not a timestamp"
    _patch(monkeypatch, inventory=odd)
    findings, _ = asyncio.run(_run(_scanner(stale_device_days=90)))

    assert len(findings) == 2


def test_inventory_failure_degrades_rather_than_aborts(monkeypatch):
    """No device map is a worse result, not a dead scan.

    Findings fall back to the name the sub-resource gave, which is the
    behaviour the map replaced.
    """
    _patch(monkeypatch, inventory=PermissionError("403 Forbidden"))
    findings, errors = asyncio.run(_run(_scanner(stale_device_days=90)))

    assert len(findings) == 2
    assert {f.device_name for f in findings} == {"LAPTOP-01", "LAPTOP-02"}


def test_device_missing_from_inventory_is_still_reported(monkeypatch):
    """The app is installed somewhere even if the record has been removed."""
    _patch(monkeypatch, inventory=[INVENTORY[0]])
    findings, _ = asyncio.run(_run(_scanner(stale_device_days=90)))

    assert {f.device_name for f in findings} == {"PF2ABCDE", "LAPTOP-02"}


def test_inventory_is_asked_for_the_fields_the_sub_resource_stubs(monkeypatch):
    seen = _patch(monkeypatch)
    asyncio.run(_run(_scanner()))

    inventory_url = next(
        u for u in seen if "managedDevices?" in u and "detectedApps" not in u
    )
    for field in ("serialNumber", "lastSyncDateTime", "userPrincipalName"):
        assert field in inventory_url


def test_sub_resource_is_not_asked_for_fields_it_stubs(monkeypatch):
    """Asking costs nothing and returns a lie, which is worse than not asking.

    Keeping them out of the $select is the documentation of the trap that
    survives contact with a future edit.
    """
    seen = _patch(monkeypatch)
    asyncio.run(_run(_scanner()))

    sub_url = next(u for u in seen if "detectedApps/" in u)
    assert "serialNumber" not in sub_url
    assert "lastSyncDateTime" not in sub_url


def test_inventory_is_fetched_once_not_per_app(monkeypatch):
    """Graph rejects $expand=detectedApps on managedDevices, so the map is the
    only way to avoid a per-app device call. It should not become per-app
    itself."""
    many = [
        {"id": f"app-{i}", "displayName": "ChatGPT.exe", "deviceCount": 2}
        for i in range(5)
    ]
    seen = []

    async def fake_paginate(client, url, max_pages=20):
        seen.append(url)
        if "detectedApps?" in url:
            return many
        if "managedDevices?" in url and "detectedApps" not in url:
            return INVENTORY
        return STUBBED_SUB_RESOURCE

    monkeypatch.setattr(intune_mod, "paginate", fake_paginate)
    asyncio.run(_run(_scanner()))

    inventory_calls = [
        u for u in seen if "managedDevices?" in u and "detectedApps" not in u
    ]
    assert len(inventory_calls) == 1
