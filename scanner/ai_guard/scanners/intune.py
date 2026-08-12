"""Intune scanner.

Queries Microsoft Graph / Intune for discovered apps: AI desktop
applications installed on managed Windows devices.

Browser extensions are not covered here. The registry carries extension
identifiers and DetectionSource.INTUNE_EXTENSION exists, but nothing
produces one yet; extension visibility currently comes from the browser
extension itself, not from Intune.

Per-device attribution needs DeviceManagementManagedDevices.Read.All on top
of DeviceManagementApps.Read.All. Without it the device lookup fails and the
scanner falls back to an aggregate count, which is reported as a scan error
rather than passed off as a clean result.
"""

from __future__ import annotations
from typing import Optional

import asyncio
import logging
import re
from datetime import datetime, timedelta, timezone

from ai_guard.config import ScannerConfig
from ai_guard.registry import Registry
from ai_guard.scanners.base import (
    BaseScanner,
    DetectionSource,
    Finding,
    ScanResult,
)
from ai_guard.utils.auth import AuthError, MSGraphAuth
from ai_guard.utils.graph import paginate

logger = logging.getLogger(__name__)

# Intune keeps a managed device record until someone removes it, so a laptop
# that left with a leaver still reports the AI apps that were on it. Devices
# whose last sync is older than this are counted, logged and skipped. Set
# stale_device_days in the scanner options to tighten, or 0 to disable.
#
# The timestamp is read from the managed device record, never from the
# detectedApps sub-resource. See _get_app_devices for why that distinction is
# the whole point.
DEFAULT_STALE_DEVICE_DAYS = 90

# Seconds to wait between per-app device lookups. Graph throttles
# detectedApps/{id}/managedDevices hard: twenty one matched apps queried back
# to back had most of their calls refused, and paginate() had already spent
# its four Retry-After attempts on each. A second between calls costs about
# twenty seconds on a fleet this size and avoids the throttling entirely.
#
# Set app_lookup_delay_seconds in the scanner options to change it. 0 disables
# the wait, which is right for a tenant small enough not to be throttled.
DEFAULT_APP_LOOKUP_DELAY = 1.0


def _parse_ts(value):
    """Graph returns ISO 8601 with a Z suffix. None on anything unparseable,
    which is treated as 'do not filter': dropping a device because of an
    unexpected timestamp format would hide a real machine."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


# Version suffixes Intune appends to a display name: "LM Studio 0.3.20",
# "LM Studio 0.4.20+1", "LM Studio 0.3.20-beta", "Notion 3.0 (x64)",
# "ChatGPT 1.2024.021 (Machine - MSI)". A version token, an optional alpha
# build suffix, and an optional trailing parenthetical, anchored to the end.
#
# It used to be ".*$" after the version token, which swallowed the rest of the
# name, so any display name shaped "<word> <digits> <words>" collapsed to its
# first word. Measured against 985 detectedApps display names from a live
# tenant, that folded 31 localisations of Microsoft 365 onto the single key
# "microsoft", plus 12 Visual C++ redistributables, 6 .NET SDKs and 3 SQL
# Server LocalDBs.
#
# Nothing was misattributed on that tenant, because no registry entry happened
# to claim those keys. That is luck rather than design: "Microsoft 365 Copilot"
# normalises to "microsoft" under the old pattern, so adding an exe_name for it
# would have attributed every Office install on the estate to Copilot, and it
# would have looked like a finding rather than a bug.
#
# Anchoring to the end rather than consuming to it also leaves an unrelated app
# whose name merely begins with a tool name whole: "Cursor 2024 Backup Utility"
# stays itself instead of becoming "cursor".
_VERSION_TAIL = re.compile(
    r"\s+v?\d[\d.+_-]*(?:-[a-z][a-z0-9.]*)?(?:\s*\([^)]*\))?$",
    re.IGNORECASE,
)

# Stripping a version can leave a dangling separator: "Microsoft Windows
# Desktop Runtime - 6.0.25 (x64)" would otherwise key on "...runtime -". A key
# ending in punctuation matches nothing and reads as a bug wherever it appears.
_TRAILING_SEP = re.compile(r"[\s,\-]+$")


def _normalise_app_name(name: str) -> str:
    """Reduce an app name to something two naming schemes can be compared on.

    Intune reports display names, package ids and versioned display names; the
    registry holds executables and .app bundles. Neither side is wrong, so both
    are reduced rather than one being made to look like the other.
    """
    n = (name or "").strip()
    if not n:
        return ""
    # Package id: Exafunction.Windsurf, Microsoft.Copilot. The last segment is
    # the product; the first is the publisher. Only split when there is no
    # space, so "LM Studio 0.3.20" is left alone.
    if "." in n and " " not in n:
        tail = n.rsplit(".", 1)[-1]
        # .exe and .app are suffixes, not publishers.
        if tail.lower() not in ("exe", "app"):
            n = tail
    for suffix in (".exe", ".app"):
        if n.lower().endswith(suffix):
            n = n[: -len(suffix)]
    n = _TRAILING_SEP.sub("", _VERSION_TAIL.sub("", n))
    return n.strip().lower()


def _windows_names(service) -> list:
    """Every name this service might appear under on Windows.

    Both lists, because a tool is usually called the same thing on either
    platform once the .app and .exe suffixes are gone, and 21 of the shipped
    registry's 30 tools have no windows list at all. Reading only those was
    why Intune returned one finding from a fleet with twenty one AI app
    records.
    """
    names = []
    for key in ("windows", "macos"):
        names.extend(service.desktop_apps.get(key) or [])
    out, seen = [], set()
    for n in names:
        norm = _normalise_app_name(n)
        if norm and norm not in seen:
            seen.add(norm)
            out.append(norm)
    return out


class IntuneScanner(BaseScanner):
    name = "intune"

    def __init__(self, registry: Registry, config: ScannerConfig):
        super().__init__(registry, config)
        self._auth: Optional[MSGraphAuth] = None
        # id -> managedDevice. See _build_device_map.
        self._devices: dict = {}

    def check_prerequisites(self) -> tuple[bool, str]:
        try:
            self._auth = MSGraphAuth.from_env(
                self.config.credential_env_prefix or "AIGUARD_ENTRA"
            )
            return True, "Intune credentials loaded"
        except AuthError as e:
            return False, str(e)

    async def scan(self) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        start = datetime.now(timezone.utc)

        try:
            client = await self._auth.graph_client()

            # Fetched once, before anything else needs it. Everything the
            # per-app lookup claims about a device is a stub, so this is where
            # device attributes actually come from.
            self._devices = await self._build_device_map(client)

            app_findings, app_errors = await self._scan_discovered_apps(client)
            result.findings.extend(app_findings)
            result.errors.extend(app_errors)

            await client.aclose()

        except Exception as e:
            result.errors.append(f"Intune scan failed: {e}")

        result.duration_seconds = (datetime.now(timezone.utc) - start).total_seconds()
        return result

    async def _build_device_map(self, client) -> dict:
        """Every managed device, keyed on the id the app lookup returns.

        The detectedApps sub-resource returns a device id and a device name and
        stubs the rest, so the real attributes have to come from the devices
        resource itself. One page covers a fleet of a few hundred; paginate
        handles anything larger and honours Retry-After on the way.

        An empty map is not fatal. The caller falls back to what the sub
        resource gave it, which is the behaviour this replaces, and says so.
        """
        url = (
            "/deviceManagement/managedDevices"
            "?$select=id,deviceName,serialNumber,userPrincipalName,"
            "lastSyncDateTime,operatingSystem&$top=999"
        )
        try:
            devices = await paginate(client, url)
        except Exception as e:
            logger.warning(
                "Intune: could not read managed devices (%s). Findings will "
                "carry the device name rather than the serial, and the stale "
                "filter cannot run.", e,
            )
            return {}
        out = {}
        for d in devices:
            did = d.get("id")
            if did:
                out[did] = d
        logger.info("Intune: %d managed device(s) in inventory", len(out))
        return out

    async def _scan_discovered_apps(
        self, client
    ) -> tuple[list[Finding], list[str]]:
        """Query Intune discovered apps for known AI tool executables.

        Returns findings and any errors worth surfacing. A device lookup that
        fails degrades that app to an aggregate count rather than aborting the
        scan, but the degradation is reported: an aggregate finding that looks
        identical to a successful one, with no indication attribution was
        attempted and failed, is worse than no finding at all.
        """
        findings: list[Finding] = []
        errors: list[str] = []

        # GET /deviceManagement/detectedApps lists apps found on managed devices.
        # Follow @odata.nextLink pagination to avoid silently truncated results.
        url = "/deviceManagement/detectedApps?$top=500"

        try:
            apps = await paginate(client, url)
        except Exception as e:
            raise RuntimeError(f"Failed to query Intune discovered apps: {e}") from e

        failed_lookups: list[str] = []
        first_reason: Optional[str] = None

        stale_days = int(self.config.options.get(
            "stale_device_days", DEFAULT_STALE_DEVICE_DAYS))
        lookup_delay = float(self.config.options.get(
            "app_lookup_delay_seconds", DEFAULT_APP_LOOKUP_DELAY))
        lookups_made = 0
        cutoff = (datetime.now(timezone.utc) - timedelta(days=stale_days)
                  if stale_days > 0 else None)
        stale_skipped = 0

        for app in apps:
            app_name = app.get("displayName", "")
            device_count = app.get("deviceCount", 0)

            service = self.registry.match_desktop_app(app_name)
            if not service:
                # Exact lookup failed, which is the normal case here: it is
                # keyed on the registry's own strings, and Intune reports a
                # different scheme. Compare both sides normalised instead.
                #
                # Longest known name first, so "Claude Code" is not claimed by
                # "Claude" when both are in the registry.
                norm_app = _normalise_app_name(app_name)
                if norm_app:
                    best = None
                    best_len = 0
                    for svc in self.registry.services:
                        for known in _windows_names(svc):
                            if len(known) <= best_len:
                                continue
                            # Equality only, after both sides are normalised.
                            # Prefix matching looks tempting and is wrong:
                            # "Claude Code" would be attributed to Claude,
                            # because claude-code is detected through its CLI
                            # config and carries no desktop app names. A
                            # finding against the wrong tool is worse than no
                            # finding, and the version stripping above already
                            # handles "LM Studio 0.3.20".
                            if norm_app == known:
                                best, best_len = svc, len(known)
                    service = best

            if not service:
                continue

            app_id = app.get("id", "")
            # Before the call rather than after, and skipped for the first, so
            # a single matched app costs nothing.
            if lookup_delay > 0 and lookups_made:
                await asyncio.sleep(lookup_delay)
            lookups_made += 1
            devices, lookup_error = await self._get_app_devices(client, app_id)

            if lookup_error:
                failed_lookups.append(app_name)
                if first_reason is None:
                    first_reason = lookup_error

            if devices:
                for device in devices:
                    # The sub-resource gives a usable id and a usable name and
                    # stubs everything else, so the real record is looked up
                    # here. Missing means the device is not in the inventory
                    # any more, which is worth reporting rather than dropping:
                    # the app is still installed somewhere.
                    real = self._devices.get(device.get("id")) or {}

                    # Skip devices that stopped syncing long ago. Counted and
                    # logged below rather than dropped silently. Only the
                    # inventory timestamp is trusted: the sub-resource returns
                    # year one for every device, which is older than any
                    # cutoff and skipped the entire fleet.
                    if cutoff is not None and real:
                        last_sync = _parse_ts(real.get("lastSyncDateTime"))
                        if last_sync is not None and last_sync < cutoff:
                            stale_skipped += 1
                            continue
                    findings.append(
                        Finding(
                            service=service,
                            source=DetectionSource.INTUNE_APP,
                            risk_tier=service.risk_tier,
                            user_upn=(real.get("userPrincipalName")
                                      or device.get("upn")),
                            # Device identity is the hardware serial, the same
                            # rule jamf.py follows: the endpoint collector on
                            # this machine reports its BIOS serial, so a device
                            # keyed on its computer name appears twice on any
                            # view that joins on device.
                            device_name=((real.get("serialNumber") or "").strip()
                                         or device.get("device_name")),
                            detail=f"{app_name} installed on {device.get('device_name', 'unknown')}",
                            raw_evidence={
                                "app_name": app_name,
                                "device_name": (real.get("deviceName")
                                                or device.get("device_name")),
                                "managed_device_id": device.get("id"),
                                "last_sync": real.get("lastSyncDateTime"),
                            },
                        )
                    )
            else:
                # No per-device detail. Say which kind of "no detail" this is,
                # so an operator can tell a permissions problem from an app
                # that genuinely resolved to nothing.
                if lookup_error:
                    detail = (
                        f"{app_name} found on {device_count} device(s); "
                        f"per-device attribution unavailable ({lookup_error})"
                    )
                else:
                    detail = f"{app_name} found on {device_count} device(s)"

                findings.append(
                    Finding(
                        service=service,
                        source=DetectionSource.INTUNE_APP,
                        risk_tier=service.risk_tier,
                        detail=detail,
                        occurrence_count=device_count,
                        raw_evidence={
                            "app_name": app_name,
                            "device_count": device_count,
                            "attribution_failed": bool(lookup_error),
                        },
                    )
                )

        if failed_lookups:
            errors.append(
                f"Device attribution failed for {len(failed_lookups)} app(s) "
                f"({', '.join(failed_lookups[:5])}"
                f"{', ...' if len(failed_lookups) > 5 else ''}); "
                f"those findings are aggregate counts with no user or device. "
                f"First error: {first_reason}. "
                f"DeviceManagementManagedDevices.Read.All is required for "
                f"per-device attribution."
            )

        if stale_skipped:
            logger.info(
                "Intune: skipped %d device record(s) with no sync in %d days. "
                "Set stale_device_days in the scanner options to change this.",
                stale_skipped, stale_days,
            )

        return findings, errors

    async def _get_app_devices(
        self, client, app_id: str
    ) -> tuple[list[dict], Optional[str]]:
        """Get devices that have a specific discovered app.

        Returns (devices, error). An empty list with no error means the app
        really is on no managed devices; an empty list with an error means the
        lookup did not work. Collapsing those two into one value is how a
        permissions problem gets mistaken for a clean estate.

        Paginated: a popular app can exceed one page, and a silently truncated
        device list understates exposure.
        """
        url = (
            f"/deviceManagement/detectedApps/{app_id}/managedDevices"
            # serialNumber and lastSyncDateTime are deliberately not asked
            # for: this endpoint answers 200 and returns null and year one for
            # them, which is worse than refusing, and trusting them skipped
            # the entire fleet as stale. userPrincipalName is null here too on
            # at least one tenant, but it costs nothing to ask and it keeps
            # the fallback below real when the device map is unavailable.
            f"?$select=deviceName,id,userPrincipalName"
        )
        try:
            devices = await paginate(client, url)
        except Exception as e:
            logger.warning(
                "Intune: device lookup failed for detectedApp %s: %s", app_id, e
            )
            return [], str(e)

        return [
            {
                # Device identity is the hardware serial, the same rule
                # jamf.py follows: the endpoint collector on this machine
                # reports its BIOS serial, so a device keyed here on its
                # computer name appears twice on any view that joins on
                # device. The friendly name is kept for display.
                "device_name": d.get("deviceName"),
                "id": d.get("id"),
                "upn": d.get("userPrincipalName"),
            }
            for d in devices
        ], None