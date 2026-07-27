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

import logging
from datetime import datetime, timezone

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


class IntuneScanner(BaseScanner):
    name = "intune"

    def __init__(self, registry: Registry, config: ScannerConfig):
        super().__init__(registry, config)
        self._auth: Optional[MSGraphAuth] = None

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

            app_findings, app_errors = await self._scan_discovered_apps(client)
            result.findings.extend(app_findings)
            result.errors.extend(app_errors)

            await client.aclose()

        except Exception as e:
            result.errors.append(f"Intune scan failed: {e}")

        result.duration_seconds = (datetime.now(timezone.utc) - start).total_seconds()
        return result

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

        for app in apps:
            app_name = app.get("displayName", "")
            device_count = app.get("deviceCount", 0)

            service = self.registry.match_desktop_app(app_name)
            if not service:
                # Fuzzy: check if app name contains any known service name
                for svc in self.registry.services:
                    win_apps = svc.desktop_apps.get("windows", [])
                    for known_app in win_apps:
                        if known_app.lower() in app_name.lower():
                            service = svc
                            break
                    if service:
                        break

            if not service:
                continue

            app_id = app.get("id", "")
            devices, lookup_error = await self._get_app_devices(client, app_id)

            if lookup_error:
                failed_lookups.append(app_name)
                if first_reason is None:
                    first_reason = lookup_error

            if devices:
                for device in devices:
                    findings.append(
                        Finding(
                            service=service,
                            source=DetectionSource.INTUNE_APP,
                            risk_tier=service.risk_tier,
                            user_upn=device.get("upn"),
                            device_name=device.get("device_name"),
                            detail=f"{app_name} installed on {device.get('device_name', 'unknown')}",
                            raw_evidence={
                                "app_name": app_name,
                                "device_name": device.get("device_name"),
                                "managed_device_id": device.get("id"),
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
            f"?$select=deviceName,userPrincipalName,id"
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
                "device_name": d.get("deviceName"),
                "upn": d.get("userPrincipalName"),
                "id": d.get("id"),
            }
            for d in devices
        ], None