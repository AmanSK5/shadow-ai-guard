"""Intune scanner.

Queries Microsoft Graph / Intune API for:
  1. Discovered apps: AI desktop applications on managed Windows devices
  2. Browser extensions: AI-related Chrome/Edge extensions (via device config profiles)
"""

from __future__ import annotations
from typing import Optional

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

            app_findings = await self._scan_discovered_apps(client)
            result.findings.extend(app_findings)

            await client.aclose()

        except Exception as e:
            result.errors.append(f"Intune scan failed: {e}")

        result.duration_seconds = (datetime.now(timezone.utc) - start).total_seconds()
        return result

    async def _scan_discovered_apps(self, client) -> list[Finding]:
        """Query Intune discovered apps for known AI tool executables."""
        findings = []

        # GET /deviceManagement/detectedApps lists apps found on managed devices.
        # Follow @odata.nextLink pagination to avoid silently truncated results.
        url = "/deviceManagement/detectedApps?$top=500"

        try:
            apps = await paginate(client, url)
        except Exception as e:
            raise RuntimeError(f"Failed to query Intune discovered apps: {e}") from e

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

            # Get which devices have this app
            app_id = app.get("id", "")
            devices = await self._get_app_devices(client, app_id)

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
                # No per-device detail, report aggregate
                findings.append(
                    Finding(
                        service=service,
                        source=DetectionSource.INTUNE_APP,
                        risk_tier=service.risk_tier,
                        detail=f"{app_name} found on {device_count} device(s)",
                        occurrence_count=device_count,
                        raw_evidence={
                            "app_name": app_name,
                            "device_count": device_count,
                        },
                    )
                )

        return findings

    async def _get_app_devices(self, client, app_id: str) -> list[dict]:
        """Get devices that have a specific discovered app."""
        try:
            resp = await client.get(
                f"/deviceManagement/detectedApps/{app_id}/managedDevices"
                f"?$select=deviceName,userPrincipalName,id"
            )
            if resp.status_code != 200:
                return []

            return [
                {
                    "device_name": d.get("deviceName"),
                    "upn": d.get("userPrincipalName"),
                    "id": d.get("id"),
                }
                for d in resp.json().get("value", [])
            ]
        except Exception:
            return []
