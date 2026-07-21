"""JAMF Pro scanner.

Queries JAMF Pro API for:
  1. Application inventory: AI desktop apps on managed Macs

Device identity is the hardware serial, not the friendly computer name.
The browser extension and the endpoint collector both report serials; a Mac
called "Jane's MacBook Pro (2)" cannot be reconciled with C02XK1ABCDEF, so
the same machine would appear twice on the dashboard.
"""

from __future__ import annotations

import logging
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
from ai_guard.utils.auth import AuthError, JAMFAuth

logger = logging.getLogger(__name__)

PAGE_SIZE = 100
MAX_PAGES = 50  # 5000 Macs; log and stop rather than loop forever


class JAMFScanner(BaseScanner):
    name = "jamf"

    def __init__(self, registry: Registry, config: ScannerConfig):
        super().__init__(registry, config)
        self._auth: Optional[JAMFAuth] = None

    def check_prerequisites(self) -> tuple[bool, str]:
        try:
            self._auth = JAMFAuth.from_env(
                self.config.credential_env_prefix or "AIGUARD_JAMF"
            )
            return True, "JAMF credentials loaded"
        except AuthError as e:
            return False, str(e)

    async def scan(self) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        start = datetime.now(timezone.utc)
        try:
            client = await self._auth.client()
            app_findings = await self._scan_applications(client)
            result.findings.extend(app_findings)
            await client.aclose()
        except Exception as e:
            result.errors.append(f"JAMF scan failed: {e}")

        result.duration_seconds = (datetime.now(timezone.utc) - start).total_seconds()
        return result

    async def _fetch_inventory(self, client) -> list[dict]:
        """All computers with application inventory, following pagination.

        The previous implementation read page 0 only, silently truncating the
        fleet at 100 Macs.
        """
        computers: list[dict] = []
        for page in range(MAX_PAGES):
            resp = await client.get(
                "/computers-inventory"
                "?section=APPLICATIONS&section=USER_AND_LOCATION"
                "&section=GENERAL&section=HARDWARE"
                f"&page-size={PAGE_SIZE}&page={page}"
            )
            resp.raise_for_status()
            body = resp.json()
            batch = body.get("results", [])
            computers.extend(batch)

            total = body.get("totalCount", 0)
            if len(computers) >= total or not batch:
                break
            if page == MAX_PAGES - 1:
                logger.warning(
                    "JAMF: stopped at %d computers (totalCount %d) — "
                    "raise MAX_PAGES",
                    len(computers), total,
                )
        logger.info("JAMF: %d computers in inventory", len(computers))
        return computers

    async def _scan_applications(self, client) -> list[Finding]:
        """Match installed applications against known AI services."""
        findings = []

        try:
            computers = await self._fetch_inventory(client)
        except Exception as e:
            raise RuntimeError(f"Failed to query JAMF inventory: {e}") from e

        for computer in computers:
            general = computer.get("general") or {}
            hardware = computer.get("hardware") or {}
            user_location = computer.get("userAndLocation") or {}

            friendly_name = general.get("name") or "unknown"
            # Serial is the identity every other surface reports.
            serial = hardware.get("serialNumber") or friendly_name
            upn = user_location.get("email") or user_location.get("username")

            # One finding per service per Mac. An app can match on both its
            # bundle id and its .app name, and suites ship several binaries;
            # neither means two installations.
            seen: set[str] = set()

            for app in computer.get("applications") or []:
                # Jamf returns null (not "") for apps with no bundle id:
                # App Store stubs, pkg-installed binaries, some wrappers.
                bundle_id = app.get("bundleId") or ""
                app_name = app.get("name") or ""

                # Registry indexes bundle ids and .app names in the same
                # desktop-app map, so one lookup each covers both. The old
                # substring fallback ("Claude" in "iCloud Drive.app") was a
                # false-positive generator.
                service = (
                    self.registry.match_desktop_app(bundle_id)
                    if bundle_id
                    else None
                )
                if not service and app_name:
                    service = self.registry.match_desktop_app(app_name)
                if not service:
                    continue

                key = getattr(service, "label", None) or service.name
                if key in seen:
                    continue
                seen.add(key)

                findings.append(
                    Finding(
                        service=service,
                        source=DetectionSource.JAMF_APP,
                        risk_tier=service.risk_tier,
                        user_upn=upn,
                        device_name=serial,
                        detail=(
                            f"{app_name or bundle_id} installed on {friendly_name}"
                        ),
                        raw_evidence={
                            "bundle_id": bundle_id,
                            "app_name": app_name,
                            "device_name": friendly_name,
                            "serial": serial,
                            "app_version": app.get("version") or "",
                        },
                    )
                )
        return findings