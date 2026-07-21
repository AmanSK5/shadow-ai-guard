"""Demo mode fixture scanner.

Reads static JSON fixture files and produces ScanResult objects
identical to what real scanners would return. Used with --demo flag
for video walkthroughs and demos without live API credentials.

Timestamps in fixtures are stored as relative offsets (days_ago)
and resolved to real datetimes at load time so the demo never ages.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from ai_guard.config import ScannerConfig
from ai_guard.registry import AIService, Registry
from ai_guard.scanners.base import (
    BaseScanner,
    DetectionSource,
    Finding,
    ScanResult,
)

# Default fixture directory relative to project root
FIXTURE_DIR = Path(__file__).parent.parent.parent / "fixtures" / "demo"


class FixtureScanner(BaseScanner):
    """Scanner that reads findings from a JSON fixture file.

    Acts as a drop-in replacement for any real scanner during demo mode.
    The fixture JSON contains pre-built findings that get hydrated into
    proper Finding objects using the registry for service lookups.
    """

    def __init__(
        self,
        registry: Registry,
        config: ScannerConfig,
        scanner_name: str,
        fixture_path: Path,
    ):
        super().__init__(registry, config)
        self.name = scanner_name
        self._fixture_path = fixture_path

    def check_prerequisites(self) -> tuple[bool, str]:
        if not self._fixture_path.exists():
            return False, f"Fixture file not found: {self._fixture_path}"
        return True, "Demo fixture loaded"

    async def scan(self) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        now = datetime.now(timezone.utc)

        with open(self._fixture_path, "r") as f:
            data = json.load(f)

        for entry in data.get("findings", []):
            finding = self._hydrate_finding(entry, now)
            if finding:
                result.findings.append(finding)

        duration = data.get("duration_seconds", 1.2)
        await asyncio.sleep(duration)
        result.duration_seconds = duration
        return result

    def _hydrate_finding(self, entry: dict, now: datetime) -> Optional[Finding]:
        """Convert a fixture entry dict into a Finding object."""
        service_name = entry.get("service_name", "")

        service = self._find_service(service_name)
        if not service:
            service = AIService(
                name=service_name,
                vendor=entry.get("vendor", "Unknown"),
                category=entry.get("category", "chatbot"),
                risk_tier=entry.get("risk_tier", "medium"),
                domains=entry.get("domains", []),
            )

        source = DetectionSource(entry["source"])

        return Finding(
            service=service,
            source=source,
            risk_tier=entry.get("risk_tier", service.risk_tier),
            user_upn=entry.get("user_upn"),
            device_name=entry.get("device_name"),
            detail=entry.get("detail", ""),
            raw_evidence=entry.get("raw_evidence", {}),
            timestamp=_resolve_offset(now, entry.get("timestamp_days_ago")),
            first_seen=_resolve_offset(now, entry.get("first_seen_days_ago")),
            last_seen=_resolve_offset(now, entry.get("last_seen_days_ago")),
            occurrence_count=entry.get("occurrence_count", 1),
        )

    def _find_service(self, name: str) -> Optional[AIService]:
        """Find a service in the registry by name."""
        for svc in self.registry.services:
            if svc.name.lower() == name.lower():
                return svc
        return None


def load_demo_scanners(registry: Registry) -> list[FixtureScanner]:
    """Load all fixture scanners for demo mode."""
    scanners = []
    scanner_names = ["sentinelone", "entra", "exchange", "intune", "jamf", "mcp"]

    for name in scanner_names:
        fixture_path = FIXTURE_DIR / f"{name}.json"
        if fixture_path.exists():
            scanners.append(FixtureScanner(
                registry=registry,
                config=ScannerConfig(enabled=True),
                scanner_name=name,
                fixture_path=fixture_path,
            ))

    return scanners


def _resolve_offset(now: datetime, days_ago: Optional[int]) -> Optional[datetime]:
    """Convert a relative day offset to an absolute datetime."""
    if days_ago is None:
        return None
    return now - timedelta(days=days_ago)
