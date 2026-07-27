"""Base scanner interface and shared data types.

All scanner modules inherit from BaseScanner and produce Finding objects.
The report generator consumes findings from all scanners uniformly.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional

from ai_guard.config import ScannerConfig
from ai_guard.registry import AIService, Registry


class DetectionSource(str, Enum):
    """Which scanner module produced this finding."""

    ENTRA_SIGN_IN = "entra_sign_in"
    ENTRA_SERVICE_PRINCIPAL = "entra_service_principal"
    ENTRA_CONSENT_GRANT = "entra_consent_grant"
    SENTINELONE_DNS = "sentinelone_dns"
    SENTINELONE_NETWORK = "sentinelone_network"
    SENTINELONE_BRIDGE = "sentinelone_bridge"
    EXCHANGE_EMAIL = "exchange_email"
    INTUNE_APP = "intune_app"
    INTUNE_EXTENSION = "intune_extension"
    JAMF_APP = "jamf_app"
    JAMF_EXTENSION = "jamf_extension"
    MCP_SCAN = "mcp_scan"


# occurrence_count is a different quantity per source: sign-in events for
# Entra, installed devices for Intune, signup emails for Exchange. The number
# alone invites comparing things that are not comparable, so anything that
# publishes the count publishes the unit alongside it. Sources that never
# aggregate stay at 1 and report "detections".
OCCURRENCE_UNIT: dict["DetectionSource", str] = {
    DetectionSource.ENTRA_SIGN_IN: "sign-ins",
    DetectionSource.EXCHANGE_EMAIL: "signup emails",
    DetectionSource.INTUNE_APP: "devices",
}


def occurrence_unit(source: "DetectionSource") -> str:
    return OCCURRENCE_UNIT.get(source, "detections")


@dataclass
class Finding:
    """A single detection of AI tool usage or risk."""

    # What was detected
    service: AIService
    source: DetectionSource
    risk_tier: str  # may be overridden by policy

    # Who / where
    user_upn: Optional[str] = None
    device_name: Optional[str] = None

    # Evidence
    detail: str = ""
    raw_evidence: dict = field(default_factory=dict)

    # When
    timestamp: Optional[datetime] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    occurrence_count: int = 1

    @property
    def summary(self) -> str:
        who = self.user_upn or self.device_name or "unknown"
        return f"[{self.risk_tier.upper()}] {self.service.name} detected via {self.source.value} — {who}: {self.detail}"


@dataclass
class ScanResult:
    """Output of a single scanner module run."""

    scanner_name: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    skipped_reason: Optional[str] = None
    duration_seconds: float = 0.0

    @property
    def success(self) -> bool:
        return self.skipped_reason is None and len(self.errors) == 0

    @property
    def finding_count(self) -> int:
        return len(self.findings)


class BaseScanner(ABC):
    """Interface that all scanner modules implement."""

    name: str = "base"

    def __init__(self, registry: Registry, config: ScannerConfig):
        self.registry = registry
        self.config = config

    @abstractmethod
    async def scan(self) -> ScanResult:
        """Run the scan and return findings."""
        ...

    @abstractmethod
    def check_prerequisites(self) -> tuple[bool, str]:
        """Verify API connectivity / credentials before scanning.

        Returns (ok, message). If ok is False, the scanner is skipped
        and message is set as skipped_reason on ScanResult.
        """
        ...