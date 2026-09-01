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
    ENTRA_DELEGATED_ACCESS = "entra_delegated_access"
    SENTINELONE_DNS = "sentinelone_dns"
    SENTINELONE_NETWORK = "sentinelone_network"
    SENTINELONE_BRIDGE = "sentinelone_bridge"
    EXCHANGE_EMAIL = "exchange_email"
    INTUNE_APP = "intune_app"
    INTUNE_EXTENSION = "intune_extension"
    JAMF_APP = "jamf_app"
    JAMF_EXTENSION = "jamf_extension"
    MCP_SCAN = "mcp_scan"


# What a finding proves: that a model actually ran ("active"), or only that
# the product is present on the machine ("ambient").
#
# For almost every tool in the registry the two are the same thing - a Claude
# desktop app or an Otter extension has no purpose except its AI, so finding
# it installed IS finding it used. The exception is a product that is an
# editor first and bundles AI second: Cursor and Windsurf/Devin Desktop are
# VS Code forks, and someone can run one all day without ever invoking a
# model. Reporting those the same way is how "23 people use AI" comes to mean
# "23 people have an editor installed", which is the same mistake as
# identifying Notion AI by notion.so.
#
# Only a tool the registry marks `form: ide` can ever be ambient. Everything
# else stays active and nothing about it changes.
SIGNAL_ACTIVE = "active"
SIGNAL_AMBIENT = "ambient"

# Inventory sources: they enumerate installed software and nothing more. For
# an IDE fork that is exactly the weak claim - the editor is on the machine.
_PRESENCE_ONLY = frozenset({
    "intune_app",
    "jamf_app",
})


def classify_signal(service, source, host: str = "") -> str:
    """Whether this finding shows the AI ran, or only that it is installed.

    `service` is an AIService; a BridgeTarget (which has no form) is always
    active, because a non-browser process holding a token is use by
    definition.

    Extension findings stay active even on an IDE fork: `extension_ids` names
    the AI plugin itself, not the editor hosting it, so installing one is a
    deliberate choice to add AI - the same reason plain VS Code is detected
    through its extensions rather than being in the registry at all.
    """
    if getattr(service, "form", "") != "ide":
        return SIGNAL_ACTIVE
    value = getattr(source, "value", source) or ""
    if value in _PRESENCE_ONLY:
        return SIGNAL_AMBIENT
    if host:
        return service.domain_signal(host)
    return SIGNAL_ACTIVE


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

    # active | ambient. See classify_signal above. Defaults to active so a
    # scanner that never sets it keeps reporting exactly what it did before.
    signal: str = SIGNAL_ACTIVE

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