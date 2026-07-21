"""Configuration loader.

Loads the org policy YAML which defines risk tolerance, scanner toggles,
API credentials references, and output preferences.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


@dataclass
class ScannerConfig:
    """Config for an individual scanner module."""

    enabled: bool = False
    # API connection details (loaded from env vars, not stored in config)
    credential_env_prefix: str = ""
    # Scanner-specific options
    options: dict = field(default_factory=dict)


@dataclass
class PolicyConfig:
    """Org-level policy configuration."""

    # How far back to look (days)
    lookback_days: int = 30

    # Risk tier overrides (service_name -> tier)
    risk_overrides: dict[str, str] = field(default_factory=dict)

    # Approved services (won't flag as shadow AI)
    approved_services: list[str] = field(default_factory=list)

    # Blocked services (always flag, even if approved elsewhere)
    blocked_services: list[str] = field(default_factory=list)


@dataclass
class Config:
    """Top-level configuration."""

    scanners: dict[str, ScannerConfig] = field(default_factory=dict)
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    output_format: str = "terminal"  # terminal | json | csv
    output_path: Optional[str] = None

    @classmethod
    def from_file(cls, path: Path) -> "Config":
        with open(path, "r") as f:
            data = yaml.safe_load(f) or {}

        scanners = {}
        for name, sconf in data.get("scanners", {}).items():
            scanners[name] = ScannerConfig(
                enabled=sconf.get("enabled", False),
                credential_env_prefix=sconf.get("credential_env_prefix", ""),
                options=sconf.get("options", {}),
            )

        policy_data = data.get("policy", {})
        policy = PolicyConfig(
            lookback_days=policy_data.get("lookback_days", 30),
            risk_overrides=policy_data.get("risk_overrides", {}),
            approved_services=policy_data.get("approved_services", []),
            blocked_services=policy_data.get("blocked_services", []),
        )

        return cls(
            scanners=scanners,
            policy=policy,
            output_format=data.get("output_format", "terminal"),
            output_path=data.get("output_path"),
        )

    @classmethod
    def default(cls) -> "Config":
        """Sensible defaults with all scanners disabled."""
        return cls(
            scanners={
                "entra": ScannerConfig(
                    enabled=False,
                    credential_env_prefix="AIGUARD_ENTRA",
                ),
                "sentinelone": ScannerConfig(
                    enabled=False,
                    credential_env_prefix="AIGUARD_S1",
                ),
                "exchange": ScannerConfig(
                    enabled=False,
                    credential_env_prefix="AIGUARD_EXCHANGE",
                ),
                "intune": ScannerConfig(
                    enabled=False,
                    credential_env_prefix="AIGUARD_INTUNE",
                ),
                "jamf": ScannerConfig(
                    enabled=False,
                    credential_env_prefix="AIGUARD_JAMF",
                ),
                "mcp": ScannerConfig(enabled=True),  # No API needed
            },
            policy=PolicyConfig(),
        )
