"""MCP security scanner.

Evaluates MCP server definitions against a risk framework aligned to
the OWASP Agentic AI Top 10. Takes an MCP server config (JSON/YAML)
and produces a security assessment with allow/block recommendation.

This module does not require API credentials — it analyses static
configuration files or fetched registry entries.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

import yaml

from ai_guard.config import ScannerConfig
from ai_guard.registry import Registry
from ai_guard.scanners.base import (
    BaseScanner,
    DetectionSource,
    Finding,
    ScanResult,
)


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Verdict(str, Enum):
    BLOCK = "block"
    ALLOW_WITH_CONDITIONS = "allow_with_conditions"
    ALLOW = "allow"


@dataclass
class MCPRisk:
    """A single risk identified in an MCP server definition."""

    category: str  # Maps to OWASP Agentic AI Top 10 category
    level: RiskLevel
    title: str
    detail: str
    recommendation: str


@dataclass
class MCPAssessment:
    """Full security assessment of an MCP server."""

    server_name: str
    server_description: str
    verdict: Verdict = Verdict.BLOCK  # Default to block, overridden by assessment
    risks: list[MCPRisk] = field(default_factory=list)
    tool_count: int = 0
    read_tools: list[str] = field(default_factory=list)
    write_tools: list[str] = field(default_factory=list)
    oauth_scopes: list[str] = field(default_factory=list)
    auth_method: str = "unknown"
    data_access_summary: str = ""

    @property
    def critical_count(self) -> int:
        return sum(1 for r in self.risks if r.level == RiskLevel.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for r in self.risks if r.level == RiskLevel.HIGH)


# Heuristics for classifying tools as read vs write
WRITE_INDICATORS = [
    "create", "update", "delete", "remove", "edit", "modify", "write",
    "add", "set", "patch", "put", "post", "send", "publish", "assign",
    "move", "rename", "archive", "close", "merge", "approve", "reject",
]

READ_INDICATORS = [
    "get", "list", "read", "search", "query", "fetch", "find",
    "describe", "show", "view", "count", "check", "status",
]

# Known risky OAuth scope patterns
BROAD_SCOPE_PATTERNS = [
    "read:all", "write:all", "admin", "manage:",
    ".readwrite", "files.readwrite", "mail.read",
    "sites.readwrite", "user.readwrite",
]

# OWASP Agentic AI Top 10 categories (2025)
OWASP_CATEGORIES = {
    "AG01": "Agentic Identity and Trust",
    "AG02": "Tool and Function Abuse",
    "AG03": "Prompt Injection via Agent Tools",
    "AG04": "Excessive Agency and Autonomy",
    "AG05": "Data Exfiltration via Agent Actions",
    "AG06": "Insufficient Access Controls",
    "AG07": "Insecure Agent Communication",
    "AG08": "Overreliance on Agent Output",
    "AG09": "Agent State and Session Manipulation",
    "AG10": "Uncontrolled Agent Chaining",
}


class MCPScanner(BaseScanner):
    name = "mcp"

    def __init__(self, registry: Registry, config: ScannerConfig):
        super().__init__(registry, config)
        self._mcp_configs: list[dict] = []

    def check_prerequisites(self) -> tuple[bool, str]:
        # Check if MCP config paths are specified
        config_paths = self.config.options.get("mcp_config_paths", [])
        if not config_paths:
            return True, "MCP scanner ready (no configs specified, use --mcp-config to scan)"
        return True, f"MCP scanner ready ({len(config_paths)} config(s) to scan)"

    async def scan(self) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        start = datetime.now(timezone.utc)

        config_paths = self.config.options.get("mcp_config_paths", [])

        for path_str in config_paths:
            path = Path(path_str)
            if not path.exists():
                result.errors.append(f"MCP config not found: {path}")
                continue

            try:
                mcp_def = self._load_mcp_config(path)
                assessment = self._assess(mcp_def)

                # Convert assessment risks to findings
                for risk in assessment.risks:
                    service = self.registry.match_mcp_identifier(
                        mcp_def.get("name", "")
                    )
                    findings_risk_tier = {
                        RiskLevel.CRITICAL: "high",
                        RiskLevel.HIGH: "high",
                        RiskLevel.MEDIUM: "medium",
                        RiskLevel.LOW: "low",
                        RiskLevel.INFO: "low",
                    }

                    result.findings.append(
                        Finding(
                            service=service or _unknown_service(mcp_def),
                            source=DetectionSource.MCP_SCAN,
                            risk_tier=findings_risk_tier.get(risk.level, "medium"),
                            detail=f"[{risk.category}] {risk.title}: {risk.detail}",
                            raw_evidence={
                                "assessment_verdict": assessment.verdict.value,
                                "risk_category": risk.category,
                                "risk_level": risk.level.value,
                                "recommendation": risk.recommendation,
                            },
                        )
                    )

            except Exception as e:
                result.errors.append(f"Failed to assess {path}: {e}")

        result.duration_seconds = (datetime.now(timezone.utc) - start).total_seconds()
        return result

    def _load_mcp_config(self, path: Path) -> dict:
        with open(path, "r") as f:
            if path.suffix in (".yaml", ".yml"):
                return yaml.safe_load(f)
            else:
                import json
                return json.load(f)

    def _assess(self, mcp_def: dict) -> MCPAssessment:
        """Run all risk checks against an MCP server definition."""
        name = mcp_def.get("name", "unknown")
        description = mcp_def.get("description", "")
        tools = mcp_def.get("tools", [])
        auth = mcp_def.get("auth", {})
        scopes = auth.get("scopes", [])

        assessment = MCPAssessment(
            server_name=name,
            server_description=description,
            tool_count=len(tools),
            auth_method=auth.get("type", "unknown"),
            oauth_scopes=scopes,
        )

        # Classify tools as read vs write
        for tool in tools:
            tool_name = tool.get("name", "").lower()
            tool_desc = (tool.get("description", "") or "").lower()
            combined = f"{tool_name} {tool_desc}"

            is_write = any(w in combined for w in WRITE_INDICATORS)
            is_read = any(r in combined for r in READ_INDICATORS)

            if is_write:
                assessment.write_tools.append(tool.get("name", ""))
            elif is_read:
                assessment.read_tools.append(tool.get("name", ""))
            else:
                # Ambiguous - treat as write (conservative)
                assessment.write_tools.append(tool.get("name", ""))

        # Run risk checks
        self._check_write_access(assessment)
        self._check_broad_scopes(assessment, scopes)
        self._check_auth_method(assessment, auth)
        self._check_data_ingestion(assessment, tools)
        self._check_tool_count(assessment)
        self._check_no_tool_filtering(assessment, mcp_def)

        # Determine verdict
        if assessment.critical_count > 0 or assessment.high_count >= 3:
            assessment.verdict = Verdict.BLOCK
        elif assessment.high_count > 0:
            assessment.verdict = Verdict.ALLOW_WITH_CONDITIONS
        else:
            assessment.verdict = Verdict.ALLOW

        return assessment

    def _check_write_access(self, assessment: MCPAssessment) -> None:
        if assessment.write_tools:
            assessment.risks.append(
                MCPRisk(
                    category="AG04",
                    level=RiskLevel.HIGH,
                    title="Write access to external system",
                    detail=(
                        f"{len(assessment.write_tools)} tool(s) have write capabilities: "
                        f"{', '.join(assessment.write_tools[:5])}"
                    ),
                    recommendation=(
                        "Restrict to read-only tools where possible. "
                        "If write access is needed, require human approval for actions."
                    ),
                )
            )

    def _check_broad_scopes(self, assessment: MCPAssessment, scopes: list[str]) -> None:
        broad = [s for s in scopes if any(p in s.lower() for p in BROAD_SCOPE_PATTERNS)]
        if broad:
            assessment.risks.append(
                MCPRisk(
                    category="AG06",
                    level=RiskLevel.HIGH,
                    title="Overly broad OAuth scopes",
                    detail=f"Broad scopes requested: {', '.join(broad)}",
                    recommendation=(
                        "Request minimum necessary scopes. "
                        "Prefer read-only scopes over read-write."
                    ),
                )
            )

    def _check_auth_method(self, assessment: MCPAssessment, auth: dict) -> None:
        auth_type = auth.get("type", "").lower()

        if not auth_type or auth_type == "none":
            assessment.risks.append(
                MCPRisk(
                    category="AG01",
                    level=RiskLevel.CRITICAL,
                    title="No authentication",
                    detail="MCP server requires no authentication",
                    recommendation="Require OAuth 2.0 or API key authentication at minimum.",
                )
            )
        elif auth_type == "api_key":
            assessment.risks.append(
                MCPRisk(
                    category="AG01",
                    level=RiskLevel.MEDIUM,
                    title="API key authentication",
                    detail="API key auth provides no per-user scoping or revocation",
                    recommendation=(
                        "Prefer OAuth 2.0 with per-user tokens for "
                        "user-scoped access and audit trail."
                    ),
                )
            )

    def _check_data_ingestion(self, assessment: MCPAssessment, tools: list[dict]) -> None:
        """Check for tools that bulk-read data (prompt injection surface)."""
        bulk_read_indicators = [
            "search", "list", "get_all", "export", "dump", "bulk",
            "read_page", "read_document", "get_content", "get_file",
        ]
        bulk_tools = []
        for tool in tools:
            tool_name = tool.get("name", "").lower()
            if any(ind in tool_name for ind in bulk_read_indicators):
                bulk_tools.append(tool.get("name", ""))

        if bulk_tools:
            assessment.risks.append(
                MCPRisk(
                    category="AG03",
                    level=RiskLevel.HIGH,
                    title="Bulk data ingestion (prompt injection surface)",
                    detail=(
                        f"{len(bulk_tools)} tool(s) can ingest content that becomes "
                        f"part of the AI context: {', '.join(bulk_tools[:5])}. "
                        f"Malicious content in the source system can manipulate AI behaviour."
                    ),
                    recommendation=(
                        "Treat all ingested content as untrusted. "
                        "Implement content sanitisation or limit context window exposure."
                    ),
                )
            )

    def _check_tool_count(self, assessment: MCPAssessment) -> None:
        if assessment.tool_count > 20:
            assessment.risks.append(
                MCPRisk(
                    category="AG04",
                    level=RiskLevel.MEDIUM,
                    title="Large tool surface area",
                    detail=f"Server exposes {assessment.tool_count} tools",
                    recommendation=(
                        "Reduce to minimum necessary tools. "
                        "Large tool sets increase attack surface and LLM confusion risk."
                    ),
                )
            )

    def _check_no_tool_filtering(self, assessment: MCPAssessment, mcp_def: dict) -> None:
        """Check if the MCP config allows tool filtering."""
        allowed_tools = mcp_def.get("allowed_tools", [])
        blocked_tools = mcp_def.get("blocked_tools", [])

        if not allowed_tools and not blocked_tools and assessment.tool_count > 5:
            assessment.risks.append(
                MCPRisk(
                    category="AG06",
                    level=RiskLevel.MEDIUM,
                    title="No tool-level access controls",
                    detail="All server tools are exposed without filtering",
                    recommendation=(
                        "Use allowed_tools or blocked_tools to restrict "
                        "which tools the AI agent can invoke."
                    ),
                )
            )

    def assess_from_file(self, path: Path) -> MCPAssessment:
        """Public method for standalone MCP assessment (used by CLI)."""
        mcp_def = self._load_mcp_config(path)
        return self._assess(mcp_def)


def _unknown_service(mcp_def: dict):
    """Create a placeholder AIService for unrecognised MCP servers."""
    from ai_guard.registry import AIService

    return AIService(
        name=mcp_def.get("name", "Unknown MCP Server"),
        vendor=mcp_def.get("vendor", "Unknown"),
        category="agent",
        risk_tier="medium",
        mcp_identifiers=[mcp_def.get("name", "")],
    )
