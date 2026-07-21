"""Receiver output format.

Maps scanner Findings onto the ai-guard receiver schema and POSTs them, so
cloud-side scans land in the same Loki/Prometheus/Grafana pipeline as the
browser extension and the endpoint collector.

Privacy: user_upn is split into a local part and a domain. Only the domain is
sent as account_domain. The local part is sent as `user` only when it belongs
to a corporate domain (it is already known to IT via Entra/Jamf); for any
other domain the user field is left empty. This mirrors the rule the browser
extension and endpoint collector follow.

CORPORATE_DOMAINS is a comma-separated list, because organisations have alias
domains (from CORPORATE_DOMAIN). Treating only the primary as
corporate flags your own aliases as personal accounts and strips the username
from findings that should carry it.

Severity:
  warn  personal (non-corporate) account domain on any surface
  info  everything else, including presence of unapproved tools

Unapproved-tool *presence* is deliberately info rather than warn. A daily
fleet-wide scan would otherwise fire an alert per device per unapproved tool
every morning. Presence belongs on the dashboard and in a weekly digest;
alerts are reserved for a personal account, which is the actionable signal.
"""

from __future__ import annotations

import json
import logging
import os
import re
import unicodedata
from typing import Optional

import httpx

from ai_guard.scanners.base import DetectionSource, Finding

logger = logging.getLogger(__name__)

# DetectionSource -> (surface, os). Surfaces match the receiver's vocabulary:
# browser, cli, ide, desktop, mcp, cloud.
SOURCE_MAP: dict[DetectionSource, tuple[str, str]] = {
    DetectionSource.ENTRA_SIGN_IN: ("cloud", "unknown"),
    DetectionSource.ENTRA_SERVICE_PRINCIPAL: ("cloud", "unknown"),
    DetectionSource.ENTRA_CONSENT_GRANT: ("cloud", "unknown"),
    # A DNS lookup says a device resolved a domain. It does not say a browser
    # did it: observed processes include claude.exe, svchost.exe, Code.exe and
    # systemd-resolved all resolving AI domains. Calling that "browser" would
    # be a lie, and would collide with the extension's real browser findings.
    DetectionSource.SENTINELONE_DNS: ("network", "unknown"),
    DetectionSource.SENTINELONE_NETWORK: ("cloud", "unknown"),
    DetectionSource.SENTINELONE_BRIDGE: ("cloud", "unknown"),
    DetectionSource.EXCHANGE_EMAIL: ("cloud", "unknown"),
    DetectionSource.INTUNE_APP: ("desktop", "windows"),
    DetectionSource.INTUNE_EXTENSION: ("ide", "windows"),
    DetectionSource.JAMF_APP: ("desktop", "macos"),
    DetectionSource.JAMF_EXTENSION: ("ide", "macos"),
    DetectionSource.MCP_SCAN: ("mcp", "unknown"),
}

# Some fleets name devices <PREFIX>-<serial> while the endpoint collectors
# report the bare serial, which would make one machine count twice. Set
# AIGUARD_DEVICE_PREFIX (e.g. "ACME") to strip that prefix here. Unset means
# no normalisation.
_DEVICE_PREFIX = os.environ.get("AIGUARD_DEVICE_PREFIX", "")
_PREFIX_HOSTNAME = (
    re.compile(rf"^{re.escape(_DEVICE_PREFIX)}[-_]([A-Z0-9]{{8,}})$", re.IGNORECASE)
    if _DEVICE_PREFIX
    else None
)


def slugify(name: str) -> str:
    """Display name -> metric-safe label.

    Bridge targets are BridgeTarget objects, not registry entries, so they
    carry no id: "Atlassian (Jira/Confluence)" would become a Prometheus
    label with spaces, parentheses and a slash. Slugify to `atlassian`.
    """
    s = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode()
    s = s.lower()
    s = re.sub(r"\(.*?\)", "", s)          # drop parenthesised qualifiers
    s = re.sub(r"\.(ai|io|com|dev|app|co)\b", "", s)
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    return s or "unknown"


def normalise_device(device_name: Optional[str]) -> tuple[str, str]:
    """(device, device_name) -> (serial-if-derivable, original hostname)."""
    if not device_name:
        return "", ""
    if _PREFIX_HOSTNAME is None:
        cleaned = device_name.strip()
        return cleaned, cleaned
    m = _PREFIX_HOSTNAME.match(device_name.strip())
    if m:
        return m.group(1).upper(), device_name
    # Not the convention: keep the hostname in both fields so the finding is
    # still attributable, and the mismatch is visible on the dashboard.
    return device_name.strip(), device_name.strip()


def split_upn(upn: Optional[str], corporate_domains: set[str]) -> tuple[str, str]:
    """(user, account_domain), local part only for corporate domains."""
    if not upn or "@" not in upn:
        return "", ""
    local, _, domain = upn.rpartition("@")
    domain = domain.lower()
    return (local if domain in corporate_domains else ""), domain


class ReceiverReporter:
    """POSTs findings to the ai-guard receiver."""

    def __init__(
        self,
        url: Optional[str] = None,
        token: Optional[str] = None,
        corporate_domains: Optional[str] = None,
        timeout: float = 10.0,
        dry_run: bool = False,
    ):
        self.url = (url or os.environ.get("RECEIVER_URL", "")).rstrip("/")
        self.token = token or os.environ.get("RECEIVER_TOKEN", "")
        # Comma-separated. CORPORATE_DOMAINS preferred; CORPORATE_DOMAIN kept
        # for compatibility with earlier deployments.
        raw = (
            corporate_domains
            or os.environ.get("CORPORATE_DOMAINS")
            or os.environ.get("CORPORATE_DOMAIN", "")
        )
        self.corporate_domains = {
            d.strip().lower() for d in raw.split(",") if d.strip()
        }
        self.timeout = timeout
        self.dry_run = dry_run
        # A dry run maps findings to payloads and prints them; it needs no
        # endpoint. Requiring one would mean holding a token to print JSON.
        if not dry_run and (not self.url or not self.token):
            raise ValueError("RECEIVER_URL and RECEIVER_TOKEN are required")

    def payload(self, f: Finding) -> dict:
        surface, os_name = SOURCE_MAP.get(f.source, ("cloud", "unknown"))
        device, device_name = normalise_device(f.device_name)
        user, account_domain = split_upn(f.user_upn, self.corporate_domains)

        personal = bool(account_domain) and account_domain not in self.corporate_domains

        # A non-browser process reaching a SaaS API is the sharpest signal the
        # system produces: it means something automated holds a token. Always warn.
        bridge = f.source is DetectionSource.SENTINELONE_BRIDGE

        # AIService.label is the registry id. Bridge findings carry a
        # BridgeTarget instead, which has no id — slugify its name so the
        # metric label is `atlassian`, not `Atlassian (Jira/Confluence)`.
        # Every surface must agree on this label or one tool splits into
        # several dashboard rows: "Otter" and "otter" are not the same key.
        tool = getattr(f.service, "label", None) or slugify(f.service.name)

        return {
            "tool": tool,
            "surface": surface,
            "os": os_name,
            "account_domain": account_domain,
            "device": device,
            "device_name": device_name,
            "user": user,
            "evidence": f.detail[:500],
            "severity": "warn" if (personal or bridge) else "info",
            "source": f.source.value,
            "risk_tier": f.risk_tier,
            "reported_at": (f.last_seen or f.timestamp).isoformat()
            if (f.last_seen or f.timestamp)
            else None,
        }

    def send(self, findings: list[Finding]) -> tuple[int, int]:
        """Returns (sent, failed). Never raises: a scan that found things and
        failed to report them should still print its terminal output."""
        if self.dry_run:
            for f in findings:
                print(json.dumps(self.payload(f)))
            return len(findings), 0

        sent = failed = 0
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }
        with httpx.Client(timeout=self.timeout) as client:
            for f in findings:
                body = {k: v for k, v in self.payload(f).items() if v is not None}
                try:
                    r = client.post(f"{self.url}/report", headers=headers, json=body)
                    r.raise_for_status()
                    sent += 1
                except httpx.HTTPError as e:
                    failed += 1
                    logger.warning("receiver: %s (%s)", e, body.get("tool"))
        return sent, failed