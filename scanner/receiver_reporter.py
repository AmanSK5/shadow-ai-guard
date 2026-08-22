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
import socket
import unicodedata
from typing import Optional

import httpx

from ai_guard import __version__ as AGENT_VERSION
from ai_guard.scanners.base import DetectionSource, Finding, occurrence_unit

logger = logging.getLogger(__name__)

# Managed mode. RECEIVER_TOKEN may be an enrollment token (aige_...) from a
# managed-mode receiver instead of the shared token: the run then exchanges it
# at /enroll for this scanner's own device credential (aigd_...) and uses that
# for the registry fetch and every report. The prefix is the switch, the same
# contract as the endpoint collectors and the browser extension, so the
# operator changes one Secret value when ready.
#
# A CronJob pod has no disk of its own, so by default the scanner enrolls on
# every run: the receiver reissues the same device's credential in place
# (platform "scanner", serial AIGUARD_SCANNER_ID, exempt from the one-hour
# active guard that protects laptops), so the fleet shows one row per scanner,
# not one per run. Set AIGUARD_STATE_DIR to a writable volume to keep the
# credential between runs instead; then revoking the scanner's row in the
# fleet view sticks, whereas a stateless scanner simply enrolls again next run
# and the lever for it is revoking the enrollment token it carries.
ENROLL_PREFIX = "aige_"
DEVICE_PREFIX = "aigd_"
CRED_FILENAME = "device.cred"


class EnrollmentError(Exception):
    """Enrollment was refused or the credential could not be kept. Fatal
    before any scanning: an enrollment token cannot report findings, so
    carrying on would 401 every POST and look like a clean estate."""


def resolve_credential(
    url: str,
    token: str,
    scanner_id: str,
    state_dir: Optional[str] = None,
    timeout: float = 15.0,
) -> str:
    """The bearer this run reports with.

    A stored device credential wins; an enrollment token is exchanged for
    one; anything else is used as-is (the shared token, classic mode).
    """
    if not token.startswith(ENROLL_PREFIX):
        return token
    if state_dir is None:
        state_dir = os.environ.get("AIGUARD_STATE_DIR", "")
    cred_path = os.path.join(state_dir, CRED_FILENAME) if state_dir else ""

    if cred_path and os.path.exists(cred_path):
        try:
            with open(cred_path) as f:
                stored = f.read().strip()
        except OSError as e:
            # A volume written under another uid, typically. Named, not a
            # traceback: it is the same class of deployment mistake as an
            # unwritable state dir.
            raise EnrollmentError(f"cannot read {cred_path} ({e.strerror})") from e
        if stored.startswith(DEVICE_PREFIX):
            return stored
        logger.warning("%s does not hold a device credential; enrolling again", cred_path)

    body = {
        "platform": "scanner",
        "serial": scanner_id,
        "hostname": socket.gethostname(),
        "agent_version": AGENT_VERSION,
    }
    try:
        r = httpx.post(f"{url.rstrip('/')}/enroll", json=body, timeout=timeout,
                       headers={"Authorization": f"Bearer {token}"})
    except httpx.HTTPError as e:
        raise EnrollmentError(f"enrollment failed: {type(e).__name__} reaching {url}") from e
    if r.status_code != 200:
        detail = ""
        try:
            detail = r.json().get("detail", "")
        except ValueError:
            pass
        raise EnrollmentError(
            f"enrollment failed: HTTP {r.status_code} from {url.rstrip('/')}/enroll"
            + (f": {detail}" if detail else "")
        )
    cred = r.json().get("device_token", "")
    if not cred.startswith(DEVICE_PREFIX):
        raise EnrollmentError("enrollment failed: receiver returned no device credential")

    if cred_path:
        # Loud and fatal, like the collectors: a run that enrolled but could
        # not keep the credential would enroll again next time, and an
        # unwritable state dir is a deployment mistake to fix, not to mask.
        try:
            os.makedirs(state_dir, exist_ok=True)
            fd = os.open(cred_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(cred)
        except OSError as e:
            raise EnrollmentError(
                f"enrolled, but cannot write {cred_path} ({e.strerror}); refusing to scan:"
                " the credential would be lost and every run would re-enroll"
            ) from e
        logger.info("enrolled as scanner %r; credential stored in %s", scanner_id, cred_path)
    else:
        logger.info("enrolled as scanner %r for this run (no AIGUARD_STATE_DIR)", scanner_id)
    return cred

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
    # Neither extension source is produced by anything yet, and the surface
    # here cannot be resolved as a per-source constant. extension_ids in the
    # registry mixes IDE hosts (vscode, jetbrains) with browser hosts (chrome,
    # edge), so one INTUNE_EXTENSION finding could be either kind. "ide" is
    # what most of the registry is today, 9 tools of 13, not a decision that
    # has been made. When extension detection is built, split the sources by
    # host so the surface follows from the data rather than being guessed.
    # See issue #21.
    DetectionSource.INTUNE_EXTENSION: ("ide", "windows"),
    DetectionSource.JAMF_APP: ("desktop", "macos"),
    DetectionSource.JAMF_EXTENSION: ("ide", "macos"),  # same caveat as above
    DetectionSource.MCP_SCAN: ("mcp", "unknown"),
}

# Some fleets name devices <PREFIX>-<serial> while the endpoint collectors
# report the bare serial, which would make one machine count twice. Set
# AIGUARD_DEVICE_PREFIX to strip that prefix here. Unset means no
# normalisation.
#
# Comma separated, because a fleet can have more than one: Windows and macOS
# are often enrolled by different tools under different conventions, and a
# single prefix silently normalises half an estate. AIGUARD_DEVICE_PREFIX=
# "ACME,ACM" handles both.
#
# The serial must be at least six characters and must contain a digit. Length
# alone was the original rule at eight, and it was wrong twice over: Dell
# service tags are seven, so most of a Windows fleet went unnormalised, and a
# hostname like <PREFIX>-SERVER would have been stripped to SERVER on the way
# down. A serial essentially always contains a digit and a word essentially
# never does, which separates them better than counting characters.
_DEVICE_PREFIXES = [
    p.strip() for p in os.environ.get("AIGUARD_DEVICE_PREFIX", "").split(",")
    if p.strip()
]
_PREFIX_HOSTNAME = (
    re.compile(
        r"^(?:%s)[-_](?=[A-Z0-9]*\d)([A-Z0-9]{6,})$"
        % "|".join(re.escape(p) for p in _DEVICE_PREFIXES),
        re.IGNORECASE,
    )
    if _DEVICE_PREFIXES
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
            # Volume, with its unit: the number means sign-ins for Entra,
            # devices for Intune, signup emails for Exchange. Goes in the log
            # line, never a Loki label; the label set is deliberately bounded.
            "occurrence_count": f.occurrence_count,
            "occurrence_unit": occurrence_unit(f.source),
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
            # So the receiver's inventory knows which scanner version reported.
            "X-AiGuard-Agent-Version": AGENT_VERSION,
        }
        revoked_said = False
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
                    status = getattr(getattr(e, "response", None), "status_code", None)
                    if (status == 401 and self.token.startswith(DEVICE_PREFIX)
                            and not revoked_said):
                        # Said once, not per finding. Never re-enrolled from
                        # here: a revoked scanner must be visible in the job
                        # log, and the operator removes the stored credential
                        # (or the state dir) to enroll it again.
                        revoked_said = True
                        logger.error(
                            "this scanner's device credential was refused (revoked?);"
                            " delete %s under AIGUARD_STATE_DIR and supply a valid"
                            " enrollment token to re-enroll", CRED_FILENAME)
        return sent, failed