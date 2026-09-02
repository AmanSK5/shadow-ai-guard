"""SentinelOne Deep Visibility scanner.

Queries the DV API for DNS events to detect:
  1. Shadow AI usage: DNS lookups to known AI service domains
  2. SaaS bridge connections: non-browser processes resolving SaaS API
     domains, indicating MCP bridges or API key integrations that bypass
     OAuth consent controls

Endpoints:
  POST /dv/init-query  : submit a DV query
  GET  /dv/events      : poll for results (409 = still processing)

Query syntax:
  ObjectType = "dns" AND DNSRequest contains "domain"

Response shape (MSSP/Skylight):
  {"data": [ {event}, {event}, ... ]}

Field names in events:
  dnsRequest, endpointName, agentName, processName,
  createdAt, eventTime, user, userName

Uses the Agents API to resolve endpoint names to logged-in users when
DNS events lack user attribution (e.g. NETWORK SERVICE, system processes).

Rate limiting: MSSP consoles throttle /dv/init-query aggressively. A
throttled batch is retried with backoff rather than dropped. A silently
missing bridge batch means a silently missing bridge finding.
"""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx

from ai_guard.config import ScannerConfig
from ai_guard.registry import AIService, Registry, normalise_process
from ai_guard.scanners.base import (
    BaseScanner,
    DetectionSource,
    Finding,
    ScanResult,
)
from ai_guard.utils.auth import AuthError, SentinelOneAuth

logger = logging.getLogger(__name__)

# Seconds to wait between DV batch queries to avoid 429 rate limiting.
# MSSP consoles have tighter limits; increase if still getting throttled.
BATCH_DELAY_SECONDS = 25

# A throttled batch is retried this many times before being recorded as an
# error. Each attempt waits Retry-After, or an exponential backoff.
MAX_THROTTLE_RETRIES = 3

# Microsoft domains where system-process DNS lookups are expected background
# activity (OneDrive, svchost, Office apps resolving Copilot endpoints).
# When the process is in the allowed_processes list AND the domain matches
# one of these, the event is skipped.  Browser lookups to these same domains
# are NOT filtered: those represent real user AI activity.
_MICROSOFT_SYSTEM_DOMAINS = {
    "copilot.cloud.microsoft",
    "copilot.microsoft.com",
    "sydney.bing.com",
    "substrate.office.com",
}

# A pure M365 backend: no human reaches it as an AI tool, so ANY non-browser
# hitting it is background activity regardless of which process it was.
#
# Narrower than the set above on purpose. The copilot hosts are user-facing -
# a script reaching copilot.microsoft.com is worth a second look - and only
# substrate is a backend nobody visits. Keying on the domain instead of the
# process is what lets the shell-process names stop being maintained by hand:
# Microsoft can ship a new one and it stays quiet without an entry.
_MICROSOFT_BACKEND_DOMAINS = {
    "substrate.office.com",
}

# Maximum time to spend polling a single DV query before giving up.
DV_QUERY_TIMEOUT_SECONDS = 60

# SentinelOne populates processName with the agent version ("2.1.204") on
# some event types instead of the resolving process. Such an event tells us
# a device resolved a domain but not what did the resolving, which is the
# entire basis of bridge detection.
_AGENT_VERSION_RE = re.compile(r"^\d+\.\d+(\.\d+)*$")

# Processes that resolve on behalf of everything else on the box. A stub
# resolver is the querying process for every lookup the machine makes, and
# a service host or an exec helper is whatever it was asked to run, so
# naming one of these says only "this device resolved it" - the same
# non-answer as an agent version string, and it must be treated the same.
#
# This is deliberately absolute rather than domain-scoped: allowed_processes
# only suppresses noise on the Microsoft domains, which left systemd-resolved
# attributed as the client on every other AI domain there is.
_UNATTRIBUTABLE_PROCESSES = {
    "systemd-resolved", "systemd-executor", "systemd", "resolvconf",
    "mdnsresponder", "discoveryd", "dnsmasq", "unbound", "nscd",
    "svchost", "dnscache", "networkservice",
    # Generic task hosts. Windows runs scheduled and background work inside
    # these, so the name is whatever they were told to run - the same
    # non-answer as svchost, and an allowlist entry would be the wrong shape:
    # "this is fine" rather than "this names nothing".
    "backgroundtaskhost", "taskhostw", "taskhost", "taskeng", "rundll32",
    "dllhost", "wermgr",
    # Squirrel ships its updater as "Update.exe" inside every app that uses
    # it, so the name says an application updated itself and not which one.
    # Generic by construction, the same as the hosts above - and an allowlist
    # entry would wrongly read as "this particular program is fine".
    "update", "updater", "squirrel",
    # VPN and zero-trust clients. A tunnel daemon resolves DNS for
    # everything behind the tunnel, so naming one says "something on this
    # device, through the VPN" - the same non-answer as a stub resolver.
    # The queue found firezone-client-tunnel; these are the rest of the
    # category rather than waiting to be asked about one at a time.
    "firezone-client-tunnel", "firezone-gui-client", "tailscaled",
    "openvpn", "wireguard", "wg-quick", "nordvpn", "expressvpn",
    "warp-svc", "cloudflared", "vpnagentd", "acwebsecagent", "pangps",
    "pangpa", "zsatunnel", "zscaler", "stagent", "netskope", "nsdiag",
    "globalprotect", "ivanti", "pulsesecure", "forticlient", "sonicwall",
}


def is_unattributable(process_name: str) -> bool:
    """True when processName does not name the process that wanted the name.

    Empty, an agent version string, or a resolver or host that queries on
    behalf of everything else. Bridge findings must not be raised from
    these: "something on this device reached api.github.com" is not
    actionable, and firing a warn on it trains people to ignore warns.
    """
    if not process_name:
        return True
    if _AGENT_VERSION_RE.match(process_name.strip()):
        return True
    return normalise_process(process_name) in _UNATTRIBUTABLE_PROCESSES


class SentinelOneScanner(BaseScanner):
    name = "sentinelone"

    def __init__(self, registry: Registry, config: ScannerConfig):
        super().__init__(registry, config)
        self._auth: Optional[SentinelOneAuth] = None
        self._endpoint_users: dict[str, str] = {}
        # computer name -> hardware serial. See _device_id below for why.
        self._endpoint_serials: dict[str, str] = {}

    def check_prerequisites(self) -> tuple[bool, str]:
        try:
            self._auth = SentinelOneAuth.from_env(
                self.config.credential_env_prefix or "AIGUARD_S1"
            )
            return True, "SentinelOne credentials loaded"
        except AuthError as e:
            return False, str(e)

    async def scan(self) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        start = datetime.now(timezone.utc)
        try:
            client = self._auth.client()
            lookback = min(
                self.config.options.get("lookback_days", 14), 14
            )

            # Build endpoint -> user and endpoint -> serial maps from the
            # Agents API. Both come from the same call.
            self._endpoint_users, self._endpoint_serials = (
                await self._build_endpoint_user_map(client))

            # Shared seen set: tracks (endpoint, matched_domain) pairs
            # across both scans so we record at most one finding per
            # endpoint per AI service / bridge target domain.
            seen: set[tuple[str, str]] = set()

            # Scan 1: Shadow AI discovery via DNS
            ai_findings = await self._scan_ai_dns(client, lookback, result, seen)

            # Scan 2: Bridge detection via DNS + process names
            bridge_findings = await self._scan_bridge_dns(client, lookback, result, seen)

            result.findings.extend(ai_findings)
            result.findings.extend(bridge_findings)
            await client.aclose()
        except Exception as e:
            result.errors.append(f"SentinelOne scan failed: {e}")

        result.duration_seconds = (datetime.now(timezone.utc) - start).total_seconds()
        return result

    # ─────────────────────────────────────────────
    # Agent inventory (endpoint -> user and serial mapping)
    # ─────────────────────────────────────────────

    async def _build_endpoint_user_map(
        self, client
    ) -> tuple[dict[str, str], dict[str, str]]:
        """Endpoint name -> last logged in user, and -> hardware serial.

        Both from the same Agents call, because the serial is what every
        other source keys a device on and the DV events only carry the
        computer name.
        """
        endpoint_users = {}
        endpoint_serials = {}
        cursor = None
        while True:
            params = {
                "limit": 100,
                "isActive": "true",
                "sortBy": "lastLoggedInUserName",
            }
            if cursor:
                params["cursor"] = cursor

            resp = await client.get("/agents", params=params)
            resp.raise_for_status()
            data = resp.json()

            for agent in data.get("data", []):
                name = agent.get("computerName", "")
                user = agent.get("lastLoggedInUserName", "")
                serial = (agent.get("serialNumber") or "").strip()
                if name and user:
                    endpoint_users[name] = user
                if name and serial:
                    endpoint_serials[name] = serial

            cursor = data.get("pagination", {}).get("nextCursor")
            if not cursor:
                break
        return endpoint_users, endpoint_serials

    def _device_id(self, endpoint_name: str) -> str:
        """The serial for an endpoint, or its computer name if unknown.

        Device identity is the hardware serial, the same rule jamf.py
        follows and for the same reason: the endpoint collectors and the
        browser extension both report serials, so a machine reported here
        by computer name appears twice on any view that joins on device.

        The fallback is the computer name rather than nothing, because a
        finding with no device at all is worse than one that joins
        imperfectly. The agents call filters on isActive, so an endpoint
        whose agent has gone quiet will not be in the map.
        """
        if not endpoint_name:
            return endpoint_name
        return self._endpoint_serials.get(endpoint_name, endpoint_name)

    # ─────────────────────────────────────────────
    # Scan 1: Shadow AI discovery
    # DNS lookups to known AI service domains
    # ─────────────────────────────────────────────

    async def _scan_ai_dns(
        self, client, lookback_days: int, result: ScanResult,
        seen: set[tuple[str, str]],
    ) -> list[Finding]:
        """Find DNS lookups to AI service domains across all managed endpoints.

        Records one finding per (endpoint, service) pair for maximum user
        coverage.  The API limit of 1000 events per query maximises the
        chance of seeing different endpoints; duplicate pairs are skipped
        immediately so every finding represents a distinct endpoint+service.
        """
        findings = []
        from_date, to_date = self._date_range(lookback_days)

        domain_batches = list(self._batch_list(
            sorted(self.registry.all_domains), batch_size=20
        ))

        for batch_num, batch in enumerate(domain_batches, 1):
            if batch_num > 1:
                await asyncio.sleep(BATCH_DELAY_SECONDS)

            domain_clauses = " OR ".join(
                [f'DNSRequest contains "{d}"' for d in batch]
            )
            query = f'ObjectType = "dns" AND ({domain_clauses})'

            try:
                events = await self._run_dv_query(client, query, from_date, to_date)
            except Exception as e:
                result.errors.append(
                    f"AI DNS batch {batch_num}/{len(domain_batches)} failed: "
                    f"{type(e).__name__}: {e}"
                )
                continue

            for event in events:
                dns_request = (event.get("dnsRequest") or "").rstrip(".")
                endpoint_name = event.get("endpointName") or event.get("agentName", "")
                process_name = event.get("processName") or ""

                service = self.registry.match_domain(dns_request)
                if not service:
                    continue

                # Filter system-process noise for Microsoft domains.
                # OneDrive, svchost, Office apps resolve Copilot endpoints
                # as background M365 activity, not real AI usage.
                # Browser lookups to the same domains are kept.
                if (
                    process_name
                    and self.registry.is_allowed_process(process_name)
                    and any(dns_request.endswith(d) for d in _MICROSOFT_SYSTEM_DOMAINS)
                ):
                    continue

                # A backend nobody visits: the process does not matter, only
                # that it is not somebody in a browser. This is the rule that
                # replaces maintaining a list of Windows shell process names.
                if (
                    process_name
                    and not self.registry.is_browser_process(process_name)
                    and any(dns_request.endswith(d)
                            for d in _MICROSOFT_BACKEND_DOMAINS)
                ):
                    continue

                # One finding per endpoint per service. Skip duplicates
                pair = (endpoint_name, f"ai:{service.name}")
                if pair in seen:
                    continue
                seen.add(pair)

                user = event.get("user") or event.get("userName") or endpoint_name
                ts = event.get("createdAt") or event.get("eventTime", "")

                detail = f"DNS lookup for {dns_request}"
                # An agent version is not a process; do not claim it is one.
                if process_name and not is_unattributable(process_name):
                    detail += f" (via {process_name})"

                findings.append(
                    Finding(
                        service=service,
                        source=DetectionSource.SENTINELONE_DNS,
                        risk_tier=service.risk_tier,
                        user_upn=self._normalize_user(user, endpoint_name),
                        device_name=self._device_id(endpoint_name),
                        detail=detail,
                        timestamp=_parse_ts(ts),
                        raw_evidence={
                            "dns_request": dns_request,
                            "endpoint": endpoint_name,
                            "user": user,
                            "process": process_name,
                        },
                    )
                )
        return findings

    # ─────────────────────────────────────────────
    # Scan 2: Bridge detection
    # Non-browser processes resolving SaaS API domains
    # ─────────────────────────────────────────────

    async def _scan_bridge_dns(
        self, client, lookback_days: int, result: ScanResult,
        seen: set[tuple[str, str]],
    ) -> list[Finding]:
        """Detect non-browser processes resolving SaaS API domains.

        If VS Code, Claude, Python, or any non-browser process resolves
        api.atlassian.com, api.github.com, etc., that indicates an MCP
        bridge or API key integration that bypasses OAuth consent controls.

        One finding per (endpoint, bridge target) pair.
        """
        findings = []
        from_date, to_date = self._date_range(lookback_days)

        bridge_domains = sorted(self.registry.all_bridge_domains)
        if not bridge_domains:
            return findings

        domain_batches = list(self._batch_list(bridge_domains, batch_size=10))

        for batch_num, batch in enumerate(domain_batches, 1):
            await asyncio.sleep(BATCH_DELAY_SECONDS)

            domain_clauses = " OR ".join(
                [f'DNSRequest contains "{d}"' for d in batch]
            )
            query = f'ObjectType = "dns" AND ({domain_clauses})'

            try:
                events = await self._run_dv_query(client, query, from_date, to_date)
            except Exception as e:
                # A dropped bridge batch is a dropped bridge finding. Say so
                # loudly enough that an empty bridge panel is never mistaken
                # for a clean fleet.
                result.errors.append(
                    f"Bridge batch {batch_num}/{len(domain_batches)} failed after "
                    f"retries, {len(batch)} domains not checked "
                    f"({', '.join(batch[:3])}...): {type(e).__name__}: {e}"
                )
                continue

            for event in events:
                process_name = event.get("processName") or ""

                # No process, or an agent version where the process should be.
                # We cannot assert "a non-browser did this", so we say nothing.
                if is_unattributable(process_name):
                    continue

                # Skip browser processes: those are normal SaaS access
                if self.registry.is_allowed_process(process_name):
                    continue

                dns_request = (event.get("dnsRequest") or "").rstrip(".")
                endpoint_name = event.get("endpointName") or event.get("agentName", "")

                # Match against bridge targets
                target = self.registry.match_bridge_domain(dns_request)
                if not target:
                    continue

                # One finding per endpoint per bridge target
                pair = (endpoint_name, f"bridge:{target.name}")
                if pair in seen:
                    continue
                seen.add(pair)

                user = event.get("user") or event.get("userName") or endpoint_name
                ts = event.get("createdAt") or event.get("eventTime", "")

                bridge_service = AIService(
                    name=target.name,
                    vendor="Bridge Detection",
                    category="productivity",
                    risk_tier="high",
                    domains=target.domains,
                    notes=target.notes,
                )

                findings.append(
                    Finding(
                        service=bridge_service,
                        source=DetectionSource.SENTINELONE_BRIDGE,
                        risk_tier="high",
                        user_upn=self._normalize_user(user, endpoint_name),
                        device_name=self._device_id(endpoint_name),
                        detail=f'Bridge: "{process_name}" resolving {dns_request}',
                        timestamp=_parse_ts(ts),
                        raw_evidence={
                            "process_name": process_name,
                            "dns_request": dns_request,
                            "endpoint": endpoint_name,
                            "user": user,
                            "bridge_target": target.name,
                        },
                    )
                )
        return findings

    # ─────────────────────────────────────────────
    # Deep Visibility query helpers
    # ─────────────────────────────────────────────

    async def _run_dv_query(
        self, client, query: str, from_date: str, to_date: str
    ) -> list[dict]:
        """Submit a DV query and poll for results, retrying on throttling.

        Endpoints:
          POST /dv/init-query  : initiate query
          GET  /dv/events      : fetch results

        Raises the last error if every attempt is throttled, so the caller
        can record which domains went unchecked.
        """
        last_error: Optional[Exception] = None

        for attempt in range(1, MAX_THROTTLE_RETRIES + 1):
            try:
                init_resp = await client.post(
                    "/dv/init-query",
                    json={
                        "query": query,
                        "fromDate": from_date,
                        "toDate": to_date,
                        "queryType": ["events"],
                    },
                )
                if init_resp.status_code == 429:
                    wait = self._retry_after(init_resp, attempt)
                    logger.warning(
                        "S1: throttled on init-query (attempt %d/%d), "
                        "waiting %ds",
                        attempt, MAX_THROTTLE_RETRIES, wait,
                    )
                    last_error = httpx.HTTPStatusError(
                        "429 Too Many Requests",
                        request=init_resp.request,
                        response=init_resp,
                    )
                    await asyncio.sleep(wait)
                    continue

                init_resp.raise_for_status()
                query_id = init_resp.json().get("data", {}).get("queryId")
                if not query_id:
                    return []
                return await self._poll_dv_query(client, query_id)

            except httpx.HTTPStatusError as e:
                if e.response is not None and e.response.status_code == 429:
                    wait = self._retry_after(e.response, attempt)
                    logger.warning(
                        "S1: throttled (attempt %d/%d), waiting %ds",
                        attempt, MAX_THROTTLE_RETRIES, wait,
                    )
                    last_error = e
                    await asyncio.sleep(wait)
                    continue
                raise

        raise last_error if last_error else RuntimeError("DV query failed")

    @staticmethod
    def _retry_after(response, attempt: int) -> int:
        """Seconds to wait: the server's Retry-After, else exponential backoff."""
        header = response.headers.get("Retry-After") if response is not None else None
        if header:
            try:
                return max(1, int(float(header)))
            except (TypeError, ValueError):
                pass
        return BATCH_DELAY_SECONDS * (2 ** (attempt - 1))

    async def _poll_dv_query(
        self, client, query_id: str, max_polls: int = 20
    ) -> list[dict]:
        """Poll a DV query until results are ready.

        MSSP console behaviour:
          - 409 status  → query still processing, retry
          - empty list  → query still processing, retry
          - non-empty list under "data" → results ready
        """
        deadline = asyncio.get_event_loop().time() + DV_QUERY_TIMEOUT_SECONDS

        for _ in range(max_polls):
            if asyncio.get_event_loop().time() >= deadline:
                logger.warning(
                    "DV query %s timed out after %ds", query_id, DV_QUERY_TIMEOUT_SECONDS
                )
                break

            resp = await client.get(
                "/dv/events",
                params={"queryId": query_id, "limit": 1000},
            )

            # 409 means query is still being processed; wait and retry
            if resp.status_code == 409:
                await asyncio.sleep(3)
                continue

            # Throttled while polling: back off rather than hammering.
            if resp.status_code == 429:
                await asyncio.sleep(self._retry_after(resp, 1))
                continue

            resp.raise_for_status()
            data = resp.json().get("data", [])

            # MSSP console returns data as a list directly under "data".
            # A non-empty list means results are ready.
            if isinstance(data, list) and len(data) > 0:
                return data

            # Empty list means still processing; wait and retry
            await asyncio.sleep(3)

        return []

    # ─────────────────────────────────────────────
    # Shared utilities
    # ─────────────────────────────────────────────

    def _date_range(self, lookback_days: int) -> tuple[str, str]:
        """Generate from/to date strings for DV queries."""
        from_date = (
            datetime.now(timezone.utc) - timedelta(days=lookback_days)
        ).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        to_date = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        return from_date, to_date

    def _batch_list(self, items: list, batch_size: int = 20):
        """Yield batches from a list."""
        for i in range(0, len(items), batch_size):
            yield items[i : i + batch_size]

    def _normalize_user(self, user_str: str, endpoint_name: str = "") -> Optional[str]:
        """Extract UPN from S1 user field, falling back to agent lookup."""
        system_accounts = {
            "NETWORK SERVICE", "LOCAL SERVICE", "SYSTEM",
            "NT AUTHORITY\\NETWORK SERVICE",
            "NT AUTHORITY\\LOCAL SERVICE",
            "NT AUTHORITY\\SYSTEM",
            "USŁUGA SIECIOWA",  # Polish for NETWORK SERVICE
        }

        if user_str and user_str.upper() not in system_accounts:
            if "\\" in user_str:
                user_str = user_str.split("\\", 1)[1]
            return user_str

        # Fall back to last logged-in user from Agents API
        if endpoint_name and self._endpoint_users:
            agent_user = self._endpoint_users.get(endpoint_name)
            if agent_user:
                if "\\" in agent_user:
                    agent_user = agent_user.split("\\", 1)[1]
                return agent_user

        return None


def _parse_ts(ts_str: str) -> Optional[datetime]:
    if not ts_str:
        return None
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None