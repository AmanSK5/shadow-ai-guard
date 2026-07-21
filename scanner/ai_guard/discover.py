"""Keyword-based DNS sweep for unknown AI tool discovery.

Queries SentinelOne Deep Visibility for DNS lookups containing common
AI-related keywords, then filters out:
  - Domains already in the AI service registry
  - Common false-positive domains (major cloud/CDN providers, OS vendors)

What remains is a list of potentially unknown AI tools, grouped by
how many times they were observed.
"""

from __future__ import annotations

import asyncio
import logging
import re
from collections import Counter
from datetime import datetime, timedelta, timezone

from ai_guard.registry import Registry
from ai_guard.utils.auth import SentinelOneAuth

logger = logging.getLogger(__name__)

# AI-related keywords to search for in DNS requests.
AI_KEYWORDS = [
    "ai",
    "gpt",
    "llm",
    "copilot",
    "chat",
    "whisper",
    "wispr",
    "anthropic",
    "openai",
    "diffusion",
    "hugging",
    "gemini",
    "claude",
    "cursor",
    "windsurf",
    "codeium",
    "perplexity",
    "midjourney",
    "replicate",
    "stability",
    "ollama",
]

# Domain fragments that indicate false positives — major vendors, CDNs,
# OS services, and other infrastructure that happen to match AI keywords
# (e.g. "ai.google.com", "chat.microsoft.com").
FALSE_POSITIVE_FRAGMENTS = [
    "google",
    "googleapis",
    "microsoft",
    "windows",
    "apple",
    "icloud",
    "amazon",
    "amazonaws",
    "cloudflare",
    "akamai",
    "akadns",
    "cloudfront",
    "azure",
    "office365",
    "office",
    "outlook",
    "live.com",
    "bing",
    "msedge",
    "mozilla",
    "firefox",
    "gstatic",
    "youtube",
    "facebook",
    "meta",
    "instagram",
    "twitter",
    "linkedin",
    "github",
    "githubusercontent",
    "slack",
    "zoom",
    "teams",
    "skype",
    "adobe",
    "salesforce",
    "oracle",
    "sap",
    "vmware",
    "citrix",
    "aaplimg",
    "edgekey",
    "edgesuite",
    "trafficmanager",
    "msftconnecttest",
    "digicert",
    "verisign",
    "symantec",
    "norton",
    "mcafee",
    "sentinelone",
    "crowdstrike",
    "sophos",
    "kaspersky",
    "avast",
    "avg",
    "bitdefender",
    "malwarebytes",
]

# Seconds between DV batch queries (same rate-limit policy as scanner).
BATCH_DELAY_SECONDS = 25

# DV query poll timeout.
DV_QUERY_TIMEOUT_SECONDS = 60

# Pattern to strip DNS record-type prefixes like "type:  28" or "type:  1"
# that SentinelOne sometimes prepends to dnsRequest values.
_DNS_TYPE_PREFIX_RE = re.compile(r"^type:\s*\d+\s+")


def _strip_dns_prefix(raw: str) -> str:
    """Remove DNS record-type prefix (e.g. 'type:  28 ') from a domain string."""
    return _DNS_TYPE_PREFIX_RE.sub("", raw).strip()


def _extract_base_domain(fqdn: str) -> str:
    """Extract the registrable domain from an FQDN.

    Simple heuristic: return the last two labels, or three if the
    second-to-last is short (co, com, org, net, etc.) to handle
    domains like foo.co.uk.
    """
    fqdn = fqdn.lower().strip(".")
    parts = fqdn.split(".")
    if len(parts) <= 2:
        return fqdn
    # Handle two-part TLDs like co.uk, com.au, org.uk
    if len(parts[-2]) <= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _is_false_positive(domain: str) -> bool:
    """Check if a domain matches any false-positive fragment."""
    lower = domain.lower()
    return any(fp in lower for fp in FALSE_POSITIVE_FRAGMENTS)


async def run_discover(
    auth: SentinelOneAuth,
    registry: Registry,
    lookback_days: int = 14,
) -> tuple[Counter[str], list[str]]:
    """Run keyword DNS sweep and return (domain_counts, errors).

    Returns a Counter mapping base domains to their observation count,
    and a list of any errors encountered.
    """
    client = auth.client()
    errors: list[str] = []
    all_domains: list[str] = []

    # All known registry domains (for filtering)
    known_domains = registry.all_domains | registry.all_bridge_domains

    from_date = (
        datetime.now(timezone.utc) - timedelta(days=min(lookback_days, 14))
    ).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    to_date = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    # Batch keywords to avoid overly long queries.
    # Each keyword becomes an OR clause, so ~5 per batch is reasonable.
    batch_size = 5
    keyword_batches = [
        AI_KEYWORDS[i : i + batch_size]
        for i in range(0, len(AI_KEYWORDS), batch_size)
    ]

    for batch_num, batch in enumerate(keyword_batches, 1):
        if batch_num > 1:
            await asyncio.sleep(BATCH_DELAY_SECONDS)

        keyword_clauses = " OR ".join(
            f'DNSRequest contains "{kw}"' for kw in batch
        )
        query = f'ObjectType = "dns" AND ({keyword_clauses})'

        try:
            events = await _run_dv_query(client, query, from_date, to_date)

            for event in events:
                raw = event.get("dnsRequest") or ""
                dns_request = _strip_dns_prefix(raw).rstrip(".")
                if not dns_request:
                    continue
                all_domains.append(dns_request)

        except Exception as e:
            errors.append(f"Keyword batch {batch_num} ({', '.join(batch)}): {e}")
            if "429" in str(e):
                await asyncio.sleep(30)
            continue

    await client.aclose()

    # Deduplicate: extract base domains, filter known & false positives
    exclude_domains = registry.discover_exclude_domains
    domain_counts: Counter[str] = Counter()
    for fqdn in all_domains:
        base = _extract_base_domain(fqdn)

        # Skip if this domain (or FQDN) is already in the registry
        if registry.match_domain(fqdn):
            continue

        # Skip false positives
        if _is_false_positive(fqdn):
            continue

        # Skip domains on the discover exclusion list
        if base in exclude_domains or any(fqdn.endswith("." + ed) or fqdn == ed for ed in exclude_domains):
            continue

        domain_counts[base] += 1

    return domain_counts, errors


# ── DV query helpers (mirrors sentinelone.py) ──────────────


async def _run_dv_query(
    client, query: str, from_date: str, to_date: str
) -> list[dict]:
    init_resp = await client.post(
        "/dv/init-query",
        json={
            "query": query,
            "fromDate": from_date,
            "toDate": to_date,
            "queryType": ["events"],
        },
    )
    init_resp.raise_for_status()
    query_id = init_resp.json().get("data", {}).get("queryId")
    if not query_id:
        return []
    return await _poll_dv_query(client, query_id)


async def _poll_dv_query(client, query_id: str, max_polls: int = 20) -> list[dict]:
    deadline = asyncio.get_event_loop().time() + DV_QUERY_TIMEOUT_SECONDS
    for _ in range(max_polls):
        if asyncio.get_event_loop().time() >= deadline:
            logger.warning("DV query %s timed out after %ds", query_id, DV_QUERY_TIMEOUT_SECONDS)
            break
        resp = await client.get(
            "/dv/events",
            params={"queryId": query_id, "limit": 1000},
        )
        if resp.status_code == 409:
            await asyncio.sleep(3)
            continue
        resp.raise_for_status()
        data = resp.json().get("data", [])
        if isinstance(data, list) and len(data) > 0:
            return data
        await asyncio.sleep(3)
    return []
