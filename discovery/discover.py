#!/usr/bin/env python3
"""ai-guard discovery: find AI tools the registry doesn't know about.

Weekly CronJob. Pipeline:

  1. Pull last 7 days of DNS events from SentinelOne Deep Visibility.
  2. Reduce to distinct eTLD+1 domains; drop anything already in the
     registry, in the allowlist, or below the device-count floor.
  3. Classify the residue with Claude ("is this an AI/LLM service?").
  4. Open a GitLab MR appending candidates to registry.yaml with
     category: unreviewed, approved: false, added_by: discovery.

Human stays the approval gate: nothing enters detection until the MR merges.

Env:
  S1_BASE_URL, S1_API_TOKEN
  RECEIVER_URL, RECEIVER_TOKEN          (to fetch the live registry)
  ANTHROPIC_API_KEY                     (classification)
  ANTHROPIC_MODEL                       (default claude-sonnet-4-6)
  GITLAB_URL, GITLAB_TOKEN, GITLAB_PROJECT_ID
  MIN_DEVICES                           (default 1)
  DRY_RUN                               (set to skip the MR, print instead)
"""

import json
import os
import re
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

S1_BASE = os.environ.get("S1_BASE_URL", "").rstrip("/")
S1_TOKEN = os.environ.get("S1_API_TOKEN", "")
RECEIVER_URL = os.environ.get("RECEIVER_URL", "").rstrip("/")
RECEIVER_TOKEN = os.environ.get("RECEIVER_TOKEN", "")
MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-6")
GITLAB_URL = os.environ.get("GITLAB_URL", "").rstrip("/")
GITLAB_TOKEN = os.environ.get("GITLAB_TOKEN", "")
GITLAB_PROJECT = os.environ.get("GITLAB_PROJECT_ID", "")
MIN_DEVICES = int(os.environ.get("MIN_DEVICES", "1"))
DRY_RUN = bool(os.environ.get("DRY_RUN"))

def _require_https(name: str, value: str) -> None:
    """Reject non-HTTPS base URLs at startup to prevent sending API tokens
    over cleartext. Matches the scheme check in SentinelOneAuth.from_env()."""
    if value and not value.startswith("https://"):
        sys.exit(f"{name} must use https:// (got {value!r})")


def _require_https_or_cluster(name: str, value: str) -> None:
    """Like _require_https, but allow plain HTTP for in-cluster URLs.

    The documented deployment runs discovery as a CronJob talking to the
    receiver over the pod network where TLS terminates at the ingress.
    Requiring HTTPS there would break every in-cluster deployment, so
    *.svc.cluster.local URLs are exempted.
    """
    if not value:
        return
    if value.startswith("https://"):
        return
    if value.startswith("http://") and ".svc.cluster.local" in value:
        return
    sys.exit(
        f"{name} must use https:// (or http:// only for "
        f"*.svc.cluster.local in-cluster URLs). Got {value!r}"
    )


_require_https("S1_BASE_URL", S1_BASE)
_require_https("GITLAB_URL", GITLAB_URL)
_require_https_or_cluster("RECEIVER_URL", RECEIVER_URL)

ALLOWLIST_FILE = Path(__file__).with_name("allowlist.txt")

TWO_PART_TLDS = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "co.nz", "co.jp"}


def etld1(host: str) -> str:
    parts = host.lower().strip(".").split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_PART_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


# ------------------------------------------------------------ registry ------

def fetch_registry() -> dict:
    r = httpx.get(
        f"{RECEIVER_URL}/registry",
        headers={"Authorization": f"Bearer {RECEIVER_TOKEN}"},
        timeout=15,
    )
    r.raise_for_status()
    return r.json()


def known_domains(registry: dict) -> set[str]:
    out = set()
    for t in registry.get("tools", []):
        for d in t.get("domains", []):
            out.add(etld1(d))
    return out


# ------------------------------------------------------ deep visibility -----

def s1_dns_domains(days: int = 7) -> dict[str, set[str]]:
    """Return {etld1: {device, ...}} for DNS events in the window."""
    now = datetime.now(timezone.utc)
    headers = {"Authorization": f"ApiToken {S1_TOKEN}"}
    init = httpx.post(
        f"{S1_BASE}/web/api/v2.1/dv/init-query",
        headers=headers,
        json={
            "query": 'EventType = "DNS Resolved"',
            "fromDate": (now - timedelta(days=days)).isoformat(),
            "toDate": now.isoformat(),
        },
        timeout=30,
    )
    init.raise_for_status()
    qid = init.json()["data"]["queryId"]

    for _ in range(60):
        st = httpx.get(
            f"{S1_BASE}/web/api/v2.1/dv/query-status",
            headers=headers,
            params={"queryId": qid},
            timeout=30,
        ).json()["data"]
        if st.get("responseState") == "FINISHED":
            break
        time.sleep(5)
    else:
        sys.exit("DV query did not finish")

    domains: dict[str, set[str]] = defaultdict(set)
    cursor = None
    while True:
        params = {"queryId": qid, "limit": 1000}
        if cursor:
            params["cursor"] = cursor
        page = httpx.get(
            f"{S1_BASE}/web/api/v2.1/dv/events/dns",
            headers=headers,
            params=params,
            timeout=60,
        ).json()
        for ev in page.get("data", []):
            host = ev.get("dnsRequest") or ""
            if host and re.match(r"^[a-z0-9.-]+$", host, re.I):
                domains[etld1(host)].add(ev.get("agentName", "unknown"))
        cursor = page.get("pagination", {}).get("nextCursor")
        if not cursor:
            break
    return domains


# --------------------------------------------------------- classification ---

CLASSIFY_PROMPT = """You classify domains for a corporate shadow-AI registry.
For each domain below, decide if it is primarily an AI/LLM/genAI service that
end users interact with or that AI tools call (chatbots, AI coding tools, AI
transcription/writing/image/voice tools, LLM APIs, AI agent platforms).
CDNs, analytics, ad networks, general SaaS, and news sites are NOT AI services.

Respond with ONLY a JSON array, no markdown fences, one object per domain:
[{"domain": "...", "is_ai": true/false, "name": "product name or null",
  "vendor": "vendor or null", "category": "assistant|coding|transcription|writing|image|search|local-model|voice|other",
  "confidence": "high|medium|low"}]

Domains:
"""


def classify(domains: list[str]) -> list[dict]:
    results = []
    for i in range(0, len(domains), 40):
        batch = domains[i : i + 40]
        r = httpx.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": os.environ["ANTHROPIC_API_KEY"].strip(),
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": MODEL,
                "max_tokens": 4000,
                "messages": [
                    {"role": "user", "content": CLASSIFY_PROMPT + "\n".join(batch)}
                ],
            },
            timeout=120,
        )
        if r.status_code >= 400:
            # The API explains itself; don't swallow the reason.
            print(f"anthropic {r.status_code}: {r.text[:500]}", file=sys.stderr)
            r.raise_for_status()
        text = "".join(
            b.get("text", "") for b in r.json()["content"] if b.get("type") == "text"
        )
        text = re.sub(r"^```(json)?|```$", "", text.strip(), flags=re.M).strip()
        try:
            results.extend(json.loads(text))
        except json.JSONDecodeError:
            print(f"unparseable classification batch at offset {i}", file=sys.stderr)
    return results


# ----------------------------------------------------------------- gitlab ---

def slugify(text: str) -> str:
    """Product name -> registry id.

    Classifiers name products the way their marketing does, TLD included:
    'Fireflies.ai', 'Otter.ai', 'n8n.io'. Strip that suffix so the id reads
    'fireflies', not 'fireflies-ai'. Everything else collapses to hyphens.
    """
    s = text.strip().lower()
    s = re.sub(r"\.(ai|io|com|dev|app|co)$", "", s)
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    return s or "unknown"


def group_candidates(candidates: list[dict], evidence: dict[str, set[str]]) -> list[dict]:
    """One entry per product, not per domain.

    The classifier sees domains individually, so a product with several domains
    (fireflies.ai + firefliesapp.com) comes back as several verdicts sharing a
    name. Emitting one registry entry each produces duplicate ids, which
    build.py correctly rejects. Group on the product name instead.
    """
    groups: dict[str, dict] = {}
    for c in candidates:
        key = (c.get("name") or c["domain"]).lower()
        g = groups.setdefault(key, {
            "name": c.get("name") or c["domain"],
            "vendor": c.get("vendor") or "unknown",
            "category": c.get("category") or "unreviewed",
            "domains": [],
            "devices": set(),
            "confidences": [],
        })
        g["domains"].append(c["domain"])
        g["devices"] |= evidence.get(c["domain"], set())
        g["confidences"].append(c.get("confidence", "?"))
        # Prefer a concrete vendor/category if any verdict supplied one.
        if g["vendor"] == "unknown" and c.get("vendor"):
            g["vendor"] = c["vendor"]

    out = []
    for g in groups.values():
        g["domains"] = sorted(set(g["domains"]))
        # Lowest confidence across the group is the honest one to report.
        order = {"high": 2, "medium": 1, "low": 0, "?": 0}
        g["confidence"] = min(g["confidences"], key=lambda c: order.get(c, 0))
        out.append(g)
    return out


def candidate_yaml(g: dict, taken: set[str]) -> str:
    slug = slugify(g["name"])
    # Never collide with an existing registry id, or with a sibling candidate.
    base, n = slug, 2
    while slug in taken:
        slug = f"{base}-{n}"
        n += 1
    taken.add(slug)

    devices = len(g["devices"])
    return f"""
  - id: {slug}
    name: {g['name']}
    vendor: {g['vendor']}
    category: unreviewed
    approved: false
    added_by: discovery
    notes: "confidence {g['confidence']}; seen on {devices} device(s) in last 7d"
    domains: [{', '.join(g['domains'])}]
"""


def open_mr(groups: list[dict], registry: dict):
    api = f"{GITLAB_URL}/api/v4/projects/{GITLAB_PROJECT}"
    headers = {"PRIVATE-TOKEN": GITLAB_TOKEN}

    # Same-day reruns must not collide with an existing branch.
    stamp = f"{datetime.now(timezone.utc):%Y-%m-%d}"
    branch = f"discovery/{stamp}"

    current = httpx.get(
        f"{api}/repository/files/registry%2Fregistry.yaml/raw",
        headers=headers,
        params={"ref": "main"},
        timeout=30,
    )
    current.raise_for_status()

    taken = {t["id"] for t in registry.get("tools", [])}
    updated = current.text.rstrip() + "\n" + "".join(
        candidate_yaml(g, taken) for g in groups
    )

    r = httpx.post(
        f"{api}/repository/branches",
        headers=headers,
        params={"branch": branch, "ref": "main"},
        timeout=30,
    )
    if r.status_code == 400:  # branch exists (rerun on the same day)
        branch = f"discovery/{stamp}-{datetime.now(timezone.utc):%H%M}"
        httpx.post(
            f"{api}/repository/branches",
            headers=headers,
            params={"branch": branch, "ref": "main"},
            timeout=30,
        ).raise_for_status()
    else:
        r.raise_for_status()

    httpx.put(
        f"{api}/repository/files/registry%2Fregistry.yaml",
        headers=headers,
        json={
            "branch": branch,
            "content": updated,
            "commit_message": f"discovery: {len(groups)} AI service candidate(s)",
        },
        timeout=30,
    ).raise_for_status()

    desc_lines = [
        "Weekly discovery run. Candidates below were observed in fleet DNS and",
        "classified as AI services. Review, set the category and approved flag,",
        "add app_names / extension_ids / cli paths where the tool has them,",
        "and merge to activate detection across all surfaces.",
        "",
        "| Product | Vendor | Domains | Confidence | Devices (7d) |",
        "|---|---|---|---|---|",
    ] + [
        f"| {g['name']} | {g['vendor']} | {', '.join(g['domains'])} "
        f"| {g['confidence']} | {len(g['devices'])} |"
        for g in groups
    ]
    mr = httpx.post(
        f"{api}/merge_requests",
        headers=headers,
        json={
            "source_branch": branch,
            "target_branch": "main",
            "title": f"Discovery {datetime.now(timezone.utc):%Y-%m-%d}: "
                     f"{len(groups)} AI service candidate(s)",
            "description": "\n".join(desc_lines),
            "labels": "ai-guard,discovery",
        },
        timeout=30,
    )
    mr.raise_for_status()
    print("MR:", mr.json()["web_url"])


# ------------------------------------------------------------------- main ---

def main():
    registry = fetch_registry()
    known = known_domains(registry)
    allow = set()
    if ALLOWLIST_FILE.exists():
        allow = {
            etld1(l.strip())
            for l in ALLOWLIST_FILE.read_text().splitlines()
            if l.strip() and not l.startswith("#")
        }

    observed = s1_dns_domains()
    residue = {
        d: devs
        for d, devs in observed.items()
        if d not in known and d not in allow and len(devs) >= MIN_DEVICES
    }
    print(f"observed {len(observed)} domains, {len(residue)} unknown after filtering")
    if not residue:
        return

    verdicts = classify(sorted(residue))
    candidates = [
        v for v in verdicts
        if v.get("is_ai") and v.get("confidence") in ("high", "medium")
    ]
    groups = group_candidates(candidates, residue)
    print(f"classified: {len(candidates)} AI domain(s) -> {len(groups)} product(s)")
    if not groups:
        return

    if DRY_RUN:
        printable = [{**g, "devices": sorted(g["devices"])} for g in groups]
        print(json.dumps(printable, indent=2))
        return
    open_mr(groups, registry)


if __name__ == "__main__":
    main()