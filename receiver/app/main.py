"""ai-guard receiver

Ingests findings from all four sources (browser extension, macOS collector,
Windows remediation, scanner CronJob) and routes them:

  severity=warn  -> Alertmanager (your alerting channel) + stdout JSON (Loki)
  severity=info  -> stdout JSON only (Loki inventory stream, no alert)
  missing        -> defaults to warn, so the existing browser extension
                    needs no change (it only ever reports violations)

Carried over from v0.1.2:
  - bearer token auth (AUTH_TOKEN)
  - ALERT_TTL_MINUTES (default 120): persistent sessions collapse into one
    continuously active alert; Alertmanager repeat_interval governs re-pings
  - "detected" annotation pre-formatted in DISPLAY_TZ (default UTC)

New in v0.1.3:
  - severity routing (above)
  - surface field, included in the dedup/label key so a browser flag and a
    CLI flag for the same tool don't collapse into one alert
  - GET /registry: serves the registry artifact mounted from the ConfigMap
  - GET /metrics: Prometheus metrics (scraped via ServiceMonitor)
"""

import json
import logging
import hmac
import os
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import httpx
from fastapi import FastAPI, Header, HTTPException, Request, Response
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Gauge,
    generate_latest,
)
from pydantic import BaseModel, Field

# ------------------------------------------------------------------ config --

AUTH_TOKEN = os.environ["AUTH_TOKEN"]
ALERTMANAGER_URL = os.environ.get("ALERTMANAGER_URL", "")
# If set, findings are POSTed straight to Loki (matches receiver v0.1.1
# behaviour); stdout JSON logging happens regardless.
LOKI_PUSH_URL = os.environ.get("LOKI_PUSH_URL", "")
ALERT_TTL_MINUTES = int(os.environ.get("ALERT_TTL_MINUTES", "120"))
REGISTRY_PATH = os.environ.get("REGISTRY_PATH", "/etc/ai-guard/registry.json")
# The endpoint collectors fetch their identifier lists from here at runtime
# instead of carrying hardcoded copies. Same ConfigMap, different view.
COLLECTOR_REGISTRY_PATH = os.environ.get(
    "COLLECTOR_REGISTRY_PATH", "/etc/ai-guard/collector.json"
)
# Timezone used only for the human-readable "detected" annotation on
# alerts. Machine timestamps are always UTC.
DISPLAY_TZ = ZoneInfo(os.environ.get("DISPLAY_TZ", "UTC"))

# "network" is a DNS/flow observation from SentinelOne: a device resolved a
# domain, but the resolving process may be a browser, a desktop app, a CLI or
# a system daemon. It is deliberately distinct from "browser", which means the
# extension saw an actual page load.
VALID_SURFACES = {"browser", "network", "cli", "ide", "desktop", "mcp", "cloud"}
VALID_SEVERITIES = {"info", "warn"}
# Bounded set: safe as a Loki stream label and a Prometheus metric label.
# Sources that pre-date the field (older browser extensions) report "unknown".
VALID_OS = {"macos", "windows", "linux", "unknown"}

logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(message)s")
log = logging.getLogger("ai-guard")

# ----------------------------------------------------------------- metrics --

# tool is deliberately NOT a label: it is user-submitted and unbounded, and
# every unique value mints a new time series (MCP findings alone would).
# Per-tool analytics come from the Loki log line, which carries tool safely.
FINDINGS = Counter(
    "aiguard_findings_total",
    "Findings ingested",
    ["surface", "severity", "os"],
)
# Same rationale as FINDINGS above: tool and account_domain are
# user-submitted and unbounded, so they must not become Prometheus labels
# (each unique value mints a time series, and /metrics is unauthenticated
# so label values are enumerable). The in-memory _active dict still tracks
# the full key for alert TTL; the exported gauge is a single total.
ACTIVE_SESSIONS = Gauge(
    "aiguard_personal_accounts_active",
    "Personal-account sessions currently inside the alert TTL (total)",
)
DEVICES_REPORTING = Gauge(
    "aiguard_devices_reporting",
    "Distinct devices seen in the last 24h",
    ["surface"],
)
LAST_REPORT = Gauge(
    "aiguard_last_scan_timestamp",
    "Unix time of the most recent finding per source surface",
    ["surface"],
)
REGISTRY_TOOLS = Gauge(
    "aiguard_registry_tools_total",
    "Number of tools in the served registry",
)

# ------------------------------------------------------------------- state --
# key -> expiry epoch. Key includes surface (new in 0.1.3).

_active_lock = threading.Lock()
_active: dict[tuple[str, str, str, str, str], float] = {}  # (device, tool, surface, domain, os)
_devices: dict[tuple[str, str], float] = {}  # (device, surface) -> last seen epoch


def _sweep_loop():
    while True:
        now = time.time()
        with _active_lock:
            for key, exp in list(_active.items()):
                if exp < now:
                    del _active[key]
                    _, _tool, _, domain, _osname = key
                    # Symmetric with the increment in /report: only sessions
                    # WITH an account domain were ever counted, so only those
                    # are uncounted. Bridge warns carry no domain; they sit in
                    # _active for alert TTL purposes but never touch the gauge.
                    # (Asymmetry here drove the gauge negative in an earlier version.)
                    if domain:
                        ACTIVE_SESSIONS.dec()
            for key, seen in list(_devices.items()):
                if seen < now - 86400:
                    del _devices[key]
            for surface in VALID_SURFACES:
                DEVICES_REPORTING.labels(surface=surface).set(
                    sum(1 for (_, s) in _devices if s == surface)
                )
        time.sleep(60)


threading.Thread(target=_sweep_loop, daemon=True).start()

# ------------------------------------------------------------------- model --


class Finding(BaseModel):
    tool: str = Field(min_length=1, max_length=200)
    surface: str = "browser"  # extension pre-dates the field
    os: str = "unknown"       # ditto
    account_domain: str = ""
    device: str = "unknown"
    user: str = ""
    evidence: str = ""
    severity: str = "warn"  # extension only reports violations
    reported_at: str = ""
    # Which detector produced this (entra_sign_in, sentinelone_bridge,
    # jamf_app, exchange_email...). Dashboards need it to separate bridge
    # observations from AI-tool findings; without it the tool inventory
    # cannot exclude bridge targets. Empty for pre-0.1.4 lines and for
    # extension flags via /flag.
    source: str = ""
    device_name: str = ""
    risk_tier: str = ""


# --------------------------------------------------------------------- app --

app = FastAPI(title="ai-guard-receiver", version="0.1.6")


def _load_registry() -> dict | None:
    try:
        with open(REGISTRY_PATH) as f:
            reg = json.load(f)
        REGISTRY_TOOLS.set(len(reg.get("tools", [])))
        return reg
    except (OSError, json.JSONDecodeError):
        return None


_load_registry()  # prime the gauge at boot


@app.get("/healthz")
def healthz():
    return {"ok": True, "version": app.version}


@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/registry")
def registry(authorization: str = Header(default="")):
    _auth(authorization)
    reg = _load_registry()
    if reg is None:
        raise HTTPException(503, "registry not available")
    return reg


@app.get("/registry/collector")
def registry_collector(authorization: str = Header(default="")):
    """cli/ide/desktop/mcp identifiers for the endpoint collectors.

    Served so a new AI tool is a registry merge request rather than an edit
    to every collector script plus an MDM re-paste on each platform.
    """
    _auth(authorization)
    try:
        with open(COLLECTOR_REGISTRY_PATH) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        raise HTTPException(503, "collector registry not available")


def _auth(authorization: str):
    # Constant-time comparison: a plain != leaks match length timing.
    if not hmac.compare_digest(authorization, f"Bearer {AUTH_TOKEN}"):
        raise HTTPException(401, "bad token")


# The Loki stream labels derived from each finding. Anything not in this
# set stays inside the JSON line body, parsed at query time. Adding a
# field here mints a new stream per unique value, so only bounded sets
# belong (surface, severity, os). Unbounded fields (tool, device,
# device_name, user, account_domain, risk_tier) must stay out.
LOKI_FINDING_LABELS = {"surface", "severity", "os"}


async def _push_loki(f: Finding, line: str):
    """Fire-and-forget push to Loki. Bounded labels only (no tool/device:
    unbounded values stay inside the JSON line, parsed at query time)."""
    payload = {
        "streams": [
            {
                "stream": {
                    "app": "ai-guard-receiver",
                    "kind": "finding",
                    **{k: getattr(f, k) for k in LOKI_FINDING_LABELS},
                },
                "values": [[str(time.time_ns()), line]],
            }
        ]
    }
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.post(LOKI_PUSH_URL, json=payload)
            r.raise_for_status()
    except httpx.HTTPError as e:
        log.info(json.dumps({"app": "ai-guard-receiver", "kind": "error",
                             "error": f"loki: {e}"}))


async def _fire_alert(f: Finding):
    if not ALERTMANAGER_URL:
        # Alerting is opt-in: no ALERTMANAGER_URL set means findings are
        # logged and dashboarded but nothing pages. Deliberate for adopters
        # without Alertmanager; set the env var to enable alerts.
        return
    now = datetime.now(timezone.utc)
    # Alert identity = who + which tool + which account. Deliberately NOT
    # device/os/evidence: one person signed into a personal account is ONE
    # alert, whether the collector sees them on two machines or re-reports
    # every scan. user is part of the fingerprint on purpose (one alert per
    # person); device and evidence ride in annotations for display only.
    # Do not move user to annotations: that re-fragments dedup per device,
    # and tool+account_domain alone would merge different people.
    alert = [
        {
            "labels": {
                "alertname": "PersonalAIAccountDetected"
                if f.account_domain
                else "ShadowAIUnapprovedTool",
                "tool": f.tool,
                "user": f.user or "unknown",
                "account_domain": f.account_domain or "none",
                "severity": "warning",
                "source": "ai-guard",
            },
            "annotations": {
                "summary": (
                    (f"{f.user} " if f.user else "")
                    + f"using {f.tool}"
                    + (f" with a personal {f.account_domain} account" if f.account_domain else "")
                    + f" on {f.device}"
                ),
                "user": f.user or "unknown",
                "device": f.device,
                "detected": now.astimezone(DISPLAY_TZ).strftime("%Y-%m-%d %H:%M:%S %Z"),
                "evidence": f.evidence,
            },
            "startsAt": now.isoformat(),
            "endsAt": (now + timedelta(minutes=ALERT_TTL_MINUTES)).isoformat(),
        }
    ]
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(f"{ALERTMANAGER_URL}/api/v2/alerts", json=alert)
        r.raise_for_status()


@app.post("/report")
@app.post("/flag")  # legacy path, kept for older browser extension versions
async def report(f: Finding, request: Request, authorization: str = Header(default="")):
    _auth(authorization)

    if f.surface not in VALID_SURFACES:
        f.surface = "browser"
    if f.severity not in VALID_SEVERITIES:
        f.severity = "warn"
    if f.os not in VALID_OS:
        f.os = "unknown"
    if not f.reported_at:
        f.reported_at = datetime.now(timezone.utc).isoformat()

    # Loki: every finding, warn and info alike. Stdout always; direct push
    # when LOKI_PUSH_URL is set (parity with receiver v0.1.1).
    line = json.dumps({"app": "ai-guard-receiver", "kind": "finding", **f.model_dump()})
    log.info(line)
    if LOKI_PUSH_URL:
        await _push_loki(f, line)

    FINDINGS.labels(
        surface=f.surface, severity=f.severity, os=f.os
    ).inc()
    LAST_REPORT.labels(surface=f.surface).set(time.time())
    with _active_lock:
        _devices[(f.device, f.surface)] = time.time()
        DEVICES_REPORTING.labels(surface=f.surface).set(
            sum(1 for (_, s) in _devices if s == f.surface)
        )

    alert_fired = False
    if f.severity == "warn":
        key = (f.device, f.tool, f.surface, f.account_domain, f.os)
        with _active_lock:
            fresh = key not in _active
            _active[key] = time.time() + ALERT_TTL_MINUTES * 60
            if fresh and f.account_domain:
                ACTIVE_SESSIONS.inc()
        # Bridge findings (source=sentinelone_bridge) are network observations,
        # not shadow-AI-tool warns - they must never page Slack as if a banned
        # tool were installed. Only account findings and genuine unapproved
        # tools alert.
        suppress = (f.source == "sentinelone_bridge")
        # Always refresh Alertmanager so endsAt extends; dedup of Slack pings
        # is governed by the route's repeat_interval, as in 0.1.2.
        try:
            if not suppress:
                await _fire_alert(f)
                alert_fired = True
        except httpx.HTTPError as e:
            log.info(json.dumps({"app": "ai-guard-receiver", "kind": "error",
                                 "error": f"alertmanager: {e}"}))

    return {"ok": True, "severity": f.severity, "alerted": alert_fired}