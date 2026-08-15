"""ai-guard receiver

Ingests findings from all four sources (browser extension, macOS collector,
Windows remediation, scanner CronJob) and routes them:

  severity=warn  -> Alertmanager (your alerting channel) + stdout JSON (Loki)
  severity=info  -> stdout JSON only (Loki inventory stream, no alert)
  missing        -> defaults to warn, so the existing browser extension
                    needs no change (it only ever reports violations)

Carried over from v0.1.2:
  - bearer token auth (AUTH_TOKEN)
  - optional basic auth to the log store (LOKI_USERNAME, LOKI_PASSWORD)
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
import urllib.parse
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import httpx
from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Gauge,
    generate_latest,
)
from pydantic import BaseModel, Field

# ------------------------------------------------------------------ config --

# Secrets can come from a file instead of the environment. Docker Compose has
# no real secret story: an environment variable is visible in `docker inspect`,
# in /proc, and in every child process's environment, while a file is confined
# to the filesystem. Better, but still plaintext on the same disk - this is not
# encryption, and the deployment docs say so rather than implying otherwise.
def _secret(name: str, default: str | None = None) -> str:
    path = os.environ.get(name + "_FILE")
    if path:
        if os.environ.get(name):
            # Ambiguous rather than harmless: someone believes one of these is
            # in effect, and it is not necessarily the one they think.
            print(
                "ai-guard: %s and %s_FILE are both set. The file wins; unset "
                "the environment variable to remove the ambiguity." % (name, name),
                file=sys.stderr,
            )
        try:
            with open(path) as fh:
                # Stripped. Almost every way of writing a file leaves a
                # trailing newline, and a token differing by one fails
                # authentication with no indication why.
                return fh.read().strip()
        except OSError as e:
            raise SystemExit(
                "%s_FILE is set to %s and it could not be read: %s" % (name, path, e)
            )

    val = os.environ.get(name)
    if val is not None:
        return val
    if default is not None:
        return default
    raise SystemExit(
        "%s is not set. Provide it directly, or set %s_FILE to a file "
        "containing it." % (name, name)
    )


AUTH_TOKEN = _secret("AUTH_TOKEN")
# Built once so the comparison below is against a fixed string.
_EXPECTED_AUTH = f"Bearer {AUTH_TOKEN}"
# Findings are small: a large one is a few hundred bytes. The cap exists so an
# unauthenticated client cannot make the receiver do work by sending something
# enormous. Raise it if a source legitimately sends more.
MAX_BODY_BYTES = int(os.environ.get("MAX_BODY_BYTES", "65536"))
ALERTMANAGER_URL = os.environ.get("ALERTMANAGER_URL", "")
# If set, findings are POSTed straight to Loki (matches receiver v0.1.1
# behaviour); stdout JSON logging happens regardless.
LOKI_PUSH_URL = os.environ.get("LOKI_PUSH_URL", "")


def _redact_url(url):
    """A URL with any embedded credentials removed, for logging.

    http://user:pass@host is a legal way to supply a URL, and this one is
    operator-supplied. It was written into the error log verbatim, so a
    deployer who put credentials in LOKI_PUSH_URL rather than in
    LOKI_USERNAME/LOKI_PASSWORD had them copied into stdout on every failed
    push, which is where the logs go and where they are least expected.

    The host stays, because naming which log store failed is the point of the
    message. Query and fragment go too: neither is meaningful for a push
    endpoint and both are places a credential gets put.

    Returns a placeholder rather than the raw string when it will not parse. A
    URL that cannot be parsed cannot be confirmed safe to echo.

    Copied from portal/app/main.py rather than shared, because the receiver and
    the portal are separate installables with nothing between them.
    """
    if not url:
        return ""
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return "<unparseable url>"
    if not parts.hostname:
        return "<redacted>"
    netloc = parts.hostname
    if parts.port:
        netloc = "%s:%d" % (netloc, parts.port)
    return urllib.parse.urlunsplit((parts.scheme, netloc, parts.path, "", ""))
# Hosted Loki (Grafana Cloud and most managed offerings) wants basic auth.
# Without these the only way to authenticate was to embed credentials in the
# URL, where they end up in `docker inspect` and in every log line that
# mentions the endpoint.
LOKI_USERNAME = _secret("LOKI_USERNAME", "")
LOKI_PASSWORD = _secret("LOKI_PASSWORD", "")
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
# A push that fails is a finding that exists only in this container's stdout.
# The receiver still returns 200 to the reporting source, which is right - a
# log store being down should not lose a collector's finding - but it means
# the failure is invisible from the outside unless something counts it.
LOKI_PUSH_FAILURES = Counter(
    "aiguard_loki_push_failures_total",
    "Pushes to the log store that failed, by reason. Any sustained increase "
    "means findings are being accepted and not stored.",
    ["reason"],
)

LOKI_PUSH_OK = Counter(
    "aiguard_loki_push_total",
    "Pushes to the log store that succeeded.",
)

# The one to alert on. Findings arrive irregularly, so a failure counter alone
# cannot distinguish "nothing is being pushed because nothing is happening"
# from "everything is failing". This is only set on success, so
# time() - aiguard_loki_push_last_success_timestamp answers it directly.
LOKI_PUSH_LAST_SUCCESS = Gauge(
    "aiguard_loki_push_last_success_timestamp",
    "Unix time of the last successful push to the log store.",
)

TOOL_NORMALISED = Counter(
    "aiguard_tool_normalised_total",
    "Findings whose tool name was a known domain and was rewritten to the "
    "registry id. A number that never moves means either every source already "
    "sends ids, or the registry is not loaded.",
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
    # Every field here arrives from outside, so every field is bounded. The
    # limits are sized to real use rather than round numbers: a domain cannot
    # exceed the DNS limit, evidence carries paths and detector lists, and
    # nothing else is longer than a hostname.
    tool: str = Field(min_length=1, max_length=200)
    surface: str = Field(default="browser", max_length=32)  # extension pre-dates the field
    os: str = Field(default="unknown", max_length=32)       # ditto
    account_domain: str = Field(default="", max_length=253)
    device: str = Field(default="unknown", max_length=256)
    user: str = Field(default="", max_length=256)
    evidence: str = Field(default="", max_length=2048)
    severity: str = Field(default="warn", max_length=16)  # extension only reports violations
    reported_at: str = Field(default="", max_length=64)
    # Which detector produced this (entra_sign_in, sentinelone_bridge,
    # jamf_app, exchange_email...). Dashboards need it to separate bridge
    # observations from AI-tool findings; without it the tool inventory
    # cannot exclude bridge targets. Empty for pre-0.1.4 lines and for
    # extension flags via /flag.
    source: str = Field(default="", max_length=64)
    device_name: str = Field(default="", max_length=256)
    risk_tier: str = Field(default="", max_length=32)
    # How many, and of what. The unit differs per source (sign-ins for Entra,
    # devices for Intune, signup emails for Exchange), so the number is only
    # meaningful next to it. Defaults keep older senders working: the browser
    # extension and pre-0.1.7 scanners do not send either field.
    occurrence_count: int = Field(default=1, ge=1, le=1_000_000)
    occurrence_unit: str = Field(default="detections", max_length=32)


# --------------------------------------------------------------------- app --

# Set at build time from the release tag, or the commit for a build off main.
# It was a hand-maintained constant, which drifted the way hand-maintained
# constants do: /healthz reported 0.1.6 while the release was 0.4.0, so the
# one endpoint an operator would check to answer "am I running what I think
# I am" answered a different question.
#
# "dev" is the honest answer for a local build, and more useful than a stale
# number that looks authoritative.
APP_VERSION = os.environ.get("APP_VERSION", "dev")

app = FastAPI(title="ai-guard-receiver", version=APP_VERSION)


# Paths that require the bearer token. /healthz and /metrics stay open:
# healthz is a probe target and metrics carries only bounded label values.
_PROTECTED = ("/report", "/flag", "/registry")


@app.middleware("http")
async def authenticate_before_reading(request: Request, call_next):
    """Check the token, and the size, before the body is touched.

    Without this the token check happens inside the endpoint, which means
    FastAPI has already read and validated the JSON body by the time an
    unauthenticated request is rejected. The receiver is meant to be
    internet-facing, so anyone could make it do that work. Here nothing is
    read until the caller has proved who they are.

    The endpoints still call _auth(). That is deliberate: it keeps them
    correct if this middleware is ever removed or reordered.
    """
    if request.url.path.startswith(_PROTECTED):
        if not hmac.compare_digest(
            request.headers.get("authorization", ""), _EXPECTED_AUTH
        ):
            return JSONResponse({"detail": "bad token"}, status_code=401)

        if request.method == "POST":
            declared = request.headers.get("content-length")
            if declared is None:
                # Every real client sends one. Refusing chunked bodies keeps
                # the size check meaningful rather than advisory.
                return JSONResponse(
                    {"detail": "content-length required"}, status_code=411
                )
            try:
                if int(declared) > MAX_BODY_BYTES:
                    return JSONResponse({"detail": "body too large"}, status_code=413)
            except ValueError:
                return JSONResponse({"detail": "bad content-length"}, status_code=400)

    return await call_next(request)


def _load_registry() -> dict | None:
    try:
        with open(REGISTRY_PATH) as f:
            reg = json.load(f)
        REGISTRY_TOOLS.set(len(reg.get("tools", [])))
        return reg
    except (OSError, json.JSONDecodeError):
        return None


# domain -> tool id. The browser extension reports the hostname it saw,
# because at the point it fires that is all it has; every other source reports
# the registry id. So one tool arrives as both chatgpt.com and chatgpt, splits
# into two rows on every dashboard, and the counts for each are wrong.
#
# Normalising here rather than in each consumer means every downstream reader
# agrees: Grafana, the portal, alerting. Fixing the extension to send the id is
# the better long-term answer, but that is a release and a managed-update cycle
# across two browsers, and findings already in flight would still be split.
#
# Unknown names pass through untouched. A tool the registry has never heard of
# is a registry gap worth seeing, not something to quietly fold into a
# neighbour.
def _build_domain_map(reg: dict | None) -> dict[str, str]:
    if not reg:
        return {}
    out: dict[str, str] = {}
    for t in reg.get("tools", []):
        tid = t.get("id")
        if not tid:
            continue
        for d in t.get("domains") or []:
            out[str(d).lower()] = tid
    return out


_DOMAIN_TO_TOOL = _build_domain_map(_load_registry())  # prime the gauge at boot


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
    # The middleware above is the real gate; this is defence in depth.
    if not hmac.compare_digest(authorization, _EXPECTED_AUTH):
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
    auth = (LOKI_USERNAME, LOKI_PASSWORD) if LOKI_USERNAME else None
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.post(LOKI_PUSH_URL, json=payload, auth=auth)
            r.raise_for_status()
    except httpx.HTTPStatusError as e:
        # Logged at error, not info. This was info, and a wrong push URL
        # therefore produced a 404 per finding that nobody read while the
        # receiver kept answering 200 to every collector. The finding is not
        # lost - it is on stdout - but it never reaches the log store, and
        # from the outside that is indistinguishable from a quiet estate.
        code = e.response.status_code
        LOKI_PUSH_FAILURES.labels(reason=f"http_{code}").inc()
        # A status code alone sends people to the wrong place. These two
        # account for almost every misconfiguration, and naming the likely
        # cause turns a wrong variable into a one-line fix.
        hints = {
            404: ("LOKI_PUSH_URL is probably the base URL rather than the "
                  "push endpoint, which is /loki/api/v1/push"),
            401: "LOKI_USERNAME and LOKI_PASSWORD are needed, or are wrong",
            403: "LOKI_USERNAME and LOKI_PASSWORD are wrong, or lack write access",
        }
        entry = {
            "app": "ai-guard-receiver", "kind": "error",
            "error": f"loki push rejected with HTTP {code}",
            "url": _redact_url(LOKI_PUSH_URL),
        }
        if code in hints:
            entry["hint"] = hints[code]
        log.error(json.dumps(entry))
    except httpx.HTTPError as e:
        LOKI_PUSH_FAILURES.labels(reason=type(e).__name__).inc()
        log.error(json.dumps({
            "app": "ai-guard-receiver", "kind": "error",
            # The exception type, not str(e). httpx puts the request URL in
            # the message, which would carry userinfo straight past the
            # redaction above.
            "error": "loki push failed: %s" % type(e).__name__,
            "url": _redact_url(LOKI_PUSH_URL),
        }))
    else:
        LOKI_PUSH_OK.inc()
        LOKI_PUSH_LAST_SUCCESS.set(time.time())


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

    # A hostname where the registry knows a tool id: rewrite it, and keep what
    # was sent. Nothing is discarded - the host lands in evidence when evidence
    # is otherwise empty, so the original is still on the finding rather than
    # only in whatever the sender happened to log.
    canonical = _DOMAIN_TO_TOOL.get(f.tool.lower())
    if canonical and canonical != f.tool:
        if not f.evidence:
            f.evidence = "site: %s" % f.tool
        TOOL_NORMALISED.labels(surface=f.surface).inc()
        f.tool = canonical

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