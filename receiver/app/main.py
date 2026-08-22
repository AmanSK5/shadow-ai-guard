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

import hmac
import json
import logging
import os
import sys
import threading
import time
import urllib.parse
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

# Importing the module costs nothing stateful: the SQLite file only exists
# once State() is instantiated, which only happens under MANAGED_MODE below.
from . import state as _state

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
# Built once, as bytes, so the comparison below is against a fixed value.
_EXPECTED_AUTH = b"Bearer " + AUTH_TOKEN.encode()


def _token_ok(header: str) -> bool:
    """Constant-time check of an Authorization header against the token.

    Compared as bytes, not str. hmac.compare_digest raises TypeError when
    either str argument contains a non-ASCII character, and Starlette decodes
    headers as latin-1, so any byte above 0x7f in the header reached the
    comparison as a non-ASCII str and threw instead of returning False. That
    was a 500 and a traceback on stdout per request, with no token required,
    on the one component meant to face the internet and whose stdout is the
    Loki stream.

    Encoding back to latin-1 cannot fail: that is the encoding the str came
    from. A plain != would leak match length through timing, so compare_digest
    stays.
    """
    return hmac.compare_digest(header.encode("latin-1"), _EXPECTED_AUTH)


def _ingest_token_ok(header: str) -> tuple[bool, dict | None]:
    """Is this bearer allowed to report and read the registry, and as whom?

    The shared token answers (True, None): the estate's anonymous credential,
    same as ever. In managed mode a device credential answers with its device
    row, so /report can stamp last_seen and agent_version - the difference
    between an inventory inferred from silence and one that knows who exists.
    A revoked device gets (False, None), which is the property this whole
    mechanism exists for. Lookup is by SHA-256 hash: without the plaintext an
    attacker cannot construct the hash, so an indexed equality match needs no
    constant-time scan.
    """
    if _token_ok(header):
        return True, None
    if STATE is not None and header.startswith("Bearer " + _state.DEVICE_PREFIX):
        dev = STATE.device_for(header[len("Bearer "):])
        if dev is not None:
            return True, dev
    return False, None
# Findings are small: a large one is a few hundred bytes. The cap exists so an
# unauthenticated client cannot make the receiver do work by sending something
# enormous. Raise it if a source legitimately sends more.
MAX_BODY_BYTES = int(os.environ.get("MAX_BODY_BYTES", "65536"))
ALERTMANAGER_URL = os.environ.get("ALERTMANAGER_URL", "")
# If set, findings are POSTed straight to Loki (matches receiver v0.1.1
# behaviour); stdout JSON logging happens regardless.
def require_http_url(name, url):
    """The URL back, or exit if it is not http or https.

    Refuses rather than warns. A log store URL that is not http is a typo or
    the wrong value pasted, and carrying on means findings accepted and never
    stored, which is the failure this project exists to notice.

    A separate function rather than an inline check so it can be tested without
    re-importing the module, which re-registers every Prometheus metric.
    """
    if url and not url.startswith(("http://", "https://")):
        raise SystemExit("%s must be http:// or https://, got %r"
                         % (name, url[:40]))
    return url


LOKI_PUSH_URL = require_http_url("LOKI_PUSH_URL",
                                 os.environ.get("LOKI_PUSH_URL", ""))


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


def _parse_corp_domains(raw: str) -> list[str]:
    """The comma-separated list as collectors need it: trimmed, lowercased,
    empties dropped, duplicates removed, order preserved. The macOS collector
    matches with a comma-anchored case pattern, so a stray space or an upper
    case letter served here would silently turn a work account into a warn.
    """
    out: list[str] = []
    for part in raw.split(","):
        d = part.strip().lower()
        if d and d not in out:
            out.append(d)
    return out


# Corporate domains, comma-separated (example.com,example.co.uk). When set,
# they ride inside /registry/collector as config.corp_domains and the
# collectors use them in place of their locally configured list, so one value
# changed here reaches the whole fleet on its next check-in instead of an MDM
# re-push per platform. Unset means collectors keep their local configuration,
# which is also what any collector talking to an older receiver does.
CORP_DOMAINS = _parse_corp_domains(os.environ.get("CORP_DOMAINS", ""))

# Managed mode: per-device credentials, enrollment, and a device inventory,
# backed by the first stateful thing in the project (one SQLite file). Off by
# default, and off means byte-for-byte today's receiver: no DB file created,
# /enroll and /admin/* answer 404. The shared AUTH_TOKEN keeps working for
# ingest either way - that is the migration path, an estate enrolls device by
# device while unenrolled machines keep reporting.
MANAGED_MODE = os.environ.get("MANAGED_MODE", "").lower() in ("1", "true", "yes")
STATE = None
_EXPECTED_ADMIN = b""
if MANAGED_MODE:
    # Required, not defaulted: managed mode without an admin credential is a
    # deployment that can never mint an enrollment token, which nobody means.
    # Deliberately a separate secret from AUTH_TOKEN - the shared token is on
    # every machine in the fleet, which is exactly why it must not be able to
    # mint credentials.
    _EXPECTED_ADMIN = b"Bearer " + _secret("ADMIN_TOKEN").encode()
    STATE = _state.State(os.environ.get("STATE_DB_PATH", "/var/lib/ai-guard/state.db"))

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


# Paths that require a bearer token. /healthz and /metrics stay open:
# healthz is a probe target and metrics carries only bounded label values.
# _PROTECTED takes the shared token or, in managed mode, a device credential;
# _MANAGED exists only in managed mode, with its own credentials.
_PROTECTED = ("/report", "/flag", "/registry")
_MANAGED = ("/enroll", "/admin")


def _body_size_response(request: Request):
    """The 4xx a too-large or unsized POST body earns, or None if fine."""
    if request.method != "POST":
        return None
    declared = request.headers.get("content-length")
    if declared is None:
        # No content-length and no transfer-encoding is no body at all -
        # which is what an admin revoke POST legitimately sends. A chunked
        # body, though, would slip past the size check, so it is refused:
        # every real client that sends a body sends a content-length.
        if request.headers.get("transfer-encoding") is None:
            return None
        return JSONResponse({"detail": "content-length required"}, status_code=411)
    try:
        if int(declared) > MAX_BODY_BYTES:
            return JSONResponse({"detail": "body too large"}, status_code=413)
    except ValueError:
        return JSONResponse({"detail": "bad content-length"}, status_code=400)
    return None


@app.middleware("http")
async def authenticate_before_reading(request: Request, call_next):
    """Check the token, and the size, before the body is touched.

    Without this the token check happens inside the endpoint, which means
    FastAPI has already read and validated the JSON body by the time an
    unauthenticated request is rejected. The receiver is meant to be
    internet-facing, so anyone could make it do that work. Here nothing is
    read until the caller has proved who they are.

    The endpoints still call their _auth counterparts. That is deliberate: it
    keeps them correct if this middleware is ever removed or reordered.
    """
    path = request.url.path
    if path.startswith(_PROTECTED):
        ok, device = _ingest_token_ok(request.headers.get("authorization", ""))
        if not ok:
            return JSONResponse({"detail": "bad token"}, status_code=401)
        # Which device authenticated, for /report to stamp last_seen. None
        # when the shared token did, which is not an identity.
        request.state.device = device
        resp = _body_size_response(request)
        if resp is not None:
            return resp

    elif path.startswith(_MANAGED):
        if STATE is None:
            # Managed mode off: these routes do not exist, and 404 rather
            # than 401 so a classic deployment does not advertise them.
            return JSONResponse({"detail": "Not Found"}, status_code=404)
        auth = request.headers.get("authorization", "")
        if path.startswith("/admin"):
            # The emptiness guard is not redundant: compare_digest holds two
            # empty strings equal, so without it a deployment that somehow
            # had state but no admin credential would let an empty header in.
            if not _EXPECTED_ADMIN or not hmac.compare_digest(
                auth.encode("latin-1"), _EXPECTED_ADMIN
            ):
                return JSONResponse({"detail": "bad token"}, status_code=401)
        else:
            # /enroll authenticates against the DB inside the handler; here
            # only the credential shape is checked, so an arbitrary bearer
            # still cannot make the receiver read a body.
            if not auth.startswith("Bearer " + _state.ENROLL_PREFIX):
                return JSONResponse({"detail": "bad token"}, status_code=401)
        resp = _body_size_response(request)
        if resp is not None:
            return resp

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
def registry(request: Request, authorization: str = Header(default="")):
    _auth(authorization)
    _touch_device(request)
    reg = _load_registry()
    if reg is None:
        raise HTTPException(503, "registry not available")
    return reg


@app.get("/registry/collector")
def registry_collector(request: Request, authorization: str = Header(default="")):
    """cli/ide/desktop/mcp identifiers for the endpoint collectors.

    Served so a new AI tool is a registry merge request rather than an edit
    to every collector script plus an MDM re-paste on each platform.

    Deployment config rides in the same response under "config" when the
    receiver has any to serve. The collectors already fetch this payload on
    every run, so central config costs no extra request, and a collector that
    pre-dates the key ignores it.
    """
    _auth(authorization)
    _touch_device(request)
    try:
        with open(COLLECTOR_REGISTRY_PATH) as f:
            reg = json.load(f)
    except (OSError, json.JSONDecodeError):
        raise HTTPException(503, "collector registry not available")
    if CORP_DOMAINS and isinstance(reg, dict):
        reg.setdefault("config", {})["corp_domains"] = CORP_DOMAINS
    return reg


def _auth(authorization: str):
    # The middleware above is the real gate; this is defence in depth. Shared
    # token or device credential, same as the middleware accepts.
    ok, _ = _ingest_token_ok(authorization)
    if not ok:
        raise HTTPException(401, "bad token")


def _touch_device(request: Request):
    """Stamp last_seen (and the agent version, when sent) for the device that
    authenticated this request.

    A device credential is an identity; the shared token is not. Called from
    every authenticated route, registry reads included, because "seen" should
    mean seen: discovery only ever reads the registry, and a collector's
    registry fetch precedes its report. The version travels as a header so
    the finding schema stays untouched. That stamp is what turns the
    inventory from inferred-from-silence into one that knows who exists and
    what they run.
    """
    device = getattr(request.state, "device", None)
    if device is not None and STATE is not None:
        STATE.touch_device(
            device["id"], request.headers.get("x-aiguard-agent-version", "")[:32]
        )


def _admin_auth(authorization: str):
    # Defence in depth for /admin/*, like _auth for ingest. 404 when managed
    # mode is off: routes that do not exist should not confirm they exist.
    if STATE is None:
        raise HTTPException(404, "Not Found")
    if not _EXPECTED_ADMIN or not hmac.compare_digest(
        authorization.encode("latin-1"), _EXPECTED_ADMIN
    ):
        raise HTTPException(401, "bad token")


# What can enroll. The three collector platforms, one browser profile
# (platform "browser", serial = MDM device id plus a per-profile install id,
# since one machine legitimately runs several managed profiles), and a scanner
# (platform "scanner", serial = its configured id). The (platform, serial) key
# is what keeps a laptop's browser profile from colliding with its collector.
PLATFORMS = ("macos", "linux", "windows", "browser", "scanner")


class EnrollRequest(BaseModel):
    platform: str = Field(min_length=1, max_length=32)
    serial: str = Field(min_length=1, max_length=256)
    hostname: str = Field(default="", max_length=256)
    agent_version: str = Field(default="", max_length=32)


class MintRequest(BaseModel):
    # note is the operator's label ("macOS Jamf rollout"), shown wherever the
    # token id appears, because a list of anonymous credentials with expiry
    # dates is unmanageable the day there are three of them.
    note: str = Field(default="", max_length=200)
    ttl_days: int = Field(default=180, ge=1, le=3650)


@app.post("/enroll")
def enroll(req: EnrollRequest, authorization: str = Header(default="")):
    """Exchange an enrollment token for this machine's own credential.

    The one moment a device credential exists in plaintext. Collectors store
    it root-only in their state dir and present it from then on; the
    enrollment token itself can do nothing but this exchange.
    """
    if STATE is None:
        raise HTTPException(404, "Not Found")
    if req.platform not in PLATFORMS:
        raise HTTPException(422, "platform must be one of " + ", ".join(PLATFORMS))
    token = authorization[len("Bearer "):] if authorization.startswith("Bearer ") else ""
    try:
        result = STATE.enroll(token, req.platform, req.serial, req.hostname,
                              req.agent_version)
    except _state.EnrollError as e:
        raise HTTPException(e.status, e.detail)
    log.info(json.dumps({"app": "ai-guard-receiver", "kind": "enrolled",
                         "device_id": result["device_id"],
                         "platform": req.platform, "serial": req.serial}))
    return result


@app.post("/admin/enrollment-tokens")
def mint_enrollment_token(req: MintRequest, authorization: str = Header(default="")):
    _admin_auth(authorization)
    return STATE.mint_token(req.note, req.ttl_days)


@app.get("/admin/enrollment-tokens")
def list_enrollment_tokens(authorization: str = Header(default="")):
    # No hashes and no plaintext: a listing is for judging expiry and
    # provenance, not for recovering credentials.
    _admin_auth(authorization)
    return {"tokens": STATE.list_tokens()}


@app.post("/admin/enrollment-tokens/{tid}/revoke")
def revoke_enrollment_token(tid: str, authorization: str = Header(default="")):
    _admin_auth(authorization)
    if not STATE.revoke_token(tid):
        raise HTTPException(404, "no such active token")
    return {"ok": True}


@app.get("/admin/devices")
def list_devices(authorization: str = Header(default="")):
    _admin_auth(authorization)
    return {"devices": STATE.list_devices()}


@app.post("/admin/devices/{did}/revoke")
def revoke_device(did: str, authorization: str = Header(default="")):
    _admin_auth(authorization)
    if not STATE.revoke_device(did):
        raise HTTPException(404, "no such active device")
    return {"ok": True}


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
    _touch_device(request)

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
            log.error(json.dumps({
                "app": "ai-guard-receiver", "kind": "error",
                "error": "alertmanager: %s" % type(e).__name__,
                "url": _redact_url(ALERTMANAGER_URL),
            }))

    return {"ok": True, "severity": f.severity, "alerted": alert_fired}