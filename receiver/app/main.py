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
import re
import secrets
import sys
import threading
import time
import urllib.parse
from datetime import date, datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import httpx
import jsonschema
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
from . import budget as _budget
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
        # The shared token: the estate's anonymous credential - until the
        # operator turns it off, at which point it is a known string that
        # is no longer a credential at all.
        return (not REQUIRE_DEVICE_CREDENTIALS), None
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
    # Optional since 0.9.7: the admin API credential for automation and for
    # break-glass (locked out of the portal: set this, call the API, reset
    # the password). Humans authenticate with an account and a session
    # instead - see /admin/setup below - so a fresh deployment needs no
    # pre-provisioned admin secret at all. Still deliberately separate from
    # AUTH_TOKEN: the shared token is on every machine in the fleet, which
    # is exactly why it must not be able to mint credentials.
    _admin_api_token = _secret("ADMIN_TOKEN", "")
    if _admin_api_token:
        _EXPECTED_ADMIN = b"Bearer " + _admin_api_token.encode()
    STATE = _state.State(os.environ.get("STATE_DB_PATH", "/var/lib/ai-guard/state.db"))

# How long a portal login lasts. Sessions stand in for a person at a
# keyboard, so they expire on their own; 24 hours means logging in about
# once a working day.
SESSION_TTL_HOURS = int(os.environ.get("SESSION_TTL_HOURS", "24"))

# What a failed login costs, beyond the scrypt derivation itself. A flat
# pause rather than progressive lockout: this credential is behind the
# operator's ingress, and a counter that can lock the real admin out is a
# denial-of-service lever pointed at the person who would respond.
LOGIN_FAILURE_DELAY_SECONDS = 0.5
# Failed-login throttling, because /admin/login is necessarily open and
# scrypt is deliberately expensive - which cuts both ways: without a cap an
# unauthenticated caller can spend receiver CPU and threadpool capacity
# freely, and grow the audit log one row per attempt. Counters live in
# memory; a restart forgives, which is fine - the defence is against
# sustained abuse, not perfect accounting.
LOGIN_WINDOW_SECONDS = 300
LOGIN_MAX_FAILURES_PER_USER = 10
LOGIN_MAX_FAILURES_GLOBAL = 50
# How many failures per username per window earn their own audit event;
# past that, the single throttle event is the record, so an attack cannot
# write the audit log full.
LOGIN_LOGGED_FAILURES = 3
_login_failures: dict[str, list] = {}
_login_lock = threading.Lock()
# scrypt work is bounded in parallel too, so a burst that stays under the
# counters still cannot occupy every worker thread at once.
_scrypt_gate = threading.BoundedSemaphore(4)


def _login_gate(username: str) -> tuple[int, int]:
    """Failures in the current window for this username, and across all of
    them, after sweeping expired entries."""
    cutoff = time.time() - LOGIN_WINDOW_SECONDS
    with _login_lock:
        total = 0
        for k in list(_login_failures):
            kept = [ts for ts in _login_failures[k] if ts > cutoff]
            if kept:
                _login_failures[k] = kept
                total += len(kept)
            else:
                del _login_failures[k]
        return len(_login_failures.get(username, [])), total


def _login_failed(username: str):
    with _login_lock:
        _login_failures.setdefault(username, []).append(time.time())

# The off-switch for the shared token, once every surface has enrolled: with
# this set, /report and /registry accept device credentials only and the
# shared AUTH_TOKEN is refused with a 401 that says so. It is the final step
# of a migration, not a mode: flip it back and unenrolled machines report
# again. Meaningless without managed mode - there would be no other credential
# to require - so that combination is a startup error rather than a receiver
# that silently rejects everything.
REQUIRE_DEVICE_CREDENTIALS = os.environ.get(
    "REQUIRE_DEVICE_CREDENTIALS", "").lower() in ("1", "true", "yes")
if REQUIRE_DEVICE_CREDENTIALS and not MANAGED_MODE:
    raise SystemExit(
        "REQUIRE_DEVICE_CREDENTIALS needs MANAGED_MODE=true: without enrollment"
        " there is no credential to require"
    )

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

# The first-boot door. While no admin account exists, every boot mints a
# fresh one-time setup code and prints it to the log - the one channel an
# operator who has just run `helm install` provably has. It lives only in
# this process (never the database), dies when claimed, and once an account
# exists boots print nothing. kubectl logs deploy/ai-guard-receiver | grep
# setup_code is the whole retrieval story, and NOTES.txt says so.
_SETUP_CODE = None
if STATE is not None and not STATE.has_admin():
    _SETUP_CODE = _state.SETUP_PREFIX + secrets.token_urlsafe(24)
    log.info(json.dumps({
        "app": "ai-guard-receiver", "kind": "setup_code",
        "setup_code": _SETUP_CODE,
        "hint": "no admin account exists yet; enter this code in the portal"
                " to create one",
    }))

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
_PROTECTED = ("/report", "/flag", "/registry", "/candidates")
_MANAGED = ("/enroll", "/admin")

# The two doors into admin auth. Exempt from the admin gate - they are how a
# session comes to exist - but not from the body-size gate, and they answer
# 404 like everything managed when managed mode is off.
_ADMIN_OPEN = ("/admin/setup", "/admin/login")


def _admin_role(header: str) -> str | None:
    """Which trust level this Authorization header carries, or None.

    Two shapes: the optional API credential (ADMIN_TOKEN, for automation and
    break-glass), which is always an admin because both of those are
    operator acts; or a live portal session minted by /admin/login, which
    carries its account's role. The emptiness guard is not redundant:
    compare_digest holds two empty strings equal, so without it a
    deployment with no ADMIN_TOKEN would let an empty header in.
    """
    if _EXPECTED_ADMIN and hmac.compare_digest(
        header.encode("latin-1"), _EXPECTED_ADMIN
    ):
        return "admin"
    if STATE is not None and header.startswith("Bearer " + _state.SESSION_PREFIX):
        u = STATE.session_user(header[len("Bearer "):])
        if u is not None:
            return u.get("role") or "admin"
    return None


def _admin_header_ok(header: str) -> bool:
    return _admin_role(header) is not None


def _body_size_response(request: Request):
    """The 4xx a too-large or unsized POST/PUT body earns, or None if fine.

    PUT joined POST when /admin/settings arrived: a method check that names
    only POST is a size cap the next body-carrying method silently walks
    past.
    """
    if request.method not in ("POST", "PUT"):
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
        auth = request.headers.get("authorization", "")
        ok, device = _ingest_token_ok(auth)
        if not ok:
            # Named when it is the shared token being turned away: the
            # straggler's MDM log should say "enroll", not "bad token".
            detail = ("shared token not accepted: this receiver requires device"
                      " credentials; enroll with an enrollment token"
                      if REQUIRE_DEVICE_CREDENTIALS and _token_ok(auth) else "bad token")
            return JSONResponse({"detail": detail}, status_code=401)
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
            if path not in _ADMIN_OPEN and not _admin_header_ok(auth):
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
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def _merged_registry() -> dict | None:
    """The shipped registry with the portal-defined entries appended.

    Shipped wins on an id collision: a release that starts shipping a tool
    an operator defined earlier should supersede the local copy, and the
    admin listing marks the local one as shadowed so it gets deleted
    rather than silently ignored. Classic mode has no STATE and this is
    exactly the file, as ever.
    """
    reg = _load_registry()
    if reg is None:
        return None
    if STATE is not None:
        custom = STATE.registry_entry_values()
        if custom and isinstance(reg, dict):
            reg = dict(reg)
            shipped_ids = {t.get("id") for t in reg.get("tools", [])}
            reg["tools"] = list(reg.get("tools", [])) + [
                e for e in custom if e.get("id") not in shipped_ids]
    if isinstance(reg, dict):
        REGISTRY_TOOLS.set(len(reg.get("tools", [])))
    return reg


def _collector_rows(tools: list[dict]) -> dict:
    """The per-surface collector view of a list of tool entries.

    A reimplementation of registry/build.py's emit() transform, because
    the receiver cannot import a module from a tree that is not in its
    image. A test asserts parity against the real build.py, so the two
    cannot drift silently.
    """
    return {
        "cli": [{"tool": t["id"], **t["cli"]} for t in tools if t.get("cli")],
        "desktop": [{"tool": t["id"], "app_names": t["app_names"],
                     "bundle_ids": t.get("bundle_ids", [])}
                    for t in tools if t.get("app_names")],
        "ide": [{"tool": t["id"], "extension_ids": t["extension_ids"]}
                for t in tools if t.get("extension_ids")],
        "mcp": [{"tool": t["id"], "path": p, "os": os_}
                for t in tools
                for key, os_ in (("mcp_config_paths", "any"),
                                 ("mcp_config_paths_macos", "macos"),
                                 ("mcp_config_paths_windows", "windows"),
                                 ("mcp_config_paths_linux", "linux"))
                for p in t.get(key, [])],
    }


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


def _refresh_domain_map():
    """Rebuild the domain→tool map (and the id set) from the merged
    registry. Called at boot and after every custom-entries write, so a
    domain defined in the portal normalizes findings from that moment and
    an id defined in the portal stops its MCP namesake becoming a
    candidate."""
    global _DOMAIN_TO_TOOL, _REGISTRY_IDS
    reg = _merged_registry()
    _DOMAIN_TO_TOOL = _build_domain_map(reg)
    _REGISTRY_IDS = {t.get("id") for t in (reg or {}).get("tools", [])
                     if t.get("id")}


_DOMAIN_TO_TOOL: dict[str, str] = {}
_REGISTRY_IDS: set[str] = set()
_refresh_domain_map()  # also primes the tools gauge at boot


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
    reg = _merged_registry()
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
    if STATE is not None and isinstance(reg, dict):
        # Portal-defined tools join every surface's identifier list, so a
        # tool defined in the Registry view is detected on the fleet's
        # next check-in - the whole point of defining it there.
        custom = STATE.registry_entry_values()
        if custom:
            for section, rows in _collector_rows(custom).items():
                if rows:
                    reg.setdefault(section, [])
                    reg[section] = list(reg[section]) + rows
    domains = _effective_corp_domains()
    if domains and isinstance(reg, dict):
        reg.setdefault("config", {})["corp_domains"] = domains
    return reg


def _effective_corp_domains() -> list[str]:
    """The corp domains the fleet should hear: the portal-saved list when
    one exists, the environment otherwise.

    The DB row wins even when empty - an operator who saved an empty list
    said "none", and falling back to the env there would resurrect the very
    value they removed. Deleting the row (set_setting None) is how the env
    comes back into effect.
    """
    if STATE is not None:
        stored = STATE.get_setting("corp_domains")
        if stored is not None:
            return stored
    return CORP_DOMAINS


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


def _admin_auth(authorization: str, write: bool = False):
    # Defence in depth for /admin/*, like _auth for ingest. 404 when managed
    # mode is off: routes that do not exist should not confirm they exist.
    # write=True is the role gate: a viewer account reads everything and
    # changes nothing, and the refusal names the reason rather than lying
    # with a generic 401 to someone who IS authenticated.
    if STATE is None:
        raise HTTPException(404, "Not Found")
    role = _admin_role(authorization)
    if role is None:
        raise HTTPException(401, "bad token")
    if write and role != "admin":
        raise HTTPException(403, "this account is read-only: an admin "
                                 "account has to make this change")


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
    _admin_auth(authorization, write=True)
    return STATE.mint_token(req.note, req.ttl_days)


@app.get("/admin/enrollment-tokens")
def list_enrollment_tokens(authorization: str = Header(default="")):
    # No hashes and no plaintext: a listing is for judging expiry and
    # provenance, not for recovering credentials.
    _admin_auth(authorization)
    return {"tokens": STATE.list_tokens()}


@app.post("/admin/enrollment-tokens/{tid}/revoke")
def revoke_enrollment_token(tid: str, authorization: str = Header(default="")):
    _admin_auth(authorization, write=True)
    if not STATE.revoke_token(tid):
        raise HTTPException(404, "no such active token")
    return {"ok": True}


@app.get("/admin/devices")
def list_devices(authorization: str = Header(default="")):
    _admin_auth(authorization)
    return {"devices": STATE.list_devices()}


@app.post("/admin/devices/{did}/revoke")
def revoke_device(did: str, authorization: str = Header(default="")):
    _admin_auth(authorization, write=True)
    if not STATE.revoke_device(did):
        raise HTTPException(404, "no such active device")
    return {"ok": True}


# ------------------------------------------------------- admin accounts --


def _bearer(authorization: str) -> str:
    return (authorization[len("Bearer "):]
            if authorization.startswith("Bearer ") else "")


class SetupRequest(BaseModel):
    setup_code: str = Field(min_length=1, max_length=128)
    username: str = Field(min_length=1, max_length=64)
    # Length is the whole policy. Composition rules produce Password1! and
    # a false sense of review; twelve characters of anything does better.
    password: str = Field(min_length=12, max_length=256)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class PasswordChangeRequest(BaseModel):
    current: str = Field(default="", max_length=256)
    new: str = Field(min_length=12, max_length=256)


@app.get("/admin/setup")
def setup_needed():
    """Whether the create-account door is open. Unauthenticated by design:
    it says one bit, and the portal needs that bit to choose between the
    sign-in form and the create-account form honestly."""
    if STATE is None:
        raise HTTPException(404, "Not Found")
    return {"needed": not STATE.has_admin()}


@app.post("/admin/setup")
def setup(req: SetupRequest):
    """Claim the boot-printed setup code and become the admin.

    Returns a session directly: the operator who just chose this password
    proving it again at a login screen is a step with no security content.
    The code dies here whether or not it ever leaked - a fresh boot mints a
    fresh one, and once the account exists boots mint none at all.
    """
    global _SETUP_CODE
    if STATE is None:
        raise HTTPException(404, "Not Found")
    if STATE.has_admin():
        raise HTTPException(409, "an admin account already exists")
    # Compared as bytes: compare_digest raises on a non-ASCII str, and the
    # submitted code is arbitrary JSON - same trap _token_ok documents.
    if _SETUP_CODE is None or not hmac.compare_digest(
        req.setup_code.encode(), _SETUP_CODE.encode()
    ):
        time.sleep(LOGIN_FAILURE_DELAY_SECONDS)
        raise HTTPException(401, "bad setup code")
    STATE.create_admin(req.username, req.password)
    _SETUP_CODE = None
    log.info(json.dumps({"app": "ai-guard-receiver", "kind": "admin_created",
                         "username": req.username}))
    return STATE.login(req.username, req.password, SESSION_TTL_HOURS)


@app.post("/admin/login")
def login(req: LoginRequest):
    if STATE is None:
        raise HTTPException(404, "Not Found")
    user_n, global_n = _login_gate(req.username)
    if (user_n >= LOGIN_MAX_FAILURES_PER_USER
            or global_n >= LOGIN_MAX_FAILURES_GLOBAL):
        # Refused before any scrypt work, sleep, or database write: the
        # point of the throttle is that a rejected attempt costs nearly
        # nothing. The single login_throttled event below is the audit
        # record; per-attempt rows here would be the attack writing our
        # log for us.
        raise HTTPException(
            429, "too many failed sign-ins; try again in a few minutes",
            headers={"Retry-After": str(LOGIN_WINDOW_SECONDS)})
    # The slot is taken without blocking: a burst that beats the failure
    # counters must be refused, not queued, or the waiters themselves
    # occupy worker threads - the exhaustion the gate exists to prevent.
    if not _scrypt_gate.acquire(blocking=False):
        raise HTTPException(
            429, "too many concurrent sign-ins; try again in a moment",
            headers={"Retry-After": "5"})
    try:
        return STATE.login(req.username, req.password, SESSION_TTL_HOURS,
                           log_failure=user_n < LOGIN_LOGGED_FAILURES)
    except _state.AuthError as e:
        _login_failed(req.username)
        if user_n + 1 == LOGIN_MAX_FAILURES_PER_USER:
            STATE.record_login_throttled(req.username)
        time.sleep(LOGIN_FAILURE_DELAY_SECONDS)
        raise HTTPException(e.status, e.detail)
    finally:
        _scrypt_gate.release()


@app.post("/admin/logout")
def logout(authorization: str = Header(default="")):
    _admin_auth(authorization)
    token = _bearer(authorization)
    if token.startswith(_state.SESSION_PREFIX):
        STATE.logout(token)
    # The API credential cannot log out - it is configuration, not a
    # session - and saying ok either way keeps the portal's logout simple.
    return {"ok": True}


@app.get("/admin/session")
def session_info(authorization: str = Header(default="")):
    """The portal's validity probe: who is this session, until when.

    The API credential answers too (it passed the gate), with an empty
    username - it is a credential, not a person.
    """
    _admin_auth(authorization)
    token = _bearer(authorization)
    if token.startswith(_state.SESSION_PREFIX):
        u = STATE.session_user(token)
        if u is not None:
            return {"username": u["username"], "expires_at": u["expires_at"],
                    "role": u.get("role") or "admin"}
    return {"username": "", "expires_at": None, "role": "admin"}


# -------------------------------------------------------------- accounts --
# Admin runs the platform; viewer reads it and changes nothing - the
# auditor, the exec, the person who needs the pages but must never be a
# way in. Every action below lands in the audit trail with who did it.

_USERNAME_RE = re.compile(r"^[a-zA-Z0-9._@-]{2,64}$")


class UserCreate(BaseModel):
    model_config = {"extra": "forbid"}
    username: str = Field(min_length=2, max_length=64)
    password: str = Field(min_length=12, max_length=256)
    role: str = Field(min_length=1, max_length=16)


class UserPasswordReset(BaseModel):
    model_config = {"extra": "forbid"}
    new: str = Field(min_length=12, max_length=256)


@app.get("/admin/users")
def get_users(authorization: str = Header(default="")):
    _admin_auth(authorization)
    return {"users": STATE.list_users()}


@app.post("/admin/users")
def post_user(req: UserCreate, authorization: str = Header(default="")):
    _admin_auth(authorization, write=True)
    if not _USERNAME_RE.match(req.username):
        raise HTTPException(422, "usernames are 2-64 characters of letters, "
                                 "digits, . _ @ -")
    try:
        return STATE.create_user(req.username, req.password, req.role,
                                 _admin_actor(authorization))
    except _state.AuthError as e:
        raise HTTPException(e.status, e.detail)


@app.post("/admin/users/{uid}/delete")
def delete_user(uid: str, authorization: str = Header(default="")):
    _admin_auth(authorization, write=True)
    if not re.fullmatch(r"[0-9a-f]{16}", uid):
        raise HTTPException(422, "malformed user id")
    try:
        if not STATE.delete_user(uid, _admin_actor(authorization)):
            raise HTTPException(404, "no account with that id")
    except _state.AuthError as e:
        raise HTTPException(e.status, e.detail)
    return {"deleted": uid}


@app.post("/admin/users/{uid}/password")
def reset_user_password(uid: str, req: UserPasswordReset,
                        authorization: str = Header(default="")):
    """An admin setting someone else's password - the forgotten-password
    path. Changing your own goes through /admin/password, which proves the
    current one."""
    _admin_auth(authorization, write=True)
    if not re.fullmatch(r"[0-9a-f]{16}", uid):
        raise HTTPException(422, "malformed user id")
    if not STATE.reset_user_password(uid, req.new,
                                     _admin_actor(authorization)):
        raise HTTPException(404, "no account with that id")
    return {"reset": uid}


# ------------------------------------------------------- central settings --
# Deployment configuration the portal edits and the fleet hears at runtime.
# Precedence is DB-wins-when-set: a saved value overrides the matching
# environment variable, and clearing it (null) falls back. The environment
# stays the whole story for classic mode, which has no DB to consult.


def _admin_actor(authorization: str) -> str:
    """Who to stamp on a write: the session's username, or "api" for the
    ADMIN_TOKEN credential - a credential, not a person."""
    token = _bearer(authorization)
    if STATE is not None and token.startswith(_state.SESSION_PREFIX):
        u = STATE.session_user(token)
        if u is not None:
            return u["username"]
    return "api"


# Central settings that are plain strings, written through the generic loop
# in put_settings: (key, must_be_http_url, max_length). Secret keys are the
# same shape to write but are never echoed by GET /admin/settings.
_STR_SETTINGS = (
    ("receiver_public_url", True, 500),
    ("log_store_url", True, 500),
    ("log_store_push_url", True, 500),
    ("log_store_username", False, 256),
    ("log_store_password", False, 512),
    ("alertmanager_url", True, 500),
    ("grafana_url", True, 500),
    ("grafana_panels", False, 2000),
    ("grafana_dashboard_uid", False, 128),
    ("overview_widgets", False, 500),
    # Where the packed extension is served from: the Chromium update
    # manifest, the packed .crx it points at, and the Mozilla-signed .xpi.
    # The portal bakes these into the Windows deploy scripts, the Firefox
    # policy, and the generated update manifests.
    ("extension_update_url", True, 500),
    ("extension_crx_url", True, 500),
    ("extension_xpi_url", True, 500),
    # Where event notifications go: a Slack-compatible incoming webhook.
    # Fired on a NEW discovery candidate - the moment a human decision
    # becomes needed - and never per finding, which would be a firehose.
    ("webhook_url", True, 500),
)

# What the paste guard does when a marked document is pasted into an AI
# tool. Baked into every extension policy artifact; "warn" is the default
# when unset, matching the extension's own default.
_PASTE_GUARD_MODES = ("off", "warn", "block")
SECRET_SETTINGS = ("log_store_password", "webhook_url")


class SettingsUpdate(BaseModel):
    # extra=forbid: an unknown key is a typo or a version mismatch, and
    # accepting it silently is how someone believes a setting is in effect.
    model_config = {"extra": "forbid"}
    corp_domains: list[str] | None = Field(default=None, max_length=200)
    extension_id: str | None = Field(default=None, max_length=128)
    onboarding_done: bool | None = None
    receiver_public_url: str | None = Field(default=None, max_length=500)
    log_store_url: str | None = Field(default=None, max_length=500)
    log_store_push_url: str | None = Field(default=None, max_length=500)
    log_store_username: str | None = Field(default=None, max_length=256)
    log_store_password: str | None = Field(default=None, max_length=512)
    alertmanager_url: str | None = Field(default=None, max_length=500)
    grafana_url: str | None = Field(default=None, max_length=500)
    grafana_panels: str | None = Field(default=None, max_length=2000)
    grafana_dashboard_uid: str | None = Field(default=None, max_length=128)
    overview_widgets: str | None = Field(default=None, max_length=500)
    extension_update_url: str | None = Field(default=None, max_length=500)
    extension_crx_url: str | None = Field(default=None, max_length=500)
    extension_xpi_url: str | None = Field(default=None, max_length=500)
    webhook_url: str | None = Field(default=None, max_length=500)
    paste_guard_mode: str | None = Field(default=None, max_length=8)
    firefox_extension_id: str | None = Field(default=None, max_length=128)
    classification_markings: list[str] | None = Field(default=None,
                                                      max_length=50)


@app.get("/admin/settings")
def get_settings(authorization: str = Header(default="")):
    """Each setting with its effective value AND where it came from, because
    the portal must show when a saved value is shadowing an environment one
    rather than let two sources of truth look like one."""
    _admin_auth(authorization)
    stored = STATE.get_settings()
    corp = stored.get("corp_domains")

    def plain(key, env=""):
        """One string setting with its effective value and source. env is
        this component's fallback; keys whose env lives on the portal
        report db|unset here and the portal overlays its own."""
        v = stored.get(key)
        out = {"value": v if v is not None else env,
               "source": "db" if v is not None else ("env" if env else "unset")}
        if env:
            out["env"] = env
        return out

    return {"settings": {
        "corp_domains": {
            "value": corp if corp is not None else CORP_DOMAINS,
            "source": ("db" if corp is not None
                       else "env" if CORP_DOMAINS else "unset"),
            # The env list rides along so the portal can say what a saved
            # value is shadowing, and what clearing it would fall back to.
            "env": CORP_DOMAINS,
        },
        "extension_id": {
            "value": stored.get("extension_id") or "",
            "source": "db" if stored.get("extension_id") is not None else "unset",
        },
        "onboarding_done": {
            "value": bool(stored.get("onboarding_done")),
            "source": "db" if stored.get("onboarding_done") is not None else "unset",
        },
        "receiver_public_url": plain("receiver_public_url"),
        "log_store_url": plain("log_store_url"),
        "log_store_push_url": plain("log_store_push_url", LOKI_PUSH_URL),
        "log_store_username": plain("log_store_username", LOKI_USERNAME),
        # The one secret: set-ness and source, never the value. The
        # plaintext exists for exactly one caller, /admin/settings/secrets.
        "log_store_password": {
            "set": stored.get("log_store_password") is not None
                   or bool(LOKI_PASSWORD),
            "source": ("db" if stored.get("log_store_password") is not None
                       else "env" if LOKI_PASSWORD else "unset"),
        },
        "alertmanager_url": plain("alertmanager_url", ALERTMANAGER_URL),
        "grafana_url": plain("grafana_url"),
        "grafana_panels": plain("grafana_panels"),
        "grafana_dashboard_uid": plain("grafana_dashboard_uid"),
        "overview_widgets": plain("overview_widgets"),
        "extension_update_url": plain("extension_update_url"),
        "extension_crx_url": plain("extension_crx_url"),
        "extension_xpi_url": plain("extension_xpi_url"),
        "paste_guard_mode": plain("paste_guard_mode"),
        "firefox_extension_id": plain("firefox_extension_id"),
        # An incoming webhook URL is itself a bearer capability - whoever
        # holds it can post to the channel - so it is masked like the log
        # store password: set-ness and source, never the value.
        "webhook_url": {
            "set": stored.get("webhook_url") is not None,
            "source": "db" if stored.get("webhook_url") is not None else "unset",
        },
        "classification_markings": {
            "value": stored.get("classification_markings"),
            "source": ("db" if stored.get("classification_markings")
                       is not None else "unset"),
        },
    }}


@app.get("/admin/settings/secrets")
def get_settings_secrets(authorization: str = Header(default="")):
    """The stored log-store configuration with the password in plaintext.

    Exists for the portal's server-side Loki reads and nothing else: the
    portal exposes no route that relays it, so the browser never sees the
    value the Settings view masks. An admin who can call this could also
    have SET the password, so it grants nothing they lack - but it is the
    honest statement of the property: integration secrets are recoverable
    by the admin API, unlike fleet credentials, which are hashes.

    Admin-only, and the role gate here is load-bearing: the stored
    credential is typically write-capable (hosted log stores hand out one
    token for both directions), so a viewer who could recover it could
    inject findings past the receiver's validation - a read-only account
    must not be a path to a write credential. The portal reads this with
    its own service credential (RECEIVER_ADMIN_TOKEN) or an admin session;
    a viewer's session is refused, and the portal says what to configure.
    """
    _admin_auth(authorization, write=True)
    s = STATE.get_settings()
    return {"log_store_url": s.get("log_store_url") or "",
            "log_store_push_url": s.get("log_store_push_url") or "",
            "log_store_username": s.get("log_store_username") or "",
            "log_store_password": s.get("log_store_password") or ""}


@app.put("/admin/settings")
def put_settings(req: SettingsUpdate, authorization: str = Header(default="")):
    """Partial upsert: only the keys sent change. An explicit null deletes
    the row, which is how the environment value comes back into effect."""
    _admin_auth(authorization, write=True)
    by = _admin_actor(authorization)

    if "corp_domains" in req.model_fields_set:
        if req.corp_domains is None:
            STATE.set_setting("corp_domains", None, by)
        else:
            # The same normalisation the env path applies, for the same
            # reason: the macOS collector matches with a comma-anchored
            # case pattern, and a stray space or upper-case letter served
            # here would silently turn a work account into a warn.
            domains = _parse_corp_domains(",".join(req.corp_domains))
            for d in domains:
                if len(d) > 253:
                    raise HTTPException(422, "corp domain too long: %s" % d[:60])
            STATE.set_setting("corp_domains", domains, by)

    if "extension_id" in req.model_fields_set:
        eid = (req.extension_id or "").strip()
        if not eid:
            STATE.set_setting("extension_id", None, by)
        else:
            if any(c.isspace() or ord(c) < 32 for c in eid):
                raise HTTPException(422, "extension id cannot contain whitespace")
            STATE.set_setting("extension_id", eid, by)

    if "onboarding_done" in req.model_fields_set:
        STATE.set_setting("onboarding_done", req.onboarding_done, by)

    if "paste_guard_mode" in req.model_fields_set:
        mode = (req.paste_guard_mode or "").strip()
        if not mode:
            STATE.set_setting("paste_guard_mode", None, by)
        elif mode not in _PASTE_GUARD_MODES:
            raise HTTPException(422, "paste_guard_mode must be one of: %s"
                                % ", ".join(_PASTE_GUARD_MODES))
        else:
            STATE.set_setting("paste_guard_mode", mode, by)

    if "firefox_extension_id" in req.model_fields_set:
        fid = (req.firefox_extension_id or "").strip()
        if not fid:
            STATE.set_setting("firefox_extension_id", None, by)
        else:
            if any(c.isspace() or ord(c) < 32 for c in fid):
                raise HTTPException(
                    422, "firefox extension id cannot contain whitespace")
            STATE.set_setting("firefox_extension_id", fid, by)

    if "classification_markings" in req.model_fields_set:
        if req.classification_markings is None:
            STATE.set_setting("classification_markings", None, by)
        else:
            marks = [m.strip() for m in req.classification_markings
                     if m and m.strip()]
            for m in marks:
                if len(m) > 120:
                    raise HTTPException(422, "marking too long: %s" % m[:60])
                if any(ord(c) < 32 for c in m):
                    raise HTTPException(
                        422, "marking cannot contain control characters")
            # An explicit empty list is a real choice (no markings, guard
            # only reports detector hits) and is stored as one; null
            # deletes, falling back to the artifact default set.
            STATE.set_setting("classification_markings", marks, by)

    for key, is_url, _max in _STR_SETTINGS:
        if key not in req.model_fields_set:
            continue
        val = (getattr(req, key) or "").strip()
        if not val:
            # Empty and null both delete: an empty URL is not a URL, and
            # "cleared" falling back to env is the documented shape.
            STATE.set_setting(key, None, by)
        else:
            if is_url and not val.startswith(("http://", "https://")):
                raise HTTPException(
                    422, "%s must be http:// or https://" % key)
            STATE.set_setting(key, val, by)

    return get_settings(authorization)


@app.post("/admin/test/log-store-push")
async def test_log_store_push(authorization: str = Header(default="")):
    """Push one synthetic line with the effective configuration and say
    what happened, hints included.

    The failure this exists for: a token with logs:write missing (or
    read-only), where every real finding is accepted with a 200 to the
    collector and never stored. That is invisible until someone looks at a
    dashboard; here it is one button during setup.
    """
    _admin_auth(authorization, write=True)
    url, username, password = _effective_log_push()
    if not url:
        raise HTTPException(
            400, "no log store is configured: save a base URL in Settings,"
                 " or set LOKI_PUSH_URL on the receiver")
    payload = {"streams": [{
        "stream": {"app": "ai-guard-receiver", "kind": "test"},
        "values": [[str(time.time_ns()),
                    json.dumps({"app": "ai-guard-receiver", "kind": "test",
                                "note": "settings connection test"})]],
    }]}
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.post(url, json=payload,
                                  auth=(username, password) if username else None)
    except httpx.HTTPError as e:
        return {"ok": False, "url": _redact_url(url),
                "detail": "could not reach the log store (%s)" % type(e).__name__}
    if r.status_code >= 300:
        out = {"ok": False, "url": _redact_url(url),
               "detail": "the log store answered HTTP %d" % r.status_code}
        if r.status_code in _LOKI_HINTS:
            out["hint"] = _LOKI_HINTS[r.status_code]
        return out
    return {"ok": True, "url": _redact_url(url)}


# What a portal-recorded decision may look like. Same three states and the
# same review-date discipline the governance file's validator enforces: an
# approval with no review date is the one that outlives the person who made
# it, and the write path must not be the way around that rule.
_VALID_STATUSES = ("approved", "not_approved", "reviewing")
_TOOL_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,100}$")


class DecisionWrite(BaseModel):
    model_config = {"extra": "forbid"}
    tool_id: str = Field(min_length=1, max_length=100)
    status: str = Field(min_length=1, max_length=32)
    owner: str = Field(default="", max_length=200)
    review_due: str = Field(default="", max_length=10)
    reason: str = Field(default="", max_length=1000)


class GovernanceUpdate(BaseModel):
    model_config = {"extra": "forbid"}
    decisions: list[DecisionWrite] = Field(default_factory=list, max_length=200)
    delete: list[str] = Field(default_factory=list, max_length=200)


# ------------------------------------------------- custom registry entries --
# Portal-defined tools: the same shape as a shipped registry entry, held to
# the same rules. The schema is a byte-verified copy of registry/schema.json
# (a test asserts equality - the receiver's image cannot see registry/), and
# the extra rules below are the ones registry/build.py enforces beyond it.

with open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "registry-schema.json")) as _f:
    _REGISTRY_SCHEMA = json.load(_f)
# The per-tool subschema, with the root's $defs carried along: its $ref
# pointers ("#/$defs/relativePath") resolve against the document root, so
# slicing the subschema out alone would break every reference.
_TOOL_VALIDATOR = jsonschema.Draft202012Validator(
    {"$defs": _REGISTRY_SCHEMA.get("$defs", {}),
     **_REGISTRY_SCHEMA["properties"]["tools"]["items"]})

# One entry is a page of identifiers at most; a megabyte of "entry" is not
# a tool, it is a payload.
MAX_REGISTRY_ENTRY_BYTES = 16384


class RegistryEntriesUpdate(BaseModel):
    model_config = {"extra": "forbid"}
    entries: list[dict] = Field(default_factory=list, max_length=100)
    delete: list[str] = Field(default_factory=list, max_length=100)


def _validated_entry(raw: dict, shipped_ids: set, domain_owner: dict) -> dict:
    """One entry, normalized and held to the registry's own rules, or the
    422 that names what is wrong. domain_owner maps each already-claimed
    domain to its tool id and is updated as the batch validates, so two
    entries in one batch cannot claim the same domain either."""
    if not isinstance(raw, dict):
        raise HTTPException(422, "each entry must be an object")
    entry = dict(raw)
    # Forced, not trusted: provenance says where the entry came from, and
    # approval is a governance decision that lives in governance_decisions,
    # never inside a registry entry.
    entry["added_by"] = "portal"
    entry["approved"] = False
    if len(json.dumps(entry)) > MAX_REGISTRY_ENTRY_BYTES:
        raise HTTPException(422, "entry too large: %s"
                            % str(entry.get("id", "?"))[:60])
    errors = sorted(_TOOL_VALIDATOR.iter_errors(entry), key=lambda e: list(e.path))
    if errors:
        e = errors[0]
        where = "/".join(str(p) for p in e.path) or "entry"
        raise HTTPException(422, "%s: %s: %s"
                            % (str(entry.get("id", "?"))[:60], where,
                               e.message[:200]))
    tid = entry["id"]
    if tid in shipped_ids:
        raise HTTPException(
            422, "%s collides with the shipped registry: that tool is "
                 "already defined upstream - use it (and delete any local "
                 "copy) rather than redefining it" % tid)
    for d in entry.get("domains", []):
        if d != d.lower():
            raise HTTPException(422, "%s: domain not lowercase: %s" % (tid, d))
        if d in domain_owner and domain_owner[d] != tid:
            raise HTTPException(
                422, "%s: domain %s is already claimed by %s"
                     % (tid, d, domain_owner[d]))
        domain_owner[d] = tid
    return entry


@app.get("/admin/registry-entries")
def get_registry_entries(authorization: str = Header(default="")):
    """The portal-defined entries, each flagged if a later release started
    shipping the same id - shipped wins at serve time, and a shadowed local
    copy is a row to delete, not silently ignore."""
    _admin_auth(authorization)
    shipped = {t.get("id")
               for t in (_load_registry() or {}).get("tools", [])}
    out = STATE.list_registry_entries()
    for e in out:
        e["shadowed"] = e["tool_id"] in shipped
    return {"entries": out}


@app.put("/admin/registry-entries")
def put_registry_entries(req: RegistryEntriesUpdate,
                         authorization: str = Header(default="")):
    """Upsert and delete portal-defined tools. The whole batch validates
    before anything is written, and the domain map refreshes on the way
    out, so a defined tool normalizes findings immediately and reaches
    collectors on their next check-in."""
    _admin_auth(authorization, write=True)
    by = _admin_actor(authorization)

    shipped = _load_registry() or {"tools": []}
    shipped_ids = {t.get("id") for t in shipped.get("tools", [])}
    deleting = set(req.delete)
    batch_ids = set()
    # Every domain already claimed - by the shipped registry, or by a
    # custom entry that this batch neither replaces nor deletes.
    replaced = {e.get("id") for e in req.entries if isinstance(e, dict)}
    domain_owner: dict[str, str] = {}
    for t in shipped.get("tools", []):
        for d in t.get("domains", []):
            domain_owner[d] = t.get("id")
    for e in STATE.list_registry_entries():
        if e["tool_id"] in deleting or e["tool_id"] in replaced:
            continue
        for d in e["entry"].get("domains", []):
            domain_owner[d] = e["tool_id"]

    validated = []
    for raw in req.entries:
        entry = _validated_entry(raw, shipped_ids, domain_owner)
        if entry["id"] in batch_ids:
            raise HTTPException(422, "duplicate id in batch: %s" % entry["id"])
        batch_ids.add(entry["id"])
        validated.append(entry)
    for tid in deleting:
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,100}", tid):
            raise HTTPException(422, "malformed tool id: %s" % tid[:60])

    for entry in validated:
        STATE.upsert_registry_entry(entry["id"], entry, by)
    for tid in deleting:
        STATE.delete_registry_entry(tid, by)
    _refresh_domain_map()
    return get_registry_entries(authorization)


# ------------------------------------------------------------- candidates --
# Tools the estate observed that nobody has defined. The discovery service
# posts its classified DNS residue here (it used to open a GitLab merge
# request - the queue in the portal replaces the queue in a forge), and the
# human gate is unchanged: a candidate detects nothing until someone turns
# it into a registry entry, or dismisses it. The poster authenticates like
# any reporting source, but the receiver validates every field itself -
# a scanner credential must not become a way to put arbitrary text in
# front of an admin who is one click from adding it to the registry.

_CANDIDATE_KINDS = ("domain", "mcp_server")
# The same shape discovery enforces on classifier output, enforced again
# here because the receiver cannot know its caller ran that code.
_CANDIDATE_TEXT = re.compile(r"^[\w .,'&()/+-]{1,80}$")
_CANDIDATE_DOMAIN = re.compile(r"^[a-z0-9.-]{1,253}$")
_CANDIDATE_CONFIDENCES = ("", "high", "medium", "low")


class CandidateIn(BaseModel):
    model_config = {"extra": "forbid"}
    kind: str = Field(default="domain", max_length=16)
    name: str = Field(min_length=1, max_length=80)
    vendor: str = Field(default="", max_length=80)
    category: str = Field(default="", max_length=40)
    confidence: str = Field(default="", max_length=8)
    domains: list[str] = Field(default_factory=list, max_length=20)
    devices: int = Field(default=0, ge=0, le=1_000_000)
    evidence: str = Field(default="", max_length=500)


class CandidatesPost(BaseModel):
    model_config = {"extra": "forbid"}
    candidates: list[CandidateIn] = Field(default_factory=list, max_length=100)


def _candidate_key(kind: str, name: str) -> str:
    """The stored identity: kind plus the slugified name, computed here and
    never taken from the caller, so one product cannot occupy two rows by
    varying its capitalisation and a key is always safe in a URL path."""
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "unknown"
    return "%s:%s" % (kind, slug[:80])


def _notify_webhook(text: str):
    """Fire-and-forget to the operator's incoming webhook, if one is set.

    A thread rather than the request: ingest must never wait on someone
    else's Slack. Failures are logged and dropped, because a webhook outage
    must not become a reason findings bounce. The payload is the plain
    {"text": ...} shape Slack-compatible incoming webhooks accept.
    """
    if STATE is None:
        return
    url = STATE.get_setting("webhook_url")
    if not url:
        return

    def post():
        try:
            httpx.post(url, json={"text": text}, timeout=5)
        except Exception as e:  # noqa: BLE001 - a log line is the whole story
            log.warning("webhook notification failed: %s", type(e).__name__)

    threading.Thread(target=post, daemon=True).start()


@app.post("/candidates")
def post_candidates(req: CandidatesPost, request: Request,
                    authorization: str = Header(default="")):
    if STATE is None:
        raise HTTPException(404, "Not Found")
    _auth(authorization)
    _touch_device(request)
    device = getattr(request.state, "device", None)
    source = device["serial"] if device else "shared-token"

    accepted = 0
    new_names = []
    for c in req.candidates:
        if c.kind not in _CANDIDATE_KINDS:
            raise HTTPException(422, "unknown candidate kind: %s" % c.kind[:16])
        for field in ("name", "vendor", "category"):
            v = getattr(c, field)
            if v and not _CANDIDATE_TEXT.match(v):
                raise HTTPException(
                    422, "%s is not a plain product name: %s" % (field, v[:60]))
        if c.confidence not in _CANDIDATE_CONFIDENCES:
            raise HTTPException(422, "bad confidence: %s" % c.confidence[:8])
        for d in c.domains:
            if not _CANDIDATE_DOMAIN.match(d):
                raise HTTPException(422, "bad domain: %s" % d[:60])
        fresh = STATE.upsert_candidate(
            _candidate_key(c.kind, c.name), c.kind, c.name, c.vendor,
            c.category, c.confidence, sorted(set(c.domains)), c.devices,
            c.evidence, source)
        if fresh:
            new_names.append(c.name)
        accepted += 1
    if new_names:
        _notify_webhook(
            "ai-guard: %d new AI tool%s in the review queue: %s"
            % (len(new_names), "" if len(new_names) == 1 else "s",
               ", ".join(sorted(new_names)[:10])))
    return {"accepted": accepted}


def _note_mcp_candidates(f: Finding):
    """MCP server names from an endpoint finding, into the queue.

    The collectors are registry-driven and cannot report a tool the
    registry does not name - except here: the MCP scan reports the raw
    server names from a machine's config files as evidence. Those names
    are the one place a genuinely unknown integration already leaves the
    machine, so they feed the candidates queue: a server whose slug is a
    registry id is a known tool doing MCP (not a discovery), anything
    else waits for a human. Names that fail the candidate text rule are
    skipped, not refused - they are evidence on a valid finding, and a
    finding must never bounce because one server has an odd name."""
    if STATE is None or f.surface != "mcp":
        return
    ev = f.evidence or ""
    if "mcpServers:" in ev:
        names = [x.strip() for x in ev.split("mcpServers:", 1)[1].split(",")]
    elif "-mcp:" in f.tool:
        names = [x.strip() for x in f.tool.split("-mcp:", 1)[1].split(",")]
    else:
        return
    for name in names:
        if not name or not _CANDIDATE_TEXT.match(name):
            continue
        key = _candidate_key("mcp_server", name)
        if key.split(":", 1)[1] in _REGISTRY_IDS:
            continue
        if STATE.observe_candidate(
                key, "mcp_server", name,
                "MCP server defined in %s config" % f.tool, "endpoint",
                f.device if f.device != "unknown" else ""):
            _notify_webhook(
                "ai-guard: unknown MCP server %r seen in a %s config - now"
                " in the review queue" % (name, f.tool))


@app.get("/admin/candidates")
def get_candidates(authorization: str = Header(default="")):
    """Every candidate, each flagged resolved once the merged registry
    claims one of its domains - the row's question has been answered by an
    entry, and the portal hides it rather than asking again."""
    _admin_auth(authorization)
    # The merged view when the shipped file is readable; the portal-defined
    # entries alone when it is not. An unreadable shipped registry must not
    # un-resolve every candidate an operator already answered with an entry.
    reg = _merged_registry()
    tools = reg.get("tools", []) if reg else STATE.registry_entry_values()
    claimed = {d for t in tools for d in t.get("domains", [])}
    ids = {t.get("id") for t in tools if t.get("id")}
    out = STATE.list_candidates()
    for c in out:
        # A domain candidate is answered by an entry claiming its domain;
        # an MCP-server candidate by an entry whose id is the server's
        # slug - servers have no domain to claim.
        if c["kind"] == "mcp_server":
            c["resolved"] = c["key"].split(":", 1)[1] in ids
        else:
            c["resolved"] = any(d in claimed for d in c["domains"])
    return {"candidates": out}


@app.post("/admin/candidates/{key}/dismiss")
def dismiss_candidate(key: str, authorization: str = Header(default="")):
    _admin_auth(authorization, write=True)
    if not re.fullmatch(r"[a-z0-9_:-]{1,100}", key):
        raise HTTPException(422, "malformed candidate key")
    if not STATE.dismiss_candidate(key, _admin_actor(authorization)):
        raise HTTPException(404, "no undismissed candidate with that key")
    return {"dismissed": key}


class FindingStatusWrite(BaseModel):
    model_config = {"extra": "forbid"}
    key: str = Field(min_length=1, max_length=500)
    status: str = Field(min_length=1, max_length=16)
    reason: str = Field(default="", max_length=500)


class FindingStatusClear(BaseModel):
    model_config = {"extra": "forbid"}
    key: str = Field(min_length=1, max_length=500)


@app.get("/admin/finding-status")
def get_finding_statuses(authorization: str = Header(default="")):
    """The human answers to derived findings: acknowledged, or accepted with
    a reason. The findings themselves live in the log store and are
    recomputed every load; only the answer is state, and only the answer
    is here. The key is opaque to the receiver on purpose - the portal
    composes it from the finding's identity, and a receiver that parsed it
    would couple itself to a shape it does not own."""
    _admin_auth(authorization)
    return {"statuses": STATE.list_finding_statuses()}


@app.put("/admin/finding-status")
def put_finding_status(req: FindingStatusWrite,
                       authorization: str = Header(default="")):
    _admin_auth(authorization, write=True)
    try:
        STATE.set_finding_status(req.key, req.status, req.reason,
                                 _admin_actor(authorization))
    except ValueError as e:
        raise HTTPException(422, str(e))
    return {"key": req.key, "status": req.status}


@app.post("/admin/finding-status/clear")
def clear_finding_status(req: FindingStatusClear,
                         authorization: str = Header(default="")):
    _admin_auth(authorization, write=True)
    if not STATE.clear_finding_status(req.key, _admin_actor(authorization)):
        raise HTTPException(404, "no status recorded for that key")
    return {"cleared": req.key}


@app.get("/admin/events")
def get_events(limit: int = 200, authorization: str = Header(default="")):
    """The audit trail. Every admin write already records who did what and
    when; this read is what turns that from a diary into accountability."""
    _admin_auth(authorization)
    return {"events": STATE.list_events(min(max(int(limit), 1), 1000))}


@app.get("/admin/governance")
def get_governance(authorization: str = Header(default="")):
    _admin_auth(authorization)
    return {"decisions": STATE.list_decisions()}


@app.put("/admin/governance")
def put_governance(req: GovernanceUpdate, authorization: str = Header(default="")):
    """Upsert and delete decisions, validated to the same rules as the file.

    Validation happens for the whole batch before anything is written, so a
    422 means nothing changed rather than half a batch applied.
    """
    _admin_auth(authorization, write=True)
    by = _admin_actor(authorization)

    for d in req.decisions:
        if not _TOOL_ID_RE.match(d.tool_id):
            raise HTTPException(422, "malformed tool id: %s" % d.tool_id[:60])
        if d.status not in _VALID_STATUSES:
            raise HTTPException(
                422, "status must be one of " + ", ".join(_VALID_STATUSES))
        if d.review_due:
            try:
                date.fromisoformat(d.review_due)
            except ValueError:
                raise HTTPException(
                    422, "review_due must be an ISO date (YYYY-MM-DD)")
        if d.status == "approved" and not d.review_due:
            raise HTTPException(
                422, "an approval needs a review_due date: an approval with"
                     " no expiry is the one that outlives the person who"
                     " made it")
    for tid in req.delete:
        if not _TOOL_ID_RE.match(tid):
            raise HTTPException(422, "malformed tool id: %s" % tid[:60])

    for d in req.decisions:
        STATE.upsert_decision(d.tool_id, d.status, d.owner.strip(),
                              d.review_due, d.reason.strip(), by)
    for tid in req.delete:
        STATE.delete_decision(tid, by)
    return {"decisions": STATE.list_decisions()}


# ------------------------------------------------------------- budget --
# What the organisation pays for, per tool: subscription, seat tiers,
# members, and (where a vendor has an admin API) the connection that syncs
# them. Storage in state.py, vendor calls in budget.py; these routes
# validate shape and hold the role gate. The vendor key is written here
# and never read back out by any route - sync spends it server-side.

_TIER_NAME_RE = re.compile(r"^[^\x00-\x1f]{1,64}$")
# Not RFC 5322 - a member row needs an @ with something either side, and
# a tighter pattern only manufactures reasons to refuse a real address.
_EMAIL_RE = re.compile(r"^[^@\s]{1,180}@[^@\s]{1,253}$")


class SeatTierWrite(BaseModel):
    model_config = {"extra": "forbid"}
    name: str = Field(min_length=1, max_length=64)
    seats: int = Field(default=0, ge=0, le=100000)
    unit_price_monthly: float = Field(default=0, ge=0, le=1000000)


class BudgetSubscriptionWrite(BaseModel):
    model_config = {"extra": "forbid"}
    tool_id: str = Field(min_length=1, max_length=100)
    vendor: str = Field(default="", max_length=200)
    plan: str = Field(default="", max_length=100)
    currency: str = Field(default="", max_length=8)
    renewal_date: str = Field(default="", max_length=10)
    owner: str = Field(default="", max_length=200)
    notes: str = Field(default="", max_length=1000)
    seat_tiers: list[SeatTierWrite] = Field(default_factory=list,
                                            max_length=10)


class BudgetMemberWrite(BaseModel):
    model_config = {"extra": "forbid"}
    email: str = Field(min_length=3, max_length=254)
    name: str = Field(default="", max_length=200)
    role: str = Field(default="", max_length=64)
    seat_tier: str = Field(default="", max_length=64)


class BudgetMembersWrite(BaseModel):
    model_config = {"extra": "forbid"}
    tool_id: str = Field(min_length=1, max_length=100)
    # csv and manual only: "api" rows are written by sync alone, and a
    # request that could claim to be a sync would let a CSV wear an
    # API-synced provenance label in the portal.
    source: str = Field(min_length=1, max_length=16)
    members: list[BudgetMemberWrite] = Field(default_factory=list,
                                             max_length=_budget.MAX_MEMBERS)


class BudgetConnectionWrite(BaseModel):
    model_config = {"extra": "forbid"}
    tool_id: str = Field(min_length=1, max_length=100)
    provider: str = Field(min_length=1, max_length=32)
    api_key: str = Field(min_length=8, max_length=512)


class BudgetToolRef(BaseModel):
    model_config = {"extra": "forbid"}
    tool_id: str = Field(min_length=1, max_length=100)


@app.get("/admin/budget")
def get_budget(authorization: str = Header(default="")):
    """Subscriptions with members, connection metadata (never keys), and
    the provider catalogue the wizard offers."""
    _admin_auth(authorization)
    out = STATE.list_budget()
    out["providers"] = _budget.PROVIDERS
    return out


@app.put("/admin/budget/subscription")
def put_budget_subscription(req: BudgetSubscriptionWrite,
                            authorization: str = Header(default="")):
    _admin_auth(authorization, write=True)
    if not _TOOL_ID_RE.match(req.tool_id):
        raise HTTPException(422, "malformed tool id: %s" % req.tool_id[:60])
    if req.renewal_date:
        try:
            date.fromisoformat(req.renewal_date)
        except ValueError:
            raise HTTPException(
                422, "renewal_date must be an ISO date (YYYY-MM-DD)")
    names = [t.name.strip() for t in req.seat_tiers]
    for n in names:
        if not _TIER_NAME_RE.match(n):
            raise HTTPException(422, "malformed seat tier name")
    if len(set(n.lower() for n in names)) != len(names):
        raise HTTPException(422, "seat tier names must be unique")
    STATE.upsert_budget_subscription(
        req.tool_id,
        {"vendor": req.vendor.strip(), "plan": req.plan.strip(),
         "currency": req.currency.strip(),
         "renewal_date": req.renewal_date, "owner": req.owner.strip(),
         "notes": req.notes.strip(),
         "seat_tiers": [{"name": n, "seats": t.seats,
                         "unit_price_monthly": t.unit_price_monthly}
                        for n, t in zip(names, req.seat_tiers)]},
        _admin_actor(authorization))
    return get_budget(authorization)


@app.post("/admin/budget/subscription/delete")
def delete_budget_subscription(req: BudgetToolRef,
                               authorization: str = Header(default="")):
    _admin_auth(authorization, write=True)
    if not STATE.delete_budget_subscription(req.tool_id,
                                            _admin_actor(authorization)):
        raise HTTPException(404, "no subscription for that tool")
    return get_budget(authorization)


@app.put("/admin/budget/members")
def put_budget_members(req: BudgetMembersWrite,
                       authorization: str = Header(default="")):
    """Replace the member rows the named source owns. Validated as a
    batch before anything is written: a 422 means nothing changed."""
    _admin_auth(authorization, write=True)
    if not _TOOL_ID_RE.match(req.tool_id):
        raise HTTPException(422, "malformed tool id: %s" % req.tool_id[:60])
    if req.source not in ("csv", "manual"):
        raise HTTPException(422, "source must be csv or manual")
    seen = set()
    members = []
    for m in req.members:
        email = m.email.strip().lower()
        if not _EMAIL_RE.match(email):
            raise HTTPException(422, "not an email address: %s" % email[:60])
        if email in seen:
            raise HTTPException(422, "duplicate email: %s" % email[:60])
        seen.add(email)
        members.append({"email": email, "name": m.name.strip(),
                        "role": m.role.strip(),
                        "seat_tier": m.seat_tier.strip()})
    count = STATE.replace_budget_members(req.tool_id, members, req.source,
                                         _admin_actor(authorization))
    return {"ok": True, "count": count}


@app.put("/admin/budget/connection")
def put_budget_connection(req: BudgetConnectionWrite,
                          authorization: str = Header(default="")):
    _admin_auth(authorization, write=True)
    if not _TOOL_ID_RE.match(req.tool_id):
        raise HTTPException(422, "malformed tool id: %s" % req.tool_id[:60])
    if req.provider not in _budget.SYNCERS:
        raise HTTPException(
            422, "provider must be one of: " + ", ".join(_budget.SYNCERS))
    key = req.api_key.strip()
    if any(ord(c) < 33 for c in key):
        raise HTTPException(422, "the API key contains whitespace or "
                                 "control characters - check the paste")
    STATE.set_budget_connection(req.tool_id, req.provider, key,
                                _admin_actor(authorization))
    return {"ok": True}


@app.post("/admin/budget/connection/delete")
def delete_budget_connection(req: BudgetToolRef,
                             authorization: str = Header(default="")):
    _admin_auth(authorization, write=True)
    if not STATE.delete_budget_connection(req.tool_id,
                                          _admin_actor(authorization)):
        raise HTTPException(404, "no connection for that tool")
    return {"ok": True}


@app.post("/admin/budget/sync")
async def budget_sync(req: BudgetToolRef,
                      authorization: str = Header(default="")):
    """One user sync, now, with the stored connection. The failure body
    is the operator's answer (ok: false with the reason), not a 5xx: the
    vendor refusing a key is an expected state the page must render, and
    the result is recorded either way so the card can show it later."""
    _admin_auth(authorization, write=True)
    by = _admin_actor(authorization)
    conn = STATE.sync_connection_key(req.tool_id)
    if conn is None:
        raise HTTPException(404, "no connection for that tool: save one "
                                 "first")
    provider, key = conn
    try:
        members = await _budget.SYNCERS[provider](key)
    except _budget.SyncError as e:
        # e.detail, not str(e): the field is assigned only from budget.py's
        # own message templates, so the response provably cannot carry a
        # stack trace however the sync failed.
        STATE.record_budget_sync(req.tool_id, False, e.detail, 0, by)
        return {"ok": False, "detail": e.detail}
    STATE.replace_budget_members(req.tool_id, members, "api", by)
    STATE.record_budget_sync(req.tool_id, True, "", len(members), by)
    return {"ok": True, "count": len(members)}


@app.post("/admin/password")
def change_password(req: PasswordChangeRequest,
                    authorization: str = Header(default="")):
    """Change the admin password, proving the current one.

    With the API credential the current password is not required: that is
    the break-glass path, and whoever can set the receiver's environment
    already owns the box. Every other session dies with the old password.
    """
    _admin_auth(authorization)
    token = _bearer(authorization)
    is_session = token.startswith(_state.SESSION_PREFIX)
    # A session changes its own account's password, whatever its role: a
    # viewer owning their credential is not a write to the platform. The
    # API credential path targets the oldest admin - break-glass.
    user = STATE.session_user(token) if is_session else None
    try:
        STATE.change_password(
            req.new,
            current=req.current if is_session else None,
            keep_session=token if is_session else None,
            user_id=user["user_id"] if user else None,
        )
    except _state.AuthError as e:
        raise HTTPException(e.status, e.detail)
    return {"ok": True}


# The Loki stream labels derived from each finding. Anything not in this
# set stays inside the JSON line body, parsed at query time. Adding a
# field here mints a new stream per unique value, so only bounded sets
# belong (surface, severity, os). Unbounded fields (tool, device,
# device_name, user, account_domain, risk_tier) must stay out.
LOKI_FINDING_LABELS = {"surface", "severity", "os"}


def _effective_log_push() -> tuple[str, str, str]:
    """(push URL, username, password) the receiver should push with.

    The portal-saved configuration wins: an explicit push override, else
    the push endpoint derived from the saved base URL - deriving is the
    point, it makes the base-vs-push mixup impossible to make in the
    portal. Whichever source supplies the URL supplies the credentials
    too: pairing a portal-saved URL with environment credentials would
    send the old store's password to the new store.
    """
    if STATE is not None:
        s = STATE.get_settings()
        push = s.get("log_store_push_url") or ""
        base = s.get("log_store_url") or ""
        if not push and base:
            push = base.rstrip("/") + "/loki/api/v1/push"
        if push:
            return (push, s.get("log_store_username") or "",
                    s.get("log_store_password") or "")
    return (LOKI_PUSH_URL, LOKI_USERNAME, LOKI_PASSWORD)


def _effective_alertmanager() -> str:
    if STATE is not None:
        v = STATE.get_setting("alertmanager_url")
        if v:
            return v
    return ALERTMANAGER_URL


# The two status codes behind almost every log-store misconfiguration,
# shared by the per-finding push and the settings test button so both name
# the same likely cause.
_LOKI_HINTS = {
    404: ("the push URL is probably the base URL rather than the "
          "push endpoint, which is /loki/api/v1/push"),
    401: "a username and password are needed, or are wrong",
    403: "the username and password are wrong, or lack write access",
}


async def _push_loki(f: Finding, line: str, url: str, username: str,
                     password: str) -> bool:
    """Push to Loki and say whether it worked. Bounded labels only (no
    tool/device: unbounded values stay inside the JSON line, parsed at
    query time). The caller turns False into a 503, because collectors
    treat only a 200 as delivered - answering 200 on a failed push is what
    made them discard findings the store never received."""
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
    auth = (username, password) if username else None
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.post(url, json=payload, auth=auth)
            r.raise_for_status()
    except httpx.HTTPStatusError as e:
        # Logged at error, not info. This was info, and a wrong push URL
        # therefore produced a 404 per finding that nobody read while the
        # receiver kept answering 200 to every collector. The finding is not
        # lost - it is on stdout - but it never reaches the log store, and
        # from the outside that is indistinguishable from a quiet estate.
        code = e.response.status_code
        LOKI_PUSH_FAILURES.labels(reason=f"http_{code}").inc()
        # A status code alone sends people to the wrong place. _LOKI_HINTS
        # names the likely cause and turns a wrong value into a one-line fix.
        entry = {
            "app": "ai-guard-receiver", "kind": "error",
            "error": f"loki push rejected with HTTP {code}",
            "url": _redact_url(url),
        }
        if code in _LOKI_HINTS:
            entry["hint"] = _LOKI_HINTS[code]
        log.error(json.dumps(entry))
        return False
    except httpx.HTTPError as e:
        LOKI_PUSH_FAILURES.labels(reason=type(e).__name__).inc()
        log.error(json.dumps({
            "app": "ai-guard-receiver", "kind": "error",
            # The exception type, not str(e). httpx puts the request URL in
            # the message, which would carry userinfo straight past the
            # redaction above.
            "error": "loki push failed: %s" % type(e).__name__,
            "url": _redact_url(url),
        }))
        return False
    else:
        LOKI_PUSH_OK.inc()
        LOKI_PUSH_LAST_SUCCESS.set(time.time())
        return True


async def _fire_alert(f: Finding, alertmanager_url: str):
    if not alertmanager_url:
        # Alerting is opt-in: nothing configured means findings are logged
        # and dashboarded but nothing pages. Deliberate for adopters
        # without Alertmanager; set it in the portal (or the env var).
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
        r = await client.post(f"{alertmanager_url}/api/v2/alerts", json=alert)
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

    # MCP server names ride in as evidence; unknown ones join the
    # candidates queue (managed mode only - the function gates itself).
    _note_mcp_candidates(f)

    # Loki: every finding, warn and info alike. Stdout always; direct push
    # when a push target is configured - the portal-saved log store when
    # one exists, LOKI_PUSH_URL otherwise. Resolved per finding, so a
    # store configured in the wizard takes effect with no restart.
    #
    # A failed push is a 503, not a 200. Collectors advance their delivered
    # state only on 200, so acknowledging a finding the store rejected made
    # them discard it - a broken token produced a clean-looking dashboard
    # because telemetry silently stopped reaching storage, which is the
    # exact failure this platform exists to catch. The retry costs a
    # duplicate stdout line; duplicate evidence beats silently missing
    # evidence. Metrics, gauges and alerting run only on the stored path,
    # so a retried finding counts once, when it is actually stored.
    line = json.dumps({"app": "ai-guard-receiver", "kind": "finding", **f.model_dump()})
    log.info(line)
    push_url, push_user, push_pass = _effective_log_push()
    if push_url:
        if not await _push_loki(f, line, push_url, push_user, push_pass):
            raise HTTPException(
                503, "finding accepted locally but log-store delivery "
                     "failed; retry")

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
        am_url = _effective_alertmanager()
        try:
            if not suppress and am_url:
                await _fire_alert(f, am_url)
                alert_fired = True
        except httpx.HTTPError as e:
            log.error(json.dumps({
                "app": "ai-guard-receiver", "kind": "error",
                "error": "alertmanager: %s" % type(e).__name__,
                "url": _redact_url(am_url),
            }))

    return {"ok": True, "severity": f.severity, "alerted": alert_fired}