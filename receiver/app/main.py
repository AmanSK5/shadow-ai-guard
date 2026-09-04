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

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sys
import smtplib
import ssl
import threading
from email.message import EmailMessage
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
# Whether a finding shows a model ran ("active") or only that the product
# is installed ("ambient"). Bounded like every other label. Findings from
# before 0.21 carry neither, and "" is read as active downstream - the
# meaning they were reported with.
VALID_SIGNALS = {"active", "ambient"}
# Whether a person was at the keyboard. "autonomous" means something started
# this without being asked - a timer, a scheduler, a pipeline step - and
# nobody was present while it ran. Absent reads as "unknown", never as
# autonomous: claiming a tool ran unattended when nothing established that is
# the accusation this must not make by default.
VALID_MODES = {"interactive", "autonomous"}
# Who the credential belongs to, which is a different question from which
# account domain was seen. Three states a collector can genuinely tell apart:
#   person   an account with a human behind it
#   machine  a credential that authenticates, with no human behind it - an
#            API key in a unit file, a service token. This is the one that
#            survives offboarding, because revoking somebody's sign-on does
#            not touch it.
#   none     nothing authenticated at all; installed and never signed in
# Empty means the sender did not say. Before this existed, "machine" and
# "none" both arrived as a blank account domain and were indistinguishable,
# which is why the blank alone could never carry this meaning.
VALID_IDENTITIES = {"person", "machine", "none"}
# H:MM-H:MM, hours 0-23 and minutes optional. Only the shape: whether the
# range makes sense is the reader's business, and a value that saves and
# then shades nothing is worse than one refused at the point of typing.
_WORKING_HOURS_RE = re.compile(
    r"^([01]?\d|2[0-3])(:[0-5]\d)?-([01]?\d|2[0-3])(:[0-5]\d)?$")
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
    # active | ambient. Only an `ide` registry entry (a VS Code fork, where
    # the editor is useful without ever calling a model) can report ambient;
    # every other tool's presence is use. Empty from senders that pre-date
    # the field, which reads as active - what they always meant.
    signal: str = Field(default="", max_length=16)
    # interactive | autonomous. See VALID_MODES.
    mode: str = Field(default="", max_length=16)
    # person | machine | none. See VALID_IDENTITIES.
    identity: str = Field(default="", max_length=16)
    # What starts it, in the words of whatever schedules it: "systemd timer",
    # "launchd, at login", "Scheduled Task, hourly". Free text because every
    # scheduler describes itself differently and flattening them into an
    # enum would lose the part an operator needs to go and find the thing.
    # Bounded like every other field that arrives from outside.
    trigger: str = Field(default="", max_length=200)
    # The cadence, in the words of whatever schedules it, prefixed with the
    # dialect so one field carries all of them and the reader knows how to
    # read it: "cron:0 2 * * *", "oncalendar:*:0/15", "interval:21600",
    # "atlogin", "event".
    #
    # Raw rather than normalised, because normalising means three
    # implementations - a bash collector, another bash collector and a
    # PowerShell one - and three chances to disagree. One parser in the
    # portal is one place to be wrong, and the untranslated spec stays
    # readable by whoever has to go and find the thing.
    schedule: str = Field(default="", max_length=120)
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

# The doors into admin auth. Exempt from the admin gate - they are how a
# session comes to exist - but not from the body-size gate, and they answer
# 404 like everything managed when managed mode is off.
#
# The two federated ones are open for the same reason the password one is:
# nobody has a session yet. What protects the callback is the state it must
# quote, minted by /sso/start minutes earlier, single-use, and paired with
# a PKCE verifier the browser never saw. /sso/start itself answers 404
# until federated sign-in is fully configured, so an estate that has not
# set it up does not advertise the endpoint.
_ADMIN_OPEN = ("/admin/setup", "/admin/login",
               "/admin/sso/start", "/admin/sso/callback")


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
# Tool ids the registry marks `form: ide` - an editor that bundles AI, where
# finding the app installed proves an editor is installed and nothing more.
# The scanner classifies its own findings (it sees the DNS hostname next to
# the registry entry), but the three endpoint collectors report a plain
# `surface: desktop` and know nothing about forms. Rather than teach a bash
# script, a PowerShell script and a Linux script the same rule - and then
# need all three upgraded before it takes effect - the receiver fills it in
# on the way past, the same place and for the same reason it already
# rewrites a hostname to a tool id.
def _build_ide_tools(reg: dict | None) -> set[str]:
    if not reg:
        return set()
    return {t.get("id") for t in reg.get("tools", [])
            if t.get("id") and t.get("form") == "ide"}


# Surfaces that only ever prove the product is on the machine. `ide` is not
# here: that surface is an AI EXTENSION someone installed into an editor,
# which is a deliberate choice to add AI rather than an editor existing.
_PRESENCE_SURFACES = {"desktop"}


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
    global _DOMAIN_TO_TOOL, _REGISTRY_IDS, _IDE_TOOLS
    reg = _merged_registry()
    _DOMAIN_TO_TOOL = _build_domain_map(reg)
    _IDE_TOOLS = _build_ide_tools(reg)
    _REGISTRY_IDS = {t.get("id") for t in (reg or {}).get("tools", [])
                     if t.get("id")}
    _REBUILD_KNOWN_PROCESSES(reg)


_DOMAIN_TO_TOOL: dict[str, str] = {}
_REGISTRY_IDS: set[str] = set()
_IDE_TOOLS: set[str] = set()
# Every process name the registry can account for: the binaries its CLIs run
# as, the apps and Windows executables its desktop tools ship under, and the
# browsers, apps and daemons on allowed_processes. Anything else that reaches
# a model is a question for a human, which is what the candidates queue is.
_KNOWN_PROCESSES: set[str] = set()

# The same three sets the portal reads findings through. They live here too
# because the receiver decides what becomes a candidate at ingest, and the
# two services share no library - a parity test asserts they do not drift.
_BROWSERS = {
    "chrome", "google chrome", "chromium", "firefox", "safari",
    "com.apple.safari", "msedge", "microsoft edge", "brave", "brave browser",
    "opera", "vivaldi", "arc",
}
_UNATTRIBUTABLE = {
    "systemd-resolved", "systemd-executor", "systemd", "resolvconf",
    "mdnsresponder", "discoveryd", "dnsmasq", "unbound", "nscd",
    "svchost", "dnscache", "networkservice",
    "backgroundtaskhost", "taskhostw", "taskhost", "taskeng", "rundll32",
    "dllhost", "wermgr",
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
_VIA_RE = re.compile(r"\(via ([^)]{1,80})\)")
def _strip_helper_suffix(n):
    """"google chrome helper (renderer)" -> "google chrome".

    String work rather than a pattern. The regex this replaces was
    `\\s+helper(\\s*\\(.*)?$`, whose two adjacent whitespace quantifiers
    backtrack polynomially on a name of many spaces - and the name comes off
    a posted finding, so it is not input this gets to assume anything about.
    """
    i = n.rfind(" helper")
    if i == -1:
        return n
    tail = n[i + len(" helper"):].lstrip(" \t")
    if tail and not tail.startswith("("):
        return n
    return n[:i].rstrip(" \t")


def _norm_process(name: str) -> str:
    """Lowercased, path and .exe stripped, a macOS "X Helper (Role)" cut to X."""
    n = (name or "").strip().lower()
    if not n:
        return ""
    n = n.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    if n.endswith(".exe"):
        n = n[:-4]
    return _strip_helper_suffix(n).strip()


def _process_stems(name: str) -> list[str]:
    """The name and its shorter dotted prefixes, longest first."""
    n = _norm_process(name)
    if not n:
        return []
    parts = n.split(".")
    return [".".join(parts[:i]) for i in range(len(parts), 0, -1)]


def _REBUILD_KNOWN_PROCESSES(reg):
    global _KNOWN_PROCESSES
    out = set()
    for t in (reg or {}).get("tools", []) or []:
        for b in ((t.get("cli") or {}).get("binaries") or []):
            out.add(_norm_process(str(b)))
        for a in (t.get("app_names") or []):
            a = str(a)
            out.add(_norm_process(a[:-4] if a.lower().endswith(".app") else a))
        for e in (t.get("exe_names") or []):
            out.add(_norm_process(str(e)))
    for pn in (reg or {}).get("allowed_processes", []) or []:
        out.add(_norm_process(str(pn)))
    _KNOWN_PROCESSES = out - {""}
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

    Served so a new AI tool is a registry entry - defined in the portal, or
    by merge request - rather than an edit
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


def _admin_auth(authorization: str, write: bool = False,
                owner: bool = False):
    # Defence in depth for /admin/*, like _auth for ingest. 404 when managed
    # mode is off: routes that do not exist should not confirm they exist.
    # write=True is the role gate: a viewer account reads everything and
    # changes nothing, and the refusal names the reason rather than lying
    # with a generic 401 to someone who IS authenticated.
    #
    # owner=True is the tier above it, for the settings that decide who may
    # sign in at all. Returns the caller's role, because the account routes
    # need it: the rules there are relative to who is asking, not absolute.
    # The API credential returns "admin" from _admin_role and is treated as
    # unrestricted by the state layer, which is what break-glass means.
    if STATE is None:
        raise HTTPException(404, "Not Found")
    role = _admin_role(authorization)
    if role is None:
        raise HTTPException(401, "bad token")
    if owner and role not in ("owner",):
        raise HTTPException(403, "only an owner account can change this")
    if write and role not in ("owner", "admin"):
        raise HTTPException(403, "this account is read-only: an admin "
                                 "account has to make this change")
    return role


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


@app.post("/admin/devices/{did}/allow-reenrollment")
def allow_reenrollment(did: str, authorization: str = Header(default="")):
    """Lift the tombstone on a revoked device's serial, for one enrollment.

    A revoked serial is refused at /enroll, because the enrollment token that
    created it is usually still in the MDM artifact and would otherwise hand
    the credential back. The reimage and the replacement machine are the real
    reasons a serial returns, and this is the deliberate step that says so.
    """
    _admin_auth(authorization, write=True)
    if not STATE.allow_reenrollment(did):
        raise HTTPException(
            404, "no such revoked device, or re-enrollment is already allowed")
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
    """What the sign-in screen needs before anybody has authenticated.

    Unauthenticated by design, and deliberately two bits that say nothing
    about the estate. Whether the create-account door is open, so the
    portal can choose between the sign-in form and the create-account form
    honestly. And whether federated sign-in is on, because somebody who
    was onboarded through the identity provider has no password here to
    type, and a sign-in screen that only offers the one credential they do
    not have is a locked door.
    """
    if STATE is None:
        raise HTTPException(404, "Not Found")
    return {"needed": not STATE.has_admin(),
            # The estate's name, for the screen that has nobody to greet
            # yet. A name, nothing else: see org_name in _STR_SETTINGS.
            "org_name": STATE.get_setting("org_name") or "",
            "sso_enabled": _sso_conf()["enabled"],
            # Enforced means the password form has nothing to offer anybody
            # but one account, and a screen that still leads with it is
            # inviting every other person to fail.
            "sso_enforced": _sso_conf()["enabled"] and STATE.sso_enforced()}


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
        # 403 is the enforcement refusal, and the password was right. It
        # must not touch the throttle: the counters are global as well as
        # per-user, so counting these would let one person's habit of
        # typing their password lock every account out of signing in.
        if e.status == 403:
            raise HTTPException(e.status, e.detail)
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
    # Optional, and optional it stays: local accounts have never needed an
    # address, and a required field here would block creating the very
    # break-glass account that exists for when the rest is broken.
    email: str = Field(default="", max_length=254)


class UserPasswordReset(BaseModel):
    model_config = {"extra": "forbid"}
    new: str = Field(min_length=12, max_length=256)


class UserEmailWrite(BaseModel):
    model_config = {"extra": "forbid"}
    email: str = Field(default="", max_length=254)


class UserRoleWrite(BaseModel):
    model_config = {"extra": "forbid"}
    role: str = Field(min_length=1, max_length=16)


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
        out = STATE.create_user(req.username, req.password, req.role,
                                _admin_actor(authorization), req.email,
                                _actor_role(authorization))
    except _state.AuthError as e:
        raise HTTPException(e.status, e.detail)
    # The invite goes after the account exists, never as a condition of it.
    # Its outcome rides back on the response so the page can say what
    # actually happened rather than implying a mail nobody sent.
    out["invited"] = False
    out["invite_error"] = ""
    if out.get("email") and _smtp_conf()["ready"]:
        why = _send_invite(out)
        if why:
            out["invite_error"] = why
        else:
            STATE.mark_invited(out["id"])
            out["invited"] = True
    elif out.get("email"):
        out["invite_error"] = "no mail server is configured"
    return out


class InviteRequest(BaseModel):
    model_config = {"extra": "forbid"}
    # Empty means everybody who has never been told. Naming one account is
    # the resend case.
    user_id: str = Field(default="", max_length=64)


@app.post("/admin/users/invite")
def send_invites(req: InviteRequest, authorization: str = Header(default="")):
    """Tell people their account exists. One, or everybody who was missed.

    Synchronous, unlike the invite that rides on account creation: somebody
    pressed a button that does exactly this and is owed the outcome of it.
    """
    _admin_auth(authorization, write=True)
    if not _smtp_conf()["ready"]:
        raise HTTPException(400, "no mail server is configured")
    if req.user_id:
        user = STATE.user_by_id(req.user_id)
        if user is None:
            raise HTTPException(404, "no such account")
        if not user.get("email"):
            raise HTTPException(422, "that account has no email address")
        targets = [user]
    else:
        targets = STATE.uninvited()
    sent, failed = 0, []
    for u in targets:
        why = _send_invite(u)
        if why:
            failed.append({"username": u["username"], "detail": why})
        else:
            STATE.mark_invited(u["id"])
            sent += 1
    return {"sent": sent, "failed": failed, "considered": len(targets)}


class MailTest(BaseModel):
    model_config = {"extra": "forbid"}
    to: str = Field(min_length=3, max_length=320)


@app.post("/admin/test/mail")
def test_mail(req: MailTest, authorization: str = Header(default="")):
    """Prove the relay works before anybody depends on it.

    The same lesson the sign-on wizard taught: configuration that looks
    right and silently does not send is how an invite vanishes and the
    person who never got it is blamed for not checking their inbox.
    """
    _admin_auth(authorization, write=True)
    conf = _smtp_conf()
    if not conf["ready"]:
        raise HTTPException(400, "a server and a from address are needed first")
    why = _smtp_send(
        req.to.strip(), "Shadow AI Guard: test message",
        "This is a test from the Shadow AI Guard portal.\n\n"
        "If you are reading it, invites will reach people.\n")
    if why:
        return {"ok": False, "detail": why}
    return {"ok": True, "detail": "sent to %s" % req.to.strip()}


@app.post("/admin/users/{uid}/delete")
def delete_user(uid: str, authorization: str = Header(default="")):
    _admin_auth(authorization, write=True)
    if not re.fullmatch(r"[0-9a-f]{16}", uid):
        raise HTTPException(422, "malformed user id")
    try:
        if not STATE.delete_user(uid, _admin_actor(authorization),
                                 _actor_role(authorization)):
            raise HTTPException(404, "no account with that id")
    except _state.AuthError as e:
        raise HTTPException(e.status, e.detail)
    return {"deleted": uid}


@app.post("/admin/users/{uid}/role")
def set_user_role(uid: str, req: UserRoleWrite,
                  authorization: str = Header(default="")):
    """Move an account between admin and viewer.

    Takes effect on that account's next request, not at its next sign-in:
    the role is read off the account row per request, so a demotion is
    immediate and a promotion costs a reload. The last admin cannot be
    demoted, for the same reason it cannot be deleted.
    """
    _admin_auth(authorization, write=True)
    if not re.fullmatch(r"[0-9a-f]{16}", uid):
        raise HTTPException(422, "malformed user id")
    try:
        if not STATE.set_user_role(uid, req.role,
                                   _admin_actor(authorization),
                                   _actor_role(authorization)):
            raise HTTPException(404, "no account with that id")
    except _state.AuthError as e:
        raise HTTPException(e.status, e.detail)
    return {"user": uid, "role": req.role}


@app.post("/admin/users/{uid}/email")
def set_user_email(uid: str, req: UserEmailWrite,
                   authorization: str = Header(default="")):
    """Record which address an identity provider would map onto this
    account, or clear it with an empty string. An admin action, not a
    self-service one: an account that could rewrite its own mapping could
    point somebody else's federated sign-in at itself."""
    _admin_auth(authorization, write=True)
    if not re.fullmatch(r"[0-9a-f]{16}", uid):
        raise HTTPException(422, "malformed user id")
    try:
        if not STATE.set_user_email(uid, req.email,
                                    _admin_actor(authorization),
                                    _actor_role(authorization)):
            raise HTTPException(404, "no account with that id")
    except _state.AuthError as e:
        raise HTTPException(e.status, e.detail)
    return {"user": uid, "email": _state.normalize_email(req.email)}


@app.post("/admin/users/{uid}/password")
def reset_user_password(uid: str, req: UserPasswordReset,
                        authorization: str = Header(default="")):
    """An admin setting someone else's password - the forgotten-password
    path. Changing your own goes through /admin/password, which proves the
    current one."""
    _admin_auth(authorization, write=True)
    if not re.fullmatch(r"[0-9a-f]{16}", uid):
        raise HTTPException(422, "malformed user id")
    try:
        if not STATE.reset_user_password(uid, req.new,
                                         _admin_actor(authorization),
                                         _actor_role(authorization)):
            raise HTTPException(404, "no account with that id")
    except _state.AuthError as e:
        raise HTTPException(e.status, e.detail)
    return {"reset": uid}


# ---------------------------------------------------------- preferences --
# An account's own view of the portal. Read and written by whoever is
# signed in, for themselves only - there is no route to another account's
# preferences, because no feature needs one and a layout is nobody else's
# business. Viewers write these freely: choosing a chart type changes what
# one person sees, never what the page reports.


class PreferencesWrite(BaseModel):
    model_config = {"extra": "forbid"}
    # A merge, so one page saves its own key without carrying the others.
    # A null value deletes the key rather than storing a copy of today's
    # default, which would freeze it against every later change.
    preferences: dict[str, str | None] = Field(default_factory=dict)


@app.get("/admin/preferences")
def get_preferences(authorization: str = Header(default="")):
    _admin_auth(authorization)
    return {"preferences": STATE.get_preferences(
        _session_account(authorization))}


@app.put("/admin/preferences")
def put_preferences(req: PreferencesWrite,
                    authorization: str = Header(default="")):
    # No write=True: this is the one authenticated write a viewer owns.
    _admin_auth(authorization)
    try:
        return {"preferences": STATE.set_preferences(
            _session_account(authorization), req.preferences)}
    except _state.AuthError as e:
        raise HTTPException(e.status, e.detail)



# ----------------------------------------------------- federated sign-in --
# OpenID Connect against Microsoft Entra, authorization code flow with
# PKCE. The browser never carries a token: it carries a code, which this
# receiver exchanges itself over TLS.
#
# ON NOT VERIFYING THE ID TOKEN SIGNATURE. The token is fetched by this
# process, over verified TLS, directly from the token endpoint named by
# the tenant's own discovery document. OpenID Connect Core 3.1.3.7 permits
# exactly this: "If the ID Token is received via direct communication
# between the Client and the Token Endpoint... the TLS server validation
# MAY be used to validate the issuer in place of checking the token
# signature." Everything a signature would not have told us is still
# checked below - issuer, audience, expiry, nonce and tenant.
#
# The alternative is a JWT library and the native cryptography stack it
# pulls in, on an image this project keeps deliberately small, for a
# guarantee the transport already gives in this flow. That trade is worth
# revisiting the day a token arrives by any route other than this one.

_MS_AUTHORITY = "https://login.microsoftonline.com"
# SSO_AUTHORITY_URL points federated sign-in at something other than
# Microsoft. It exists for the demo stack, which ships a stand-in provider
# so the flow can be walked without a real tenant, and it is the kind of
# setting that must never be set by accident: everything this receiver
# believes about who somebody is comes from the host named here.
#
# So it is loud rather than clever. There is no auto-detection and no
# "looks like localhost" heuristic - a deployment either says this in so
# many words or it talks to Microsoft. When it has been said, the boot log
# says so every single time, next to the value, in the same voice
# PORTAL_AUTH=none uses on the portal.
_AUTHORITY = os.environ.get("SSO_AUTHORITY_URL", "").rstrip("/") or _MS_AUTHORITY
if _AUTHORITY != _MS_AUTHORITY:
    print(json.dumps({
        "app": "ai-guard-receiver", "kind": "sso_authority_override",
        "authority": _AUTHORITY,
        "warning": "federated sign-in is pointed at a NON-MICROSOFT identity "
                   "provider. Every account it vouches for will be signed in. "
                   "This is for the demo stack; unset SSO_AUTHORITY_URL for "
                   "any real deployment.",
    }), flush=True)
# Guessing at endpoint paths is how an integration breaks silently when a
# cloud instance differs; these come from the tenant's own document.
_DISCOVERY = _AUTHORITY + "/%s/v2.0/.well-known/openid-configuration"
# A tenant is a GUID or a verified domain. Anything else is somebody's
# typo, and refusing it here beats a confusing failure three steps later.
_TENANT_RE = re.compile(r"^[0-9a-fA-F-]{36}$|^[a-zA-Z0-9.-]{3,120}$")
_GUID_RE = re.compile(r"^[0-9a-fA-F-]{36}$")

# In-flight sign-ins: state -> what has to match when the browser returns.
# In memory on purpose. A restart losing them costs somebody a retry,
# where a table would keep the nonce and verifier of every abandoned
# attempt indefinitely.
_SSO_FLIGHT: dict[str, dict] = {}
SSO_FLIGHT_SECONDS = 600
SSO_FLIGHT_MAX = 64


# How long a sign-in at the provider stays good for. Twelve hours by
# default: a working day, so nobody is asked twice before lunch, and a
# laptop left open overnight cannot be walked up to the next morning.
#
# Sent as max_age AND checked on the way back. max_age is a request - a
# provider is meant to honour it and Entra does, but a control that is only
# ever asked for is not a control. The token's auth_time is what proves it,
# and a token that arrives without one when max_age was asked for is
# refused rather than trusted.
SSO_MAX_AGE_DEFAULT_HOURS = 12
# Clocks differ. Two minutes is enough for that and far too little to
# matter against a window measured in hours.
SSO_AUTH_TIME_SKEW = 120


def _sso_max_age() -> int:
    """The window in seconds. 0 means re-authenticate every time."""
    raw = ((STATE.get_setting("sso_max_age_hours") if STATE else None) or "").strip()
    if raw == "":
        return SSO_MAX_AGE_DEFAULT_HOURS * 3600
    try:
        hours = int(raw)
    except ValueError:
        return SSO_MAX_AGE_DEFAULT_HOURS * 3600
    return max(0, hours) * 3600


def _sso_conf() -> dict:
    g = (lambda k, d="": (STATE.get_setting(k) if STATE else None) or d)
    return {
        "tenant": g("sso_tenant_id"),
        "client_id": g("sso_client_id"),
        "secret": g("sso_client_secret"),
        "redirect": g("sso_redirect_uri"),
        "enabled": g("sso_enabled") == "1",
    }


async def _sso_discover(tenant: str) -> dict:
    """The tenant's OpenID configuration, or a refusal naming the reason."""
    if not _TENANT_RE.match(tenant or ""):
        raise HTTPException(422, "that does not look like a tenant id or "
                                 "domain")
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(_DISCOVERY % tenant)
    except Exception as e:
        raise HTTPException(502, "could not reach the identity provider: %s"
                                 % type(e).__name__)
    if r.status_code != 200:
        raise HTTPException(400, "the identity provider does not recognise "
                                 "that tenant (HTTP %d)" % r.status_code)
    doc = r.json()
    for key in ("authorization_endpoint", "token_endpoint", "issuer"):
        if not doc.get(key):
            raise HTTPException(502, "the provider's configuration document "
                                     "is missing %s" % key)
    return doc


def _sso_sweep():
    now = time.time()
    for k in [k for k, v in _SSO_FLIGHT.items()
              if now - v["at"] > SSO_FLIGHT_SECONDS]:
        _SSO_FLIGHT.pop(k, None)


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _jwt_payload(token: str) -> dict:
    """The claims, without verifying the signature - see the note above."""
    try:
        part = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(
            part + "=" * (-len(part) % 4)))
    except Exception:
        raise HTTPException(502, "the identity provider returned a token "
                                 "this receiver could not read")


class SSOProbe(BaseModel):
    model_config = {"extra": "forbid"}
    tenant_id: str = Field(min_length=1, max_length=120)
    client_id: str = Field(default="", max_length=64)
    client_secret: str = Field(default="", max_length=512)


@app.post("/admin/sso/probe")
async def sso_probe(req: SSOProbe, authorization: str = Header(default="")):
    """Check a tenant, and optionally an app registration, before anything
    is saved.

    The wizard's verification step. Each answer names what was actually
    established, because "it works" over a half-configured provider is
    what produces a deployment nobody can sign in to.
    """
    _admin_auth(authorization, write=True, owner=True)
    doc = await _sso_discover(req.tenant_id.strip())
    out = {"tenant_ok": True, "issuer": doc["issuer"],
           "authorization_endpoint": doc["authorization_endpoint"]}
    if not (req.client_id and req.client_secret):
        return out
    if not _GUID_RE.match(req.client_id.strip()):
        raise HTTPException(422, "an application (client) id is a GUID")
    # A client credentials grant proves the id and secret are a real pair
    # in that tenant, before anybody is asked to sign in with them. It
    # says nothing about redirect URIs - only a real sign-in does.
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.post(doc["token_endpoint"], data={
                "client_id": req.client_id.strip(),
                "client_secret": req.client_secret,
                "scope": "https://graph.microsoft.com/.default",
                "grant_type": "client_credentials",
            })
    except Exception as e:
        raise HTTPException(502, "could not reach the token endpoint: %s"
                                 % type(e).__name__)
    body = {}
    try:
        body = r.json()
    except Exception:
        pass
    if r.status_code == 200 and body.get("access_token"):
        out["client_ok"] = True
        return out
    code = body.get("error", "")
    detail = body.get("error_description", "") or ("HTTP %d" % r.status_code)
    if code == "unauthorized_client" or "AADSTS700016" in detail:
        raise HTTPException(400, "no application with that client id exists "
                                 "in this tenant")
    if code == "invalid_client" or "AADSTS7000215" in detail:
        raise HTTPException(400, "that client secret is wrong, or expired")
    # A tenant can refuse the grant for reasons that say nothing about the
    # credentials - no application permissions consented, for one. The
    # pair is real if the refusal is about permissions rather than
    # identity, and saying so beats blocking a correct configuration.
    out["client_ok"] = False
    out["detail"] = detail[:300]
    return out


@app.get("/admin/sso/start")
async def sso_start(request: Request):
    """Begin a sign-in, or a test of one.

    Deliberately unauthenticated: this is the door somebody knocks on
    BEFORE they have a session. It gives away nothing a sign-in page does
    not - and returns 404 rather than a description when federated
    sign-in is off, so an estate that has not configured it does not
    advertise the endpoint.
    """
    if STATE is None:
        raise HTTPException(404, "Not Found")
    conf = _sso_conf()
    if not (conf["tenant"] and conf["client_id"] and conf["secret"]
            and conf["redirect"]):
        raise HTTPException(404, "Not Found")
    doc = await _sso_discover(conf["tenant"])
    _sso_sweep()
    if len(_SSO_FLIGHT) >= SSO_FLIGHT_MAX:
        raise HTTPException(429, "too many sign-ins in flight; try again")
    verifier = _b64u(secrets.token_bytes(48))
    state = _b64u(secrets.token_bytes(24))
    nonce = _b64u(secrets.token_bytes(24))
    # Whether this is the wizard proving a configuration rather than
    # somebody actually arriving. It has to be remembered HERE, against the
    # state, because the answer comes back as a cross-site form post
    # carrying nothing but a code and that state - there is no cookie on
    # it and no fragment, so the browser cannot be asked afterwards.
    max_age = _sso_max_age()
    _SSO_FLIGHT[state] = {"nonce": nonce, "verifier": verifier,
                          "at": time.time(), "issuer": doc["issuer"],
                          "token_endpoint": doc["token_endpoint"],
                          "max_age": max_age,
                          "test": request.query_params.get("test") == "1"}
    challenge = _b64u(hashlib.sha256(verifier.encode()).digest())
    return {"authorize_url": doc["authorization_endpoint"] + "?" + urllib.parse.urlencode({
        "client_id": conf["client_id"],
        "response_type": "code",
        "redirect_uri": conf["redirect"],
        # form_post keeps the code out of the URL, where it would land in
        # browser history and any proxy log on the way.
        "response_mode": "form_post",
        "scope": "openid profile email",
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        # Never a silent redirect. Without this, somebody already signed in
        # to the provider in that browser is returned straight here with no
        # interaction at all - click a link and you are inside a tool that
        # says who uses which AI. select_account is the floor: signing in
        # has to be something a person did, not something that happened.
        "prompt": "select_account",
        # And how recently they proved it. 0 asks the provider to
        # reauthenticate outright.
        "max_age": str(max_age),
    })}


class SSOCallback(BaseModel):
    model_config = {"extra": "forbid"}
    code: str = Field(min_length=1, max_length=4096)
    state: str = Field(min_length=1, max_length=256)


def _sso_refuse(why: str):
    # One shape for every refusal, and never the provider's raw error to a
    # browser: these are read by whoever is trying to sign in.
    return {"ok": False, "detail": why}


@app.post("/admin/sso/callback")
async def sso_callback(req: SSOCallback):
    """Redeem the code the provider handed the browser.

    Unauthenticated, like /start and for the same reason: nobody has a
    session yet. What protects it is the state it must quote - minted here
    minutes earlier, single-use, and paired with a PKCE verifier the
    browser never saw.

    The portal is what the browser talks to; it forwards the code here and
    turns the answer into its own cookie. The client secret stays in this
    process and the session is minted where sessions live.
    """
    if STATE is None:
        raise HTTPException(404, "Not Found")
    _sso_sweep()
    flight = _SSO_FLIGHT.pop(req.state, None)
    if flight is None:
        return _sso_refuse("that sign-in expired or was not started here")
    conf = _sso_conf()
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.post(flight["token_endpoint"], data={
                "client_id": conf["client_id"],
                "client_secret": conf["secret"],
                "code": req.code,
                "grant_type": "authorization_code",
                "redirect_uri": conf["redirect"],
                "code_verifier": flight["verifier"],
            })
    except Exception as e:
        return _sso_refuse("could not reach the token endpoint: %s"
                           % type(e).__name__)
    body = {}
    try:
        body = r.json()
    except Exception:
        pass
    if r.status_code != 200 or not body.get("id_token"):
        return _sso_refuse(str(body.get("error_description")
                               or "the provider refused the sign-in")[:300])

    claims = _jwt_payload(body["id_token"])
    # Everything a signature check would not have told us anyway. The
    # issuer is compared against the one this tenant's own discovery
    # document named, not against a pattern.
    if claims.get("iss") != flight["issuer"]:
        return _sso_refuse("the token came from an unexpected issuer")
    if claims.get("aud") != conf["client_id"]:
        return _sso_refuse("the token was issued for a different application")
    if claims.get("nonce") != flight["nonce"]:
        return _sso_refuse("the token did not answer this sign-in")
    if int(claims.get("exp") or 0) <= int(time.time()):
        return _sso_refuse("the token had already expired")
    # How recently they actually proved who they are, not how recently a
    # token was minted. exp says the token is fresh; auth_time says the
    # PERSON is. Without this max_age is a polite request, and a browser
    # holding a week-old provider session would be let in on a token
    # issued a second ago.
    want = flight.get("max_age")
    if want is not None:
        auth_time = int(claims.get("auth_time") or 0)
        if not auth_time:
            return _sso_refuse(
                "the provider did not say when this person last signed in, "
                "so how recent it was cannot be checked")
        age = int(time.time()) - auth_time
        if age > want + SSO_AUTH_TIME_SKEW:
            return _sso_refuse(
                "that sign-in is %d minutes old and this deployment asks "
                "for one within %d. Sign in again."
                % (age // 60, max(1, want // 60)))
    tid, sub = claims.get("tid") or "", claims.get("oid") or ""
    if not tid or not sub:
        return _sso_refuse("the token carried no tenant or object id")
    # A guest signing in through this tenant is a different account from
    # the same person in their home tenant, by Microsoft's own design.
    # Pinning the tenant is what keeps that true here.
    if _GUID_RE.match(conf["tenant"] or "") and tid != conf["tenant"]:
        return _sso_refuse("that account is not in this tenant")

    email = claims.get("email") or claims.get("preferred_username") or ""
    user = STATE.sso_account(tid, sub, email)
    if user is None:
        # No account, and none is created. An address in a tenant is not a
        # way in here: somebody has to have been given an account first.
        return _sso_refuse("no account here matches that sign-in. An owner "
                           "or admin has to create one and set its email "
                           "address first.")
    if not user["bound"]:
        try:
            STATE.sso_bind(user["id"], tid, sub)
        except _state.AuthError as e:
            return _sso_refuse(e.detail)
    out = STATE.sso_login(user["id"], ttl_hours=SESSION_TTL_HOURS)
    return {"ok": True, "token": out["token"], "username": out["username"],
            "role": out["role"], "expires_at": out["expires_at"],
            "bound_now": not user["bound"],
            "test": bool(flight.get("test"))}

# ------------------------------------------------------- central settings --
# Deployment configuration the portal edits and the fleet hears at runtime.
# Precedence is DB-wins-when-set: a saved value overrides the matching
# environment variable, and clearing it (null) falls back. The environment
# stays the whole story for classic mode, which has no DB to consult.


def _session_account(authorization: str) -> str:
    """The account id behind this request, for the rows an account owns.

    The ADMIN_TOKEN credential has no account and never will: it is
    automation and break-glass, and preferences belong to a person with a
    portal open. Saying so plainly beats inventing a shared pseudo-account
    for a credential several operators may hold.
    """
    token = _bearer(authorization)
    if STATE is not None and token.startswith(_state.SESSION_PREFIX):
        u = STATE.session_user(token)
        if u is not None:
            return u["user_id"]
    raise HTTPException(409, "preferences belong to a signed-in account; "
                             "the API credential does not have one")


def _actor_role(authorization: str) -> str:
    """The role to enforce the account rules against, or "" for the API
    credential - which is the operator's own break-glass and deliberately
    outside them."""
    token = _bearer(authorization)
    if STATE is not None and token.startswith(_state.SESSION_PREFIX):
        u = STATE.session_user(token)
        if u is not None:
            return u.get("role") or "admin"
    return ""


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
    # What the estate is called: the control beneath the portal logo, the
    # sign-in screen and the narrow top bar all say it. Public on purpose -
    # it is served to the sign-in screen before anybody has authenticated,
    # so it must never carry anything the estate would not put on a badge.
    ("org_name", False, 120),
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
    # Federated sign-in. Owner-gated in put_settings, because these decide
    # who may sign in at all rather than what the platform reports.
    # sso_enabled is deliberately last to matter: nothing here takes effect
    # until it is "1", and the portal will not set it until a real sign-in
    # has been completed against the rest.
    ("sso_tenant_id", False, 64),
    ("sso_client_id", False, 64),
    ("sso_client_secret", False, 512),
    ("sso_redirect_uri", True, 500),
    ("sso_enabled", False, 1),
    # Enforcement: a correct password stops being enough for every account
    # except the break-glass one. Guarded in put_settings, because turning
    # this on without a federated sign-in ever having completed is how a
    # deployment locks itself down to a single password.
    ("sso_enforce", False, 1),
    # How stale an existing session at the provider may be before somebody
    # has to prove who they are again. Hours; empty means the default
    # below, "0" means every single time. See _sso_max_age.
    ("sso_max_age_hours", False, 4),
    # The currency the Budget view's headline reports in, and the default
    # for newly linked tools. A display preference, not money math: the
    # portal never converts between currencies.
    ("budget_currency", False, 8),
    # Outbound mail, for telling somebody an account has been made for
    # them. Optional everywhere: an estate with no relay creates accounts
    # exactly as before and is told plainly that nobody was emailed, which
    # is the honest half of "invites" that a blocked Add account is not.
    ("smtp_host", False, 255),
    ("smtp_port", False, 5),
    ("smtp_username", False, 255),
    ("smtp_password", False, 512),
    # What the mail says it is from. Separate from the username because
    # plenty of relays authenticate as one identity and send as another.
    ("smtp_from", False, 320),
    # starttls (the default and what almost every relay wants), tls for
    # implicit TLS on 465, or none for a relay on a trusted network.
    ("smtp_security", False, 16),
    # The invite itself. Empty means the built-in wording; anything here
    # replaces it whole. {username} and {portal_url} are substituted.
    ("invite_subject", False, 200),
    ("invite_body", False, 4000),
    # The address people are told to go to. The receiver has no idea what
    # hostname the portal is reached on, and a link to the wrong one is
    # worse than no link.
    ("portal_public_url", True, 500),
)

# What the paste guard does when a marked document is pasted into an AI
# tool. Baked into every extension policy artifact; "warn" is the default
# when unset, matching the extension's own default.
_PASTE_GUARD_MODES = ("off", "warn", "block")
SECRET_SETTINGS = ("log_store_password", "webhook_url", "sso_client_secret",
                   "smtp_password")


class SettingsUpdate(BaseModel):
    # extra=forbid: an unknown key is a typo or a version mismatch, and
    # accepting it silently is how someone believes a setting is in effect.
    model_config = {"extra": "forbid"}
    org_name: str | None = Field(default=None, max_length=120)
    corp_domains: list[str] | None = Field(default=None, max_length=200)
    extension_id: str | None = Field(default=None, max_length=128)
    onboarding_done: bool | None = None
    receiver_public_url: str | None = Field(default=None, max_length=500)
    log_store_url: str | None = Field(default=None, max_length=500)
    log_store_push_url: str | None = Field(default=None, max_length=500)
    log_store_username: str | None = Field(default=None, max_length=256)
    log_store_password: str | None = Field(default=None, max_length=512)
    sso_tenant_id: str | None = Field(default=None, max_length=64)
    sso_client_id: str | None = Field(default=None, max_length=64)
    sso_redirect_uri: str | None = Field(default=None, max_length=500)
    sso_enabled: str | None = Field(default=None, max_length=1)
    sso_enforce: str | None = Field(default=None, max_length=1)
    sso_max_age_hours: str | None = Field(default=None, max_length=4)
    sso_client_secret: str | None = Field(default=None, max_length=512)
    alertmanager_url: str | None = Field(default=None, max_length=500)
    grafana_url: str | None = Field(default=None, max_length=500)
    grafana_panels: str | None = Field(default=None, max_length=2000)
    grafana_dashboard_uid: str | None = Field(default=None, max_length=128)
    overview_widgets: str | None = Field(default=None, max_length=500)
    extension_update_url: str | None = Field(default=None, max_length=500)
    extension_crx_url: str | None = Field(default=None, max_length=500)
    extension_xpi_url: str | None = Field(default=None, max_length=500)
    webhook_url: str | None = Field(default=None, max_length=500)
    smtp_host: str | None = Field(default=None, max_length=255)
    smtp_port: str | None = Field(default=None, max_length=5)
    smtp_username: str | None = Field(default=None, max_length=255)
    smtp_password: str | None = Field(default=None, max_length=512)
    smtp_from: str | None = Field(default=None, max_length=320)
    smtp_security: str | None = Field(default=None, max_length=16)
    invite_subject: str | None = Field(default=None, max_length=200)
    invite_body: str | None = Field(default=None, max_length=4000)
    portal_public_url: str | None = Field(default=None, max_length=500)
    budget_currency: str | None = Field(default=None, max_length=8)
    paste_guard_mode: str | None = Field(default=None, max_length=8)
    # "09:00-18:00", or empty. Empty is the honest default: nothing here can
    # know when an organisation works, and a shaded stretch nobody set is a
    # claim the platform has no basis for. Unset, the day is drawn with no
    # band at all rather than with an invented one.
    working_hours: str | None = Field(default=None, max_length=11)
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
        "org_name": plain("org_name"),
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
        "working_hours": plain("working_hours"),
        "budget_currency": plain("budget_currency"),
        "firefox_extension_id": plain("firefox_extension_id"),
        # An incoming webhook URL is itself a bearer capability - whoever
        # holds it can post to the channel - so it is masked like the log
        # store password: set-ness and source, never the value.
        "smtp_password": {
            # Never a value, only whether one exists and where from. A
            # password mounted by the deployment is still "set" as far as
            # anybody configuring this needs to know.
            "set": (stored.get("smtp_password") is not None
                    or bool(_SMTP_ENV["smtp_password"])),
            "source": "db" if stored.get("smtp_password") is not None
                      else ("env" if _SMTP_ENV["smtp_password"] else "unset"),
        },
        "webhook_url": {
            "set": stored.get("webhook_url") is not None,
            "source": "db" if stored.get("webhook_url") is not None else "unset",
        },
        "classification_markings": {
            "value": stored.get("classification_markings"),
            "source": ("db" if stored.get("classification_markings")
                       is not None else "unset"),
        },
        # Federated sign-in. The tenant, application id and redirect are
        # not secrets - they are in every authorize URL a browser sees -
        # so the wizard can show them back and say what is configured.
        "sso_tenant_id": plain("sso_tenant_id"),
        "sso_client_id": plain("sso_client_id"),
        "sso_redirect_uri": plain("sso_redirect_uri"),
        "smtp_host": plain("smtp_host", _SMTP_ENV["smtp_host"]),
        "smtp_port": plain("smtp_port", _SMTP_ENV["smtp_port"]),
        "smtp_username": plain("smtp_username", _SMTP_ENV["smtp_username"]),
        "smtp_from": plain("smtp_from", _SMTP_ENV["smtp_from"]),
        "smtp_security": plain("smtp_security", _SMTP_ENV["smtp_security"]),
        "invite_subject": plain("invite_subject"),
        "invite_body": plain("invite_body"),
        # The built-in wording, so the portal can show it as the starting
        # point and offer a way back to it.
        "invite_default_subject": {"value": INVITE_SUBJECT, "source": "derived"},
        "invite_default_body": {"value": INVITE_BODY, "source": "derived"},
        "portal_public_url": plain("portal_public_url"),
        # Derived, so the portal can say "nobody was emailed" without
        # having to work out what "configured" means for itself.
        "smtp_ready": {"value": "1" if _smtp_conf()["ready"] else "",
                       "source": "derived"},
        # What the portal needs to draw the enforcement control honestly:
        # whether it is on, and whether it could be turned on at all.
        "sso_enforce": plain("sso_enforce"),
        "sso_max_age_hours": plain("sso_max_age_hours"),
        "sso_max_age_default": {"value": str(SSO_MAX_AGE_DEFAULT_HOURS),
                                "source": "derived"},
        "sso_enforce_ready": {"value": "1" if STATE.an_owner_is_bound() else "",
                              "source": "derived"},
        "sso_break_glass": {"value": STATE.break_glass_username(),
                            "source": "derived"},
        "sso_enabled": plain("sso_enabled"),
        # The secret is not. Same treatment as the log-store password: set
        # -ness and source, never the value.
        "sso_client_secret": {
            "set": stored.get("sso_client_secret") is not None,
            "source": ("db" if stored.get("sso_client_secret") is not None
                       else "unset"),
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
    the row, which is how the environment value comes back into effect.

    The sso_* keys are owner-gated inside. They are not settings about
    what the platform reports; they decide who may sign in to it at all,
    which is the one thing the tier above admin exists to hold.
    """
    _admin_auth(authorization, write=True)
    if any(k.startswith("sso_") for k in req.model_fields_set):
        _admin_auth(authorization, write=True, owner=True)
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

    if "working_hours" in req.model_fields_set:
        wh = (req.working_hours or "").strip()
        if not wh:
            STATE.set_setting("working_hours", None, by)
        elif not _WORKING_HOURS_RE.match(wh):
            raise HTTPException(
                422, "working_hours must look like 09:00-18:00. A shift "
                     "crossing midnight is fine: 22:00-06:00.")
        else:
            STATE.set_setting("working_hours", wh, by)

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

    # Checked before the loop writes anything: the refusal has to name the
    # missing thing, and a partial write that enabled enforcement and then
    # failed on a later key would be the lockout this exists to prevent.
    if (req.sso_enforce or "").strip() == "1":
        stored = STATE.get_settings()
        if stored.get("sso_enabled") != "1" and (
                req.sso_enabled or "").strip() != "1":
            raise HTTPException(
                422, "single sign-on has to be on before it can be required")
        if not STATE.an_owner_is_bound():
            raise HTTPException(
                422, "no owner has completed a single sign-on yet. Sign in "
                     "through the provider once first: requiring a door "
                     "nobody has opened leaves only the break-glass account")

    if "sso_max_age_hours" in req.model_fields_set:
        raw = (req.sso_max_age_hours or "").strip()
        if raw and not (raw.isdigit() and 0 <= int(raw) <= 720):
            raise HTTPException(
                422, "sso_max_age_hours is a whole number of hours from 0 "
                     "to 720, or empty for the default")

    if "smtp_security" in req.model_fields_set:
        mode = (req.smtp_security or "").strip()
        if mode and mode not in _SMTP_SECURITY:
            raise HTTPException(422, "smtp_security must be one of: %s"
                                % ", ".join(_SMTP_SECURITY))
    if "smtp_port" in req.model_fields_set:
        port = (req.smtp_port or "").strip()
        if port and not (port.isdigit() and 1 <= int(port) <= 65535):
            raise HTTPException(422, "smtp_port must be a number from 1 to 65535")

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

_CANDIDATE_KINDS = ("domain", "mcp_server", "process")
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


# ------------------------------------------------------------- outbound mail --
# Telling somebody an account has been made for them. Deliberately small:
# stdlib smtplib, no templating engine, no queue, and nothing in the message
# that is worth intercepting.
#
# ON WHAT THE INVITE CONTAINS. Nothing secret. It says an account exists and
# where to sign in, and that is all. It carries no token and sets no
# password, so an invite sitting in the wrong inbox gains its reader
# nothing they could not have guessed. The alternative - a link that sets a
# password - is a credential in an inbox, and it needs expiry, single use,
# revocation and a throttle before it is safe. That is a feature of its
# own, not a line in this one.
#
# ON NOT BLOCKING. Sending happens on a thread and its failure is reported
# rather than raised. An account is created whether or not a relay answers:
# a product that refuses to make somebody an account because the mail
# server is not set up yet has chosen its own tidiness over the operator's
# morning.

_SMTP_SECURITY = ("starttls", "tls", "none")

# Every field can come from the environment instead, and the database wins
# when it holds one - the same precedence every other setting here uses.
#
# It exists for the password above all. In a cluster the relay credential is
# already a Secret, mounted into whatever else sends mail, and asking
# somebody to read it back out and paste it into a web form is asking them
# to copy a secret into a place it did not need to go. The chart can mount
# the same Secret here and the portal will show it as coming from the
# deployment, with no value to echo.
_SMTP_ENV = {
    "smtp_host": os.environ.get("SMTP_HOST", ""),
    "smtp_port": os.environ.get("SMTP_PORT", ""),
    "smtp_username": os.environ.get("SMTP_USERNAME", ""),
    # Through _secret, unlike its neighbours: this one is a credential, the
    # env table promises NAME_FILE for every secret in it, and Compose's
    # whole secret story is a file rather than an environment variable.
    "smtp_password": _secret("SMTP_PASSWORD", ""),
    "smtp_from": os.environ.get("SMTP_FROM", ""),
    "smtp_security": os.environ.get("SMTP_SECURITY", ""),
}


def _smtp_conf() -> dict:
    g = (lambda k, d="": ((STATE.get_setting(k) if STATE else None)
                          or _SMTP_ENV.get(k, "") or d))
    host = g("smtp_host").strip()
    sender = g("smtp_from").strip()
    return {
        "host": host,
        "port": int(g("smtp_port") or 0) or (465 if g("smtp_security") == "tls"
                                             else 587),
        "username": g("smtp_username"),
        "password": g("smtp_password"),
        "sender": sender,
        "security": g("smtp_security") or "starttls",
        "portal_url": g("portal_public_url").rstrip("/"),
        # Ready means a message could actually be addressed and sent. A
        # host with no from address produces mail most relays refuse, so
        # it is not "configured" in any sense worth reporting as such.
        "ready": bool(host and sender),
    }


def _smtp_send(to: str, subject: str, body: str) -> str:
    """Send one message. Returns "" on success, or a short reason.

    Synchronous and caller-timed: the test button wants the reason, and the
    invite path runs this on a thread of its own.
    """
    conf = _smtp_conf()
    if not conf["ready"]:
        return "no mail server is configured"
    msg = EmailMessage()
    msg["From"] = conf["sender"]
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    try:
        if conf["security"] == "tls":
            server = smtplib.SMTP_SSL(conf["host"], conf["port"], timeout=15)
        else:
            server = smtplib.SMTP(conf["host"], conf["port"], timeout=15)
        with server:
            if conf["security"] == "starttls":
                server.starttls()
            if conf["username"]:
                server.login(conf["username"], conf["password"])
            server.send_message(msg)
    except smtplib.SMTPResponseException as e:
        # The relay's own refusal, which is the useful half: "relay access
        # denied", "authentication failed", "sender rejected". Taken from
        # the structured fields rather than str(e), so what comes back is
        # the server's answer and not whatever else the exception carried.
        why = e.smtp_error
        if isinstance(why, bytes):
            why = why.decode("utf-8", "replace")
        return ("%s %s" % (e.smtp_code, why or ""))[:300].strip()
    except smtplib.SMTPException as e:
        # Everything else smtplib raises. The class name says which wall it
        # hit - SMTPAuthenticationError, SMTPServerDisconnected - without
        # relaying an arbitrary message into an API response.
        return type(e).__name__
    except (OSError, ssl.SSLError) as e:  # noqa: BLE001
        # Reached it or did not: DNS, refused, timed out, TLS. Named, not
        # quoted, for the same reason.
        return type(e).__name__
    return ""


INVITE_SUBJECT = "You have access to Shadow AI Guard"

# The default, and the thing an estate edits rather than replaces from
# nothing. Two placeholders, both filled in below.
INVITE_BODY = """An account has been created for you.

Username: {username}
Where: {portal_url}

Sign in with your work email address. If single sign-on is not set up for
you, whoever created the account will give you a password separately.

Nothing in this message is secret, and it grants no access on its own.
"""


def _invite_text(username: str) -> tuple[str, str]:
    """The invite, as this deployment has it.

    Fully editable, because it is their mail on their deployment and an
    organisation with wording standards is not wrong to have them. What
    replaces the old refusal is a warning in the portal: mail from a
    security tool telling staff to go and sign in is already the shape of
    an attack, and a body that adds a link somewhere else is the version
    of it nobody can tell apart from the real thing. Said, not enforced.
    """
    conf = _smtp_conf()
    g = (lambda k, d: ((STATE.get_setting(k) if STATE else None) or "").strip() or d)
    subject = g("invite_subject", INVITE_SUBJECT)
    body = g("invite_body", INVITE_BODY)
    fields = {"username": username,
              "portal_url": conf["portal_url"] or "the Shadow AI Guard portal"}
    for k, v in fields.items():
        # Plain replacement rather than str.format: a body somebody typed
        # will contain a stray brace sooner or later, and losing an invite
        # to a KeyError is a worse outcome than a literal {oops} arriving.
        subject = subject.replace("{%s}" % k, v)
        body = body.replace("{%s}" % k, v)
    return subject, body


def _send_invite(user: dict) -> str:
    """One invite, synchronously. Returns "" or a reason."""
    subject, body = _invite_text(user.get("username", ""))
    return _smtp_send(user.get("email", ""), subject, body)


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


def _note_process_candidates(f: Finding):
    """A process reached a model and the registry cannot name it. Ask.

    This is the same move the MCP path above makes, on the surface that
    never got it. An unrecognised process was shown on the Agentic AI view
    as "no tool we know" and then discarded - so the only way it ever became
    known was somebody editing the registry by hand, having spotted it on a
    page. The estate observed it; the estate should be the one asking.

    Deliberately quiet about what it is. The receiver knows a name reached a
    model host and nothing more, so the candidate carries the evidence and a
    human decides whether it is a tool to define, a system process to allow,
    or a script somebody wrote. That is the same contract as a domain
    candidate: the classifier proposes, the human disposes.
    """
    if STATE is None or f.surface not in ("network", "cloud"):
        return
    m = _VIA_RE.search(f.evidence or "")
    if not m:
        return
    name = m.group(1).strip()
    stems = _process_stems(name)
    if not stems:
        return
    # Names the registry already accounts for, resolvers and hosts that
    # name nothing, and browsers: none of these is a question.
    if any(x in _KNOWN_PROCESSES for x in stems):
        return
    if any(x in _UNATTRIBUTABLE for x in stems):
        return
    if name.lower() in _BROWSERS or any(x in _BROWSERS for x in stems):
        return
    # Already answered, either way. Asking again is how a review queue
    # becomes something nobody reads.
    low = name.strip().lower()
    if low in set(STATE.dispositioned_names("not_attributable")):
        return
    if low in STATE.process_aliases():
        return
    if not _CANDIDATE_TEXT.match(name):
        return
    if STATE.observe_candidate(
            _candidate_key("process", name), "process", name,
            (f.evidence or "")[:500], "network",
            f.device if f.device != "unknown" else "",
            # What the registry already thinks this is. By the time this runs
            # the finding's tool has been resolved from the domain it
            # reached, so "stable reached app.warp.dev" is known here - and
            # asking an operator what "stable" is, with the answer one
            # variable away, is a question nobody should have to research.
            #
            # A suggestion only. curl reaching api.anthropic.com is a script
            # somebody wrote, not Claude, and applying this automatically
            # would delete the exact finding this view exists for.
            suggested_tool=(f.tool or "") if (f.tool or "") in _REGISTRY_IDS
            else ""):
        _notify_webhook(
            "ai-guard: %r reached a model host and is not a tool, a browser"
            " or a system process this knows - now in the review queue"
            % (name,))


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


@app.post("/admin/candidates/{key}/not-attributable")
def mark_candidate_not_attributable(key: str,
                                    authorization: str = Header(default="")):
    """This name identifies no program: a resolver, a service host, a VPN
    tunnel that resolves for everything behind it.

    Distinct from a dismissal, which says "not a tool" and stops there. A
    dismissed curl is still a real process worth showing on the agentic view;
    a dismissed VPN tunnel is not, and saying so has to reach the views that
    read process names rather than just closing a card. Only processes: the
    claim is about a name, and a domain or an MCP server is not one.
    """
    _admin_auth(authorization, write=True)
    if not re.fullmatch(r"[a-z0-9_:-]{1,100}", key):
        raise HTTPException(422, "malformed candidate key")
    if not key.startswith("process:"):
        raise HTTPException(
            422, "only a process candidate can be marked not attributable")
    if not STATE.set_candidate_disposition(
            key, "not_attributable", _admin_actor(authorization)):
        raise HTTPException(404, "no candidate with that key")
    return {"not_attributable": key}


class CandidateBelongsTo(BaseModel):
    model_config = {"extra": "forbid"}
    tool_id: str = Field(min_length=1, max_length=100)


@app.post("/admin/candidates/{key}/belongs-to")
def mark_candidate_belongs_to(key: str, req: CandidateBelongsTo,
                              authorization: str = Header(default="")):
    """This process is a tool the registry already knows, under a name
    nothing would guess.

    Warp's macOS binary is called "stable", after its release channel. That
    name was briefly carried in the registry and had to come out: it is a
    word, and any process called "stable" was being silently excused as Warp.
    An operator can say it once here instead - which is the same trade the
    candidates queue makes everywhere else, a maintained guess replaced by an
    observed fact somebody confirmed.

    The tool must already exist. Inventing one from a process name is what
    "add to registry" is for, and it produces a tool with no domains that
    matches nothing.
    """
    _admin_auth(authorization, write=True)
    if not re.fullmatch(r"[a-z0-9_:-]{1,100}", key):
        raise HTTPException(422, "malformed candidate key")
    if not key.startswith("process:"):
        raise HTTPException(
            422, "only a process candidate can belong to a tool")
    known = {t.get("id") for t in (_merged_registry() or {}).get("tools", [])}
    if req.tool_id not in known:
        raise HTTPException(
            422, "no tool %s in the registry - define it first, or use "
                 "\"add to registry\" to create it" % req.tool_id[:60])
    if not STATE.set_candidate_disposition(
            key, "belongs_to", _admin_actor(authorization), tool=req.tool_id):
        raise HTTPException(404, "no candidate with that key")
    return {"belongs_to": req.tool_id, "key": key}


@app.get("/admin/candidates/process-aliases")
def get_process_aliases(authorization: str = Header(default="")):
    """Process name -> tool, for the views that read process names."""
    _admin_auth(authorization)
    return {"aliases": STATE.process_aliases()}


@app.get("/admin/candidates/not-attributable")
def get_not_attributable(authorization: str = Header(default="")):
    """The names a human has ruled out, for the views that read them."""
    _admin_auth(authorization)
    return {"names": STATE.dispositioned_names("not_attributable")}


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


# ------------------------------------------------------- identity map --
# Who is behind a device key or a local username. The portal generates
# the proposal, an operator corrects it, and this is where the corrected
# version lives - so the loop closes in the product instead of ending at
# a ConfigMap. A deployment that mounts a file keeps working: the portal
# merges, with what an operator saved here winning per key.

# The same characters the file loader refuses, for the same reason: a
# comma or a quote breaks the CSV round trip, and a hash starts the
# comment the proposal generator writes after each row.
_IDENTITY_UNSAFE = re.compile(r"[\x00-\x1f\x7f,\"'#]")
MAX_IDENTITY_ROWS = 10000


class IdentityRow(BaseModel):
    model_config = {"extra": "forbid"}
    key: str = Field(min_length=1, max_length=256)
    identity: str = Field(min_length=1, max_length=200)


class IdentityMapWrite(BaseModel):
    model_config = {"extra": "forbid"}
    entries: list[IdentityRow] = Field(default_factory=list,
                                       max_length=MAX_IDENTITY_ROWS)


@app.get("/admin/identity-map")
def get_identity_map(authorization: str = Header(default="")):
    """Readable by any account the portal authenticates: it renders these
    names on every page that attributes a device, so withholding the map
    from a viewer would only make the pages wrong, not private."""
    _admin_auth(authorization)
    return {"entries": STATE.list_identity_map()}


@app.put("/admin/identity-map")
def put_identity_map(req: IdentityMapWrite,
                     authorization: str = Header(default="")):
    """Replace the whole map. Validated as a batch before anything is
    written, so a 422 means nothing changed."""
    _admin_auth(authorization, write=True)
    seen, entries = set(), []
    for e in req.entries:
        key, identity = e.key.strip(), e.identity.strip()
        if not key or not identity:
            raise HTTPException(422, "every row needs a key and an identity")
        if _IDENTITY_UNSAFE.search(key) or _IDENTITY_UNSAFE.search(identity):
            raise HTTPException(
                422, "a key or identity contains a character that cannot "
                     "survive the CSV round trip (comma, quote, hash or a "
                     "control character): %s" % key[:60])
        if key.lower() in seen:
            raise HTTPException(422, "duplicate key: %s" % key[:60])
        seen.add(key.lower())
        entries.append({"key": key, "identity": identity})
    count = STATE.replace_identity_map(entries, _admin_actor(authorization))
    return {"ok": True, "count": count}


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
    # Which of the subscription's covered tools this tier entitles. Empty
    # means all of them; a narrower list is how "premium includes
    # claude-code, standard does not" is said.
    covers: list[str] = Field(default_factory=list, max_length=10)


def _resolve_plan_key(tool_id: str, given: str) -> str:
    """Which subscription on this tool a write means.

    Given explicitly, that. Otherwise the tool's only subscription, because
    a request that predates plans - or a UI that has not asked yet - means
    the one that exists. Ambiguous only when there really are several, and
    then it refuses rather than guessing: writing a member list into the
    wrong plan silently moves seats between contracts, and the money answer
    would still look plausible.

    Defaulting to "default" instead would be worse than either: it writes
    into a subscription nobody has, and the rows simply stop appearing.
    """
    keys = [x.get("plan_key") or "default"
            for x in STATE.list_budget()["subscriptions"]
            if x["tool_id"] == tool_id]
    if given:
        return given
    if len(keys) == 1:
        return keys[0]
    if not keys:
        return "default"
    raise HTTPException(
        422, "%s has %d subscriptions (%s) - say which plan this is for"
             % (tool_id, len(keys), ", ".join(sorted(keys))))


class BudgetSubscriptionWrite(BaseModel):
    model_config = {"extra": "forbid"}
    tool_id: str = Field(min_length=1, max_length=100)
    # Which subscription on that tool. Empty means "the one this plan names",
    # so creating the second plan on a tool is an ordinary save. Sent
    # explicitly when editing, which is what lets a plan be RENAMED - without
    # it, changing "Team" to "Teams" would quietly create a second
    # subscription beside the first rather than updating it.
    plan_key: str = Field(default="", max_length=64, pattern=r"^[a-z0-9-]*$")
    vendor: str = Field(default="", max_length=200)
    plan: str = Field(default="", max_length=100)
    currency: str = Field(default="", max_length=8)
    renewal_date: str = Field(default="", max_length=10)
    owner: str = Field(default="", max_length=200)
    notes: str = Field(default="", max_length=1000)
    seat_tiers: list[SeatTierWrite] = Field(default_factory=list,
                                            max_length=10)
    # Every tool this licence entitles. One seat on Claude Team covers
    # claude AND claude-code; modelling them as two subscriptions bills
    # the same licence twice and halves every observed-use answer.
    covers: list[str] = Field(default_factory=list, max_length=10)


class BudgetMemberWrite(BaseModel):
    model_config = {"extra": "forbid"}
    email: str = Field(min_length=3, max_length=254)
    name: str = Field(default="", max_length=200)
    role: str = Field(default="", max_length=64)
    seat_tier: str = Field(default="", max_length=64)


class BudgetMembersWrite(BaseModel):
    model_config = {"extra": "forbid"}
    tool_id: str = Field(min_length=1, max_length=100)
    # Which subscription on that tool. Empty means the one whose plan
    # this write names, which is what makes creating the second plan
    # on a tool an ordinary save rather than a special case.
    plan_key: str = Field(default="", max_length=64,
                          pattern=r"^[a-z0-9-]*$")
    # csv and manual only: "api" rows are written by sync alone, and a
    # request that could claim to be a sync would let a CSV wear an
    # API-synced provenance label in the portal.
    source: str = Field(min_length=1, max_length=16)
    members: list[BudgetMemberWrite] = Field(default_factory=list,
                                             max_length=_budget.MAX_MEMBERS)


class BudgetConnectionWrite(BaseModel):
    model_config = {"extra": "forbid"}
    tool_id: str = Field(min_length=1, max_length=100)
    # Which subscription on that tool. Empty means the one whose plan
    # this write names, which is what makes creating the second plan
    # on a tool an ordinary save rather than a special case.
    plan_key: str = Field(default="", max_length=64,
                          pattern=r"^[a-z0-9-]*$")
    provider: str = Field(min_length=1, max_length=32)
    api_key: str = Field(min_length=8, max_length=512)


class BudgetToolRef(BaseModel):
    model_config = {"extra": "forbid"}
    tool_id: str = Field(min_length=1, max_length=100)
    # Which subscription on that tool. Empty means the one whose plan
    # this write names, which is what makes creating the second plan
    # on a tool an ordinary save rather than a special case.
    plan_key: str = Field(default="", max_length=64,
                          pattern=r"^[a-z0-9-]*$")


@app.get("/admin/budget")
def get_budget(authorization: str = Header(default="")):
    """Subscriptions with members, connection metadata (never keys), and
    the provider catalogue the wizard offers."""
    _admin_auth(authorization)
    out = STATE.list_budget()
    out["providers"] = _budget.PROVIDERS
    # What every shipped tool's vendor offers, so the portal can say
    # whether a missing connector is our gap or the vendor's.
    out["member_apis"] = _budget.MEMBER_APIS
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

    # The covered set: the subscription's own tool always belongs to it,
    # every id is a well-formed tool id, and no tool may be covered by two
    # subscriptions - that is the same licence billed twice, refused here
    # by name rather than discovered later as double-counted spend.
    covers = [req.tool_id]
    for c in req.covers:
        c = c.strip()
        if not _TOOL_ID_RE.match(c):
            raise HTTPException(422, "malformed tool id in covers: %s"
                                % c[:60])
        if c not in covers:
            covers.append(c)
    pk = req.plan_key or _state.plan_key(req.plan)
    for other in STATE.list_budget()["subscriptions"]:
        same_tool = other["tool_id"] == req.tool_id
        if same_tool and other.get("plan_key") == pk:
            continue                      # this subscription, being edited
        if same_tool:
            # Two plans of one product entitle the same tools. A Max seat
            # includes Claude Code exactly as a Team seat does, so their
            # covered sets are SUPPOSED to be identical - different
            # contracts, different people, different member lists, and the
            # spend is each subscription's own seats times its own price.
            #
            # The first pass at this only excused the tool itself, so adding
            # Max 20 beside Team was refused the moment either named a
            # second tool. The rule is about one licence modelled twice,
            # which is a thing that happens between DIFFERENT tools.
            continue
        mine = set(covers)
        theirs = set(other.get("covers") or []) | {other["tool_id"]}
        clash = sorted(mine & theirs)
        if clash:
            raise HTTPException(
                422, "%s is already covered by the %s %s subscription - one "
                     "licence, one subscription; fold them together "
                     "instead" % (", ".join(clash), other["tool_id"],
                                  other.get("plan") or other.get("plan_key")))
    for t in req.seat_tiers:
        for c in t.covers:
            if c.strip() not in covers:
                raise HTTPException(
                    422, "tier %r covers %s, which the subscription does "
                         "not - a tier can only narrow the subscription's "
                         "own coverage" % (t.name[:40], c.strip()[:60]))

    STATE.upsert_budget_subscription(
        req.tool_id,
        {"vendor": req.vendor.strip(), "plan": req.plan.strip(),
         "currency": req.currency.strip(),
         "renewal_date": req.renewal_date, "owner": req.owner.strip(),
         "notes": req.notes.strip(),
         "covers": covers,
         "seat_tiers": [{"name": n, "seats": t.seats,
                         "unit_price_monthly": t.unit_price_monthly,
                         "covers": [c.strip() for c in t.covers]}
                        for n, t in zip(names, req.seat_tiers)]},
        _admin_actor(authorization), key=req.plan_key)
    return get_budget(authorization)


@app.post("/admin/budget/subscription/delete")
def delete_budget_subscription(req: BudgetToolRef,
                               authorization: str = Header(default="")):
    _admin_auth(authorization, write=True)
    if not STATE.delete_budget_subscription(
            req.tool_id, _admin_actor(authorization),
            key=_resolve_plan_key(req.tool_id, req.plan_key)):
        raise HTTPException(404, "no subscription for that tool and plan")
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
    count = STATE.replace_budget_members(
        req.tool_id, members, req.source, _admin_actor(authorization),
        key=_resolve_plan_key(req.tool_id, req.plan_key))
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
                                _admin_actor(authorization),
                                key=_resolve_plan_key(req.tool_id,
                                                      req.plan_key))
    return {"ok": True}


@app.post("/admin/budget/connection/delete")
def delete_budget_connection(req: BudgetToolRef,
                             authorization: str = Header(default="")):
    _admin_auth(authorization, write=True)
    if not STATE.delete_budget_connection(
            req.tool_id, _admin_actor(authorization),
            key=_resolve_plan_key(req.tool_id, req.plan_key)):
        raise HTTPException(404, "no connection for that tool and plan")
    return {"ok": True}


_CURRENCY_RE = re.compile(r"^[A-Za-z]{3}$")


@app.get("/admin/budget/fx")
async def budget_fx(to: str = "", authorization: str = Header(default="")):
    """The ECB's latest daily reference rates into the named currency,
    for the portal's converted headline. Read-only and cached; a source
    that cannot answer is a rendered fallback (ok: false), not a 5xx -
    the page shows per-currency figures instead."""
    _admin_auth(authorization)
    if not _CURRENCY_RE.match(to or ""):
        raise HTTPException(422, "to must be a 3-letter currency code")
    try:
        out = await _budget.fx_rates(to.upper())
    except _budget.SyncError as e:
        return {"ok": False, "detail": e.detail}
    return dict(out, ok=True)


@app.post("/admin/budget/sync")
async def budget_sync(req: BudgetToolRef,
                      authorization: str = Header(default="")):
    """One user sync, now, with the stored connection. The failure body
    is the operator's answer (ok: false with the reason), not a 5xx: the
    vendor refusing a key is an expected state the page must render, and
    the result is recorded either way so the card can show it later."""
    _admin_auth(authorization, write=True)
    by = _admin_actor(authorization)
    pk = _resolve_plan_key(req.tool_id, req.plan_key)
    conn = STATE.sync_connection_key(req.tool_id, pk)
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
        STATE.record_budget_sync(req.tool_id, False, e.detail, 0, by, key=pk)
        return {"ok": False, "detail": e.detail}
    STATE.replace_budget_members(req.tool_id, members, "api", by, key=pk)
    STATE.record_budget_sync(req.tool_id, True, "", len(members), by, key=pk)
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
    if f.signal and f.signal not in VALID_SIGNALS:
        f.signal = ""
    if f.mode and f.mode not in VALID_MODES:
        f.mode = ""
    if f.identity and f.identity not in VALID_IDENTITIES:
        f.identity = ""
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

    # Filled in only where the sender said nothing. A scanner that classified
    # the finding itself is never second-guessed here: it saw the hostname,
    # which is the one thing this cannot. Applied AFTER the rewrite above, so
    # it is matching a registry id rather than whatever name arrived.
    if not f.signal and f.surface in _PRESENCE_SURFACES and f.tool in _IDE_TOOLS:
        f.signal = "ambient"

    # MCP server names ride in as evidence; unknown ones join the
    # candidates queue (managed mode only - the function gates itself).
    _note_mcp_candidates(f)
    # ...and the same question for a process the registry cannot name.
    _note_process_candidates(f)

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