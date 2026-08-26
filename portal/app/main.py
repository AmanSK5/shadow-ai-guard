"""ai-guard portal.

A governance view over the findings the receiver already collects. It reads
Loki on request and derives entities: devices, identities, tools and the
relationships between them. It writes nothing, holds no database, and is not
in the path of anything that already works - if it falls over, collection
carries on.

Deliberately optional. Three deployments are equally valid: Grafana only,
portal only, or both with Grafana panels embedded here. The receiver stays
one stateless container either way.

Authentication is required, not optional. This page names who runs what on
which machine, which is the most sensitive thing the platform produces, so it
refuses to start rather than come up open by accident. Three shapes:

  managed (RECEIVER_URL set): a real login. The operator signs in with the
    admin account that lives in the receiver's state DB; the session rides
    as an HttpOnly cookie and the portal validates it against the receiver
    per request (with a short positive cache). PORTAL_USER/PORTAL_PASSWORD
    are ignored, with a warning, because two auth systems on one page is
    how one of them quietly stops being real.
  classic basic auth: PORTAL_USER and PORTAL_PASSWORD, as ever.
  PORTAL_AUTH=none: no portal auth, for localhost or behind a reverse proxy
    that authenticates. In managed mode reads are then open but admin
    actions still require the login - the receiver demands a credential
    and the session is how a person gets one.

Configuration, all optional except LOKI_URL and the auth pair:
  PORTAL_USER       basic auth username (classic mode only)
  PORTAL_PASSWORD   basic auth password (classic mode only)

Any of PORTAL_USER, PORTAL_PASSWORD, LOKI_TOKEN and LOKI_PASSWORD can be given as
NAME_FILE pointing at a file instead. Compose has no real secret story: an
environment variable is visible in docker inspect and in every child process's
environment, while a file is at least confined to the filesystem. It is not
encryption.

  PORTAL_AUTH       set to "none" to run without auth. Logs a warning on every
                    start, because an unauthenticated deployment should never
                    be something nobody noticed
  LOKI_URL          Loki base URL, e.g. http://loki:3100
  LOKI_TOKEN        bearer token, if your Loki needs one
  LOKI_USERNAME     basic auth user, for Grafana Cloud and most hosted Loki
  LOKI_PASSWORD     basic auth password, _FILE supported
  LOOKBACK_HOURS    default window, default 168
  DIGEST_WEBHOOK_URL  Slack-compatible webhook for the weekly digest;
                    DIGEST_DAY (mon..sun) and DIGEST_HOUR (UTC) tune when
  RECEIVER_ADMIN_TOKEN  the receiver's ADMIN_TOKEN, _FILE supported. Lets
                    the digest task read the log store saved through the
                    portal; without it the digest needs LOKI_URL
  REGISTRY_PATH     registry.yaml, for resolving domains to tool ids
  IDENTITY_MAP      CSV of key,identity for attaching people to devices
  GOVERNANCE_PATH   YAML of approval decisions, owners and review dates
  GRAFANA_URL       base URL of a Grafana that allows embedding; unset means
                    the dashboard shows a note instead of a broken frame
  GRAFANA_PANELS    what to embed, as "dashboardUid:panelId:Title" entries.
                    The title is the frame's accessible name, not a visible
                    caption: Grafana already renders the panel title inside
                    the frame, and showing it twice reads as a mistake.
                    Entries are separated by semicolons, not commas: Grafana
                    panel titles routinely contain commas ("Top tools
                    (devices, 7d)") and a comma separator silently split them
                    into malformed halves. Unset with GRAFANA_DASHBOARD_UID
                    set embeds the whole dashboard in one frame instead, which
                    needs no panel ids and survives someone rearranging them
  GRAFANA_DASHBOARD_UID  dashboard to embed whole, when no panels are listed
  CACHE_TTL_SECONDS how long a derived graph is reused, default 30. It exists
                    to absorb a page refresh and clicking between tabs, not to
                    reduce load: Grafana runs one query per panel on every
                    refresh, so a portal page load was already the lighter of
                    the two. It started at 300, which meant a fresh install
                    showed nothing for five minutes after the first collector
                    ran, with nothing on screen saying the view was stale.
"""

import json
import logging
import os
import re
import secrets
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import (FileResponse, JSONResponse, PlainTextResponse,
                               Response)
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field

from app import derive, evidence, governance, managed, paste_guard

log = logging.getLogger("portal")


# Secrets can come from a file instead of the environment. Docker Compose has
# no real secret story: an environment variable is visible in `docker inspect`,
# in /proc, and in every child process's environment, while a file is confined
# to the filesystem. Better, but still plaintext on the same disk - this is not
# encryption, and the deployment docs say so rather than implying otherwise.
def _secret(name: str, default: str = "") -> str:
    path = os.environ.get(name + "_FILE")
    if path:
        if os.environ.get(name):
            # Ambiguous rather than harmless: someone believes one of these is
            # in effect, and it is not necessarily the one they think.
            log.warning(
                "%s and %s_FILE are both set. The file wins; unset the "
                "environment variable to remove the ambiguity.", name, name,
            )
        try:
            with open(path) as fh:
                # Stripped. Almost every way of writing a file leaves a
                # trailing newline, and a password differing by one fails
                # authentication with no indication why.
                return fh.read().strip()
        except OSError as e:
            raise SystemExit(
                "%s_FILE is set to %s and it could not be read: %s" % (name, path, e)
            )
    return os.environ.get(name, default)


PORTAL_USER = _secret("PORTAL_USER")
PORTAL_PASSWORD = _secret("PORTAL_PASSWORD")
PORTAL_AUTH = os.environ.get("PORTAL_AUTH", "").lower()

_basic = HTTPBasic(auto_error=False)


def require_auth(request: Request,
                 creds: HTTPBasicCredentials = Depends(_basic)):
    """The gate on every data route, in whichever shape this deployment runs.

    Managed mode: the session cookie, validated against the receiver (which
    owns the accounts) with a short positive cache. Classic mode: basic auth,
    compared with compare_digest so a wrong username and a wrong password
    take the same time to reject - a difference there is enough to enumerate
    a valid username one character at a time.
    """
    if PORTAL_AUTH == "none":
        return
    if LOGIN_MODE:
        token = request.cookies.get(SESSION_COOKIE, "")
        if token and _session_ok(token):
            return
        # No WWW-Authenticate: the login is a page, not a browser dialog.
        raise HTTPException(status_code=401, detail="login required")
    if creds is None:
        raise HTTPException(
            status_code=401,
            detail="authentication required",
            headers={"WWW-Authenticate": "Basic"},
        )
    ok_user = secrets.compare_digest(creds.username, PORTAL_USER)
    ok_pass = secrets.compare_digest(creds.password, PORTAL_PASSWORD)
    if not (ok_user and ok_pass):
        raise HTTPException(
            status_code=401,
            detail="invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )


def require_page_auth(request: Request,
                      creds: HTTPBasicCredentials = Depends(_basic)):
    """The gate on the HTML shell and the logo.

    In managed mode these are open: the shell is a static file holding no
    estate data, it has to load for the login screen to exist at all, and
    every API it calls is behind require_auth above. Classic mode keeps
    basic auth on them, as ever.
    """
    if LOGIN_MODE:
        return
    require_auth(request, creds)


def require_http_url(name, url):
    """The URL back, or exit if it is not http or https.

    derive.fetch_from_loki reaches this through urllib.request.urlopen, which
    honours file:, ftp: and anything else with a handler registered, so a
    mistyped LOKI_URL of file:///etc/passwd would be read and parsed as a Loki
    response rather than refused. Operator-supplied rather than
    attacker-supplied, so less an attack path than a way for a typo to do
    something surprising quietly.

    Refuses at startup rather than warning. A portal that starts against a log
    store it cannot query shows an empty estate, and an empty estate is the
    answer this platform exists to distinguish from a quiet one.
    """
    if url and not url.startswith(("http://", "https://")):
        raise SystemExit("%s must be http:// or https://, got %r"
                         % (name, url[:40]))
    return url


LOKI_URL = require_http_url("LOKI_URL", os.environ.get("LOKI_URL", ""))
LOKI_TOKEN = _secret("LOKI_TOKEN") or None
# Basic auth for reads. The receiver has had LOKI_USERNAME/LOKI_PASSWORD for
# its writes; the portal only had a bearer token, so against Grafana Cloud the
# receiver stored findings the portal then got a 401 trying to read back.
LOKI_USERNAME = os.environ.get("LOKI_USERNAME", "") or None
LOKI_PASSWORD = _secret("LOKI_PASSWORD") or None
LOOKBACK_HOURS = float(os.environ.get("LOOKBACK_HOURS", "168"))
REGISTRY_PATH = os.environ.get("REGISTRY_PATH", "/srv/registry/registry.yaml")
IDENTITY_MAP = os.environ.get("IDENTITY_MAP", "")
# Governance decisions. Optional: without it the registry's own approved
# flag stands as the default and owner and review date show as not set.
GOVERNANCE_PATH = os.environ.get("GOVERNANCE_PATH", "")
GRAFANA_URL = os.environ.get("GRAFANA_URL", "").rstrip("/")
GRAFANA_PANELS = os.environ.get("GRAFANA_PANELS", "")
GRAFANA_DASHBOARD_UID = os.environ.get("GRAFANA_DASHBOARD_UID", "")
CACHE_TTL = int(os.environ.get("CACHE_TTL_SECONDS", "30"))
# The pagination safety cap for one Loki read (issue #104): the read walks
# the whole window page by page and stops early only here - and says so.
# Raise it for a very large fleet rather than living with a floor.
LOKI_MAX_FINDINGS = int(os.environ.get("LOKI_MAX_FINDINGS", "100000"))

# Which widgets the overview shows, in order. A deployment decision rather than
# a per-user one: the portal holds no state and has no users to hold it
# against, so this is the level at which an organisation can shape its landing
# page without the portal growing a database and an identity model.
OVERVIEW_WIDGETS = os.environ.get("OVERVIEW_WIDGETS", "")

# Facts about how this was deployed that the portal cannot verify for itself.
# Surfaced separately and labelled as such, because a value the deployment
# claims is not the same kind of thing as a value the portal observed, and
# presenting them together would make the whole page less trustworthy.
DEPLOY_CHART = os.environ.get("DEPLOY_CHART_VERSION", "")
DEPLOY_RELEASE = os.environ.get("DEPLOY_RELEASE", "")
DEPLOY_NAMESPACE = os.environ.get("DEPLOY_NAMESPACE", "")

# Managed mode. RECEIVER_URL is where admin actions are proxied - the
# receiver's internal address, because the browser's CSP keeps it on 'self'
# and something has to make the call. Unset means the managed views say so
# and everything else is exactly the classic portal. RECEIVER_PUBLIC_URL is
# different on purpose: it is the ingest URL agents can actually reach, and
# it is what gets baked into downloaded deployment artifacts - a
# cluster-internal service name baked into a Jamf script would enroll
# nothing. The portal holds no admin credential for any of this: the
# operator's token arrives per request and is forwarded, never stored.
RECEIVER_URL = require_http_url("RECEIVER_URL", os.environ.get("RECEIVER_URL", ""))
RECEIVER_PUBLIC_URL = require_http_url(
    "RECEIVER_PUBLIC_URL", os.environ.get("RECEIVER_PUBLIC_URL", ""))

# Managed mode is also login mode: one switch, not two that can disagree.
# The receiver owns the admin account (created first-boot with the setup
# code it prints); the portal signs in against it, carries the session as
# an HttpOnly cookie, and validates per request below. Basic auth belongs
# to classic mode only.
LOGIN_MODE = bool(RECEIVER_URL)
SESSION_COOKIE = "aiguard_session"
# How long a positive validation is trusted before the receiver is asked
# again. Bounds the revocation latency, and only the positive answer is
# cached: a refused session is refused every time.
SESSION_CACHE_TTL = 60
_session_cache: dict[str, tuple[float, str, str]] = {}  # token -> (until, username, role)

# The receiver-stored settings, cached briefly so a page of API calls does
# not re-fetch them. Two caches because they answer different callers: the
# masked view (display preferences, receiver public URL) and the log-store
# secrets, which only _log_store below ever touches and no route relays.
SETTINGS_CACHE_TTL = 30
_remote_settings_cache: dict = {"at": 0.0, "data": None}
_log_store_cache: dict = {"at": 0.0, "data": None}
_registry_entries_cache: dict = {"at": 0.0, "data": None}


def _invalidate_settings_caches():
    _remote_settings_cache.update(at=0.0, data=None)
    _log_store_cache.update(at=0.0, data=None)

# Fail closed. Coming up open because a variable was missed is the failure
# that matters here: the portal is reachable, it looks like it works, and
# nothing says the door is off. Refusing to start is loud and immediate.
# Checked here rather than beside PORTAL_USER above because the answer
# depends on RECEIVER_URL: managed mode brings its own login and needs no
# basic-auth pair.
if PORTAL_AUTH == "none":
    log.warning(
        "PORTAL_AUTH=none: this portal is running WITHOUT AUTHENTICATION. It "
        "shows which people use which AI tools on which machines. That is fine "
        "on localhost and behind a proxy that authenticates for it, and it is "
        "not fine on anything reachable."
    )
elif LOGIN_MODE:
    if PORTAL_USER or PORTAL_PASSWORD:
        log.warning(
            "PORTAL_USER/PORTAL_PASSWORD are ignored in managed mode: the "
            "portal login (the receiver's admin account) replaces basic auth. "
            "Unset them to remove the ambiguity."
        )
elif not (PORTAL_USER and PORTAL_PASSWORD):
    raise SystemExit(
        "refusing to start without authentication.\n\n"
        "This portal shows which people use which AI tools on which machines.\n"
        "Set PORTAL_USER and PORTAL_PASSWORD, or set PORTAL_AUTH=none if you\n"
        "mean it - localhost, or behind a proxy that authenticates for you.\n\n"
        "Basic auth is one shared credential with no per-user trail. If you\n"
        "already run a reverse proxy, authenticate there instead and run this\n"
        "with PORTAL_AUTH=none behind it."
    )
# Verified copies of the endpoint collector scripts, shipped in the image
# because the build cannot see the endpoint/ tree (same pattern as the
# chart's bundled registry; a test asserts byte equality with the sources).
COLLECTOR_SCRIPTS_DIR = os.environ.get(
    "COLLECTOR_SCRIPTS_DIR", str(Path(__file__).parent.parent / "collector-scripts"))

# Verified copies of extension/src, same pattern: the extension-source
# download serves these with the receiver origin substituted in, so packing
# the extension no longer needs a checkout.
EXTENSION_SRC_DIR = os.environ.get(
    "EXTENSION_SRC_DIR", str(Path(__file__).parent.parent / "extension-src"))

STATIC = Path(__file__).parent / "static"

# Set at build time from the release tag, or the commit for a build off main.
# "dev" for a local build, which is honest.
APP_VERSION = os.environ.get("APP_VERSION", "dev")

app = FastAPI(title="ai-guard portal", version=APP_VERSION,
              docs_url=None, redoc_url=None)


def _frame_src() -> str:
    """The Grafana origin frames may load from: env, else the portal-saved
    setting as last seen in the settings cache.

    The cache only, deliberately: this runs on every response with no
    session to fetch with. The consequence is real and worth stating
    plainly: a document's CSP is fixed when it is served, so a page that
    was open BEFORE a Grafana URL was saved stays blocked until a full
    reload, however warm this cache gets - which the homelab install
    demonstrated as "This content is blocked" with a correct header on the
    wire. The page therefore forces location.reload() after saving any
    grafana_* setting; this cache covers every load after that.
    """
    if GRAFANA_URL:
        return GRAFANA_URL
    rs = _remote_settings_cache["data"] or {}
    entry = rs.get("grafana_url")
    if isinstance(entry, dict):
        return (entry.get("value") or "").rstrip("/")
    return ""


@app.middleware("http")
async def security_headers(request, call_next):
    """Headers that limit what a rendering bug can do.

    The portal renders findings, and a finding is attacker-influenced: anyone
    holding the reporting token can put arbitrary text in a device name, and
    that token is on every collector. Escaping is the fix for that and these
    headers are what stops the next escaping mistake being exploitable.

    Be clear about what this does not do. script-src carries 'unsafe-inline',
    because the page's whole script is inline in index.html, which is served as
    a static file. So this policy does NOT stop an injected <script> tag from
    running. Making it do so means a nonce, which means templating the HTML per
    request, and that is a real change rather than a header.

    What it does stop is worth having anyway, and connect-src is most of it:
    the estate data this page can read is
    the thing worth exfiltrating, and without it a successful injection could
    read every API and post the result elsewhere. An injection that runs but
    cannot phone home is a much smaller problem than one that can.
    frame-ancestors 'none' because nothing should frame a page that names who
    runs what on which machine, and form-action 'none' because it has no forms.

    So this is a second line rather than the fix. The fix is that findings are
    escaped and nothing is interpolated into an executable context, which is
    what the tests in portal/tests hold.

    no-store on everything: the responses name people, devices and accounts,
    and a shared machine's disk cache is not where that belongs.
    """
    response = await call_next(request)
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        # 'unsafe-inline' because index.html's script is inline and served
        # static. This is the weak part of the policy and it is deliberate
        # rather than overlooked: removing it needs a nonce and a templated
        # page, not a header change.
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-src " + (_frame_src() or "'none'") + "; "
        "frame-ancestors 'none'; "
        "form-action 'none'; "
        "base-uri 'none'; "
        "object-src 'none'",
    )
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Cache-Control", "no-store")
    return response

@app.middleware("http")
async def json_posts_only(request, call_next):
    """The CSRF half that cookies made necessary.

    The old write path was immune by construction: the credential lived in
    JS memory and rode a custom header no cross-site request can set. A
    cookie goes wherever the browser goes, so two things stand in for that
    header now: SameSite=Strict on the cookie itself, and this rule - every
    POST under /api must declare application/json, which a cross-site form
    cannot (forms speak urlencoded, multipart and text/plain only, and a
    fetch that sets the header triggers CORS preflight, which 'self' fails).
    Enforced in login mode only: classic mode has no cookie to protect and
    its callers were never asked for the header.
    """
    if (LOGIN_MODE and request.method == "POST"
            and request.url.path.startswith("/api")
            and not request.headers.get("content-type", "")
                                    .startswith("application/json")):
        return JSONResponse(
            {"detail": "POST bodies here are JSON: send "
                       "Content-Type: application/json"},
            status_code=415)
    return await call_next(request)


# A derived graph, kept briefly. Not state in any meaningful sense: it rebuilds
# from Loki on the next miss and on every restart. Without it, a 7 day query
# runs on every page load, which is slow for the reader and unkind to Loki.
_cache: dict = {}

STARTED_AT = time.time()

# When Loki last answered. The distinction that matters on a status page is
# between "nothing is happening" and "we cannot see whether anything is
# happening", and only this tells them apart.
_last_loki_ok: float = 0.0
_last_loki_error: str = ""
# Whether the most recent Loki read stopped at LOKI_MAX_FINDINGS. Reported
# on every derived response and in the evidence manifest, because a count
# computed over a sample must never present itself as a total (issue #104).
_last_read_truncated: bool = False


def _redact_url(url):
    """A URL with any embedded credentials removed.

    LOKI_URL is operator-supplied and http://user:pass@host is a legal way to
    supply it. Naming which Loki failed is genuinely useful in an error, so the
    host stays and only the userinfo goes. Returns a placeholder rather than
    the raw string if it will not parse, because a URL that cannot be parsed
    cannot be confirmed safe to echo.
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
    return urllib.parse.urlunsplit(
        (parts.scheme, netloc, parts.path, "", "")
    )


def _remote_settings(request) -> dict:
    """The receiver's stored settings (masked view), or {} outside login
    mode. Quiet on failure: the callers are display preferences and
    prefills, and a page that falls back to its env values beats a page
    that refuses to render because a settings fetch hiccuped. Anything
    correctness-critical (the log store, artifacts) fetches loudly itself.
    """
    if not LOGIN_MODE or request is None:
        return {}
    now = time.time()
    if (_remote_settings_cache["data"] is not None
            and now - _remote_settings_cache["at"] < SETTINGS_CACHE_TTL):
        return _remote_settings_cache["data"]
    token = request.cookies.get(SESSION_COOKIE, "")
    try:
        out = managed.receiver_request(
            RECEIVER_URL, "GET", "/admin/settings", token).get("settings", {})
    except managed.ReceiverError:
        return {}
    _remote_settings_cache.update(at=now, data=out)
    return out


def _remote_value(settings: dict, key: str, env: str = "") -> str:
    """One effective string from the masked settings view, env fallback."""
    entry = settings.get(key)
    v = entry.get("value") if isinstance(entry, dict) else None
    return v if v else env


def _log_store(request):
    """(url, username, password, source) for reading findings back.

    The portal-saved log store wins; the portal's own env is the fallback,
    exactly the rule every setting follows. The password crosses only this
    server-side hop - no route relays it - and a receiver that cannot
    answer is a loud error, because silently falling back to env here
    could read a different store than the receiver is writing to.
    """
    # The secrets read is a server-side hop with the portal's own service
    # credential (RECEIVER_ADMIN_TOKEN) when one is configured - it also
    # serves request=None, the digest's background caller. Without one it
    # falls back to the session, which works for admins; a viewer session
    # is refused there by design (the stored credential is typically
    # write-capable, and a read-only account must not be a path to it), so
    # the refusal names what to configure instead of echoing a bare 403.
    if LOGIN_MODE and (request is not None or RECEIVER_ADMIN_TOKEN):
        now = time.time()
        if (_log_store_cache["data"] is None
                or now - _log_store_cache["at"] >= SETTINGS_CACHE_TTL):
            token = RECEIVER_ADMIN_TOKEN or (
                request.cookies.get(SESSION_COOKIE, "")
                if request is not None else "")
            try:
                _log_store_cache["data"] = managed.receiver_request(
                    RECEIVER_URL, "GET", "/admin/settings/secrets", token)
                _log_store_cache["at"] = now
            except managed.ReceiverError as e:
                if e.status == 502:
                    log.warning("receiver call failed for %s: %s",
                                _redact_url(RECEIVER_URL), e.detail)
                if e.status == 403:
                    raise HTTPException(
                        403, "this account cannot read the log-store "
                             "credentials (read-only accounts never can). "
                             "Give the portal RECEIVER_ADMIN_TOKEN - the "
                             "receiver's ADMIN_TOKEN - so it reads with "
                             "its own credential, or set LOKI_URL by env.")
                raise HTTPException(
                    e.status, "could not read the log-store configuration "
                              "from the receiver (%s)" % e.detail)
        s = _log_store_cache["data"]
        if s.get("log_store_url"):
            return (s["log_store_url"], s.get("log_store_username") or "",
                    s.get("log_store_password") or "", "portal")
    return (LOKI_URL, LOKI_USERNAME or "", LOKI_PASSWORD or "", "env")


def _custom_registry_entries(request) -> list:
    """The portal-defined registry entries (raw entry dicts, shadowed ones
    excluded - shipped wins those), cached briefly, empty outside login
    mode. Loud when the receiver cannot answer: quietly narrowing the
    registry would make a portal-defined tool vanish from every view while
    the fleet keeps detecting it, which is exactly the split-brain this
    project exists to avoid."""
    if not LOGIN_MODE or request is None:
        return []
    now = time.time()
    if (_registry_entries_cache["data"] is not None
            and now - _registry_entries_cache["at"] < SETTINGS_CACHE_TTL):
        return _registry_entries_cache["data"]
    token = request.cookies.get(SESSION_COOKIE, "")
    try:
        out = managed.receiver_request(
            RECEIVER_URL, "GET", "/admin/registry-entries", token)
    except managed.ReceiverError as e:
        if e.status == 502:
            log.warning("receiver call failed for %s: %s",
                        _redact_url(RECEIVER_URL), e.detail)
        raise HTTPException(
            e.status, "could not read the custom registry entries from the "
                      "receiver (%s)" % e.detail)
    entries = [e["entry"] for e in out.get("entries", [])
               if not e.get("shadowed")]
    _registry_entries_cache.update(at=now, data=entries)
    return entries


def _registry(request) -> dict:
    """The registry every portal view should reason over: the shipped file
    plus the portal-defined entries, merged exactly as the receiver serves
    them to the fleet. Classic mode is the file alone, as ever."""
    reg = derive.load_registry(REGISTRY_PATH)
    custom = _custom_registry_entries(request)
    if custom:
        reg = dict(reg)
        shipped = {t.get("id") for t in reg.get("tools", [])}
        reg["tools"] = list(reg.get("tools", [])) + [
            e for e in custom if e.get("id") not in shipped]
    return reg


def _cached(key, hours, builder):
    now = time.time()
    hit = _cache.get(key)
    if hit and hit["hours"] == hours and now - hit["at"] < CACHE_TTL:
        return hit["value"], hit["at"]
    value = builder()
    _cache[key] = {"value": value, "at": now, "hours": hours}
    return value, now


def _findings(hours, request=None):
    url, username, password, source = _log_store(request)
    if not url:
        raise HTTPException(
            status_code=503,
            detail="No log store is configured. Save its base URL in "
                   "Settings (managed mode), or set LOKI_URL - the same "
                   "store the receiver writes to.",
        )
    global _last_loki_ok, _last_loki_error, _last_read_truncated
    try:
        out = derive.fetch_from_loki(
            # The bearer token is env configuration and belongs to the env
            # store; a portal-saved store authenticates with its own pair.
            url, hours, LOKI_TOKEN if source == "env" else None,
            username=username or None, password=password or None,
            max_findings=LOKI_MAX_FINDINGS)
        _last_loki_ok = time.time()
        _last_loki_error = ""
        _last_read_truncated = getattr(out, "truncated", False)
        return out
    except Exception as e:
        # The detail goes to the log, not to the caller. An exception message
        # is written for an operator reading a stack trace, not for an HTTP
        # body, and LOKI_URL may carry credentials in its userinfo.
        log.warning(
            "Loki read failed for %s: %s", _redact_url(url), e,
            exc_info=True,
        )
        _last_loki_error = type(e).__name__
        # Say which of the two this is. A portal that shows an empty graph
        # when it cannot reach Loki is indistinguishable from one reporting a
        # clean estate, which is the failure this project keeps finding. The
        # redacted host and the exception type carry that distinction; the
        # message behind it is one kubectl logs away.
        raise HTTPException(
            status_code=502,
            detail="Could not read findings from Loki at %s (%s). "
                   "See the portal logs for detail."
                   % (_redact_url(url), type(e).__name__),
        )


# Deliberately unauthenticated: a liveness probe that needs a credential is a
# probe that fails for the wrong reason. It returns nothing about the estate.
@app.get("/healthz")
def healthz():
    return {"ok": True, "version": APP_VERSION}


@app.get("/api/config")
def config(request: Request, _=Depends(require_auth)):
    """What the browser needs to know about this deployment.

    In login mode the display preferences (Grafana embedding, overview
    widgets) and the receiver public URL resolve settings-first with env
    as fallback, so the wizard's answers take effect with no redeploy.
    """
    rs = _remote_settings(request)
    grafana_url = _remote_value(rs, "grafana_url", GRAFANA_URL).rstrip("/")
    panels_raw = _remote_value(rs, "grafana_panels", GRAFANA_PANELS)
    dashboard_uid = _remote_value(rs, "grafana_dashboard_uid",
                                  GRAFANA_DASHBOARD_UID)
    public_url = _remote_value(rs, "receiver_public_url", RECEIVER_PUBLIC_URL)
    log_store = _remote_value(rs, "log_store_url", LOKI_URL)

    panels = []
    for spec in panels_raw.split(";"):
        spec = spec.strip()
        if not spec:
            continue
        parts = spec.split(":", 2)
        if len(parts) < 2:
            # Said out loud rather than skipped: a panel that silently does not
            # appear looks like Grafana refusing the frame, which sends someone
            # off debugging headers for a typo in an environment variable.
            panels.append({"error": "malformed grafana panels entry: %s" % spec})
            continue
        panels.append({
            "uid": parts[0],
            "panel_id": parts[1],
            "title": parts[2] if len(parts) > 2 else "",
        })

    return {
        "loki_configured": bool(log_store),
        "grafana_url": grafana_url,
        "grafana_panels": panels,
        "grafana_dashboard_uid": dashboard_uid,
        "lookback_hours": LOOKBACK_HOURS,
        "identity_map_configured": bool(IDENTITY_MAP and Path(IDENTITY_MAP).exists()),
        "cache_ttl_seconds": CACHE_TTL,
        "version": APP_VERSION,
        "overview_widgets": _widgets(_remote_value(rs, "overview_widgets",
                                                   OVERVIEW_WIDGETS)),
        # enabled says the portal can reach an admin API; artifacts_ready
        # says downloads can bake a URL agents can reach. Separate flags,
        # because a deployment can sensibly have the first without the
        # second and the UI should name which one is missing.
        # receiver_public_url_default is the wizard's prefill: the effective
        # value today, whichever source supplies it.
        "managed": {
            "enabled": bool(RECEIVER_URL),
            "artifacts_ready": bool(RECEIVER_URL and public_url),
            "receiver_public_url_default": public_url,
            # The bundled extension source's version: the setup guide names
            # files with it and the generated update manifests carry it.
            "extension_version": _extension_version_or_blank(),
        },
    }


def _extension_version_or_blank() -> str:
    """Config must render even if the bundled source is unreadable - the
    guide then says VERSION where it would say a number, and the download
    itself reports the real error."""
    try:
        return managed.extension_version(EXTENSION_SRC_DIR)
    except managed.ArtifactError:
        return ""


# The widgets the overview knows how to draw. A name not in here is a typo or
# a value written against a different version, and either way the honest thing
# is to say so: a widget that silently does not appear looks identical to one
# that appeared and had nothing to show, which is the confusion this project
# exists to remove.
KNOWN_WIDGETS = {
    "stat_row": "Headline counts across the estate",
    "top_tools": "Tools by number of devices",
    "recent_personal_accounts": "Most recently seen personal accounts",
    "detection_coverage": "How much of each surface is reporting",
    "source_health": "Sources reporting versus silent",
    "paste_guard": "Pastes warned, overridden and blocked",
    "review_queue": "Observed tools awaiting a governance decision",
}

DEFAULT_WIDGETS = ["stat_row", "review_queue", "top_tools",
                   "recent_personal_accounts", "detection_coverage"]


def _widgets(spec=None):
    """Parse an overview-widgets string into what the browser should draw.

    grafana:<panel-title> entries are resolved against the panels list
    rather than repeating panel ids in two places. spec defaults to the
    env value; login mode passes the effective setting through.
    """
    raw = [w.strip() for w in
           (OVERVIEW_WIDGETS if spec is None else spec).split(",")
           if w.strip()]
    if not raw:
        return [{"kind": w} for w in DEFAULT_WIDGETS]
    out = []
    for w in raw:
        if w.startswith("grafana:"):
            out.append({"kind": "grafana", "ref": w.split(":", 1)[1]})
        elif w in KNOWN_WIDGETS:
            out.append({"kind": w})
        else:
            out.append({
                "kind": "error",
                "error": "unknown widget %r. Known widgets: %s"
                         % (w, ", ".join(sorted(KNOWN_WIDGETS))),
            })
    return out


@app.get("/api/diagnostics")
def diagnostics(_=Depends(require_auth)):
    """What the portal can say about itself, for a support conversation.

    Everything under "runtime" is observed: the portal either did the thing or
    it did not. Everything under "deployment" was passed in and is labelled, so
    a chart version nobody updated cannot be mistaken for a chart version
    something checked.

    No secret values, ever. Whether a credential is configured is useful.
    What it is, is not.
    """
    reg_ok, reg_tools, reg_err = False, 0, ""
    try:
        dm = derive.load_domain_map(REGISTRY_PATH)
        reg_ok = bool(dm)
        reg_tools = len(set(dm.values())) if dm else 0
    except Exception as e:  # pragma: no cover - defensive
        # A parse failure names the file, the line and the column. That is the
        # right thing in a log and the wrong thing in a response body: the path
        # is operator-supplied through REGISTRY_PATH. registry_loaded already
        # carries the signal, so the type is enough to act on.
        log.warning(
            "registry load failed from %s: %s", REGISTRY_PATH, e, exc_info=True
        )
        reg_err = type(e).__name__

    return {
        "runtime": {
            "version": APP_VERSION,
            "started_at": STARTED_AT,
            "uptime_seconds": round(time.time() - STARTED_AT),
            "loki_configured": bool(LOKI_URL),
            "loki_last_success": _last_loki_ok or None,
            "loki_last_error": _last_loki_error,
            "loki_last_read_truncated": _last_read_truncated,
            "lookback_hours": LOOKBACK_HOURS,
            "cache_ttl_seconds": CACHE_TTL,
            "auth_mode": ("login" if LOGIN_MODE and PORTAL_AUTH != "none"
                          else PORTAL_AUTH or "basic"),
            "auth_configured": bool(PORTAL_AUTH != "none"),
            "registry_loaded": reg_ok,
            "registry_tools": reg_tools,
            "registry_error": reg_err,
            "registry_path": REGISTRY_PATH,
            "identity_map_configured": bool(
                IDENTITY_MAP and Path(IDENTITY_MAP).exists()),
            "grafana_configured": bool(GRAFANA_URL),
            "grafana_panels": len([w for w in _widgets()
                                   if w["kind"] == "grafana"]),
            "overview_widgets": _widgets(),
        },
        # Passed in by whatever deployed this. The portal cannot check any of
        # it. Empty on a deployment that does not set it, rather than guessed.
        "deployment": {
            "chart_version": DEPLOY_CHART,
            "release": DEPLOY_RELEASE,
            "namespace": DEPLOY_NAMESPACE,
        },
    }


@app.get("/api/graph")
def graph(request: Request,
          hours: float = Query(default=None, gt=0, le=24 * 90),
          refresh: bool = Query(default=False),
          _=Depends(require_auth)):
    """refresh=true skips the cache. A cache you cannot see past is
    indistinguishable from a portal that is not working."""
    hours = hours or LOOKBACK_HOURS
    if refresh:
        _cache.pop("graph", None)
    def build():
        findings = _findings(hours, request)
        domain_map = derive.load_domain_map_from(_registry(request))
        identity_map = derive.load_identity_map(IDENTITY_MAP) if IDENTITY_MAP else {}
        return derive.graph_from(findings, domain_map, identity_map, hours)

    value, at = _cached("graph", hours, build)
    return JSONResponse(dict(value, derived_at=at, hours=hours,
                             findings_truncated=_last_read_truncated))


@app.get("/api/status")
def status(request: Request,
           hours: float = Query(default=None, gt=0, le=24 * 90),
           refresh: bool = Query(default=False),
           _=Depends(require_auth)):
    hours = hours or LOOKBACK_HOURS
    if refresh:
        _cache.pop("status", None)
    def build():
        return derive.status_from(_findings(hours, request))

    value, at = _cached("status", hours, build)
    return JSONResponse(dict(value, derived_at=at, hours=hours,
                             findings_truncated=_last_read_truncated))


@app.get("/api/evidence")
def evidence_snapshot(request: Request,
                      hours: float = Query(default=None, gt=0, le=24 * 90),
                      download: bool = Query(default=False),
                      _=Depends(require_auth)):
    """A checksummed statement of what the platform observed, for export.

    Generated on demand and not stored. Built from the same derivations the
    pages use, so a snapshot and the page it summarises cannot disagree: the
    same numbers from the same read, arranged for export.

    Not cached. A snapshot records a moment, and returning a cached one under a
    fresh generated_at would be a timestamp that lies about when the numbers
    were taken.
    """
    hours = hours or LOOKBACK_HOURS
    findings = _findings(hours, request)
    reg = _registry(request)
    domain_map = derive.load_domain_map_from(reg)
    gov, exceptions, _portal = _merged_governance(request)

    doc = evidence.evidence_from(
        derive.register_from(findings, reg, domain_map, gov, exceptions),
        derive.status_from(findings),
        derive.personal_accounts_from(findings, domain_map),
        derive.mcp_from(findings),
        paste_guard.paste_guard_from(findings, domain_map),
        registry_path=REGISTRY_PATH,
        governance_path=GOVERNANCE_PATH,
        app_version=APP_VERSION,
        hours=hours,
        findings_truncated=_last_read_truncated,
    )

    if download:
        stamp = time.strftime("%Y-%m-%dT%H%MZ", time.gmtime())
        window = ("%dh" % hours) if float(hours).is_integer() else ("%sh" % hours)
        name = "ai-guard-evidence-%s-%s.json" % (stamp, window)
        return PlainTextResponse(
            json.dumps(doc, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="%s"' % name},
        )
    return JSONResponse(doc)


@app.get("/api/paste-guard")
def paste_guard_events(request: Request,
                       hours: float = Query(default=None, gt=0, le=24 * 90),
                       refresh: bool = Query(default=False),
                       _=Depends(require_auth)):
    """Paste guard activity: what was stopped, on which tool, how often.

    Metadata only, and deliberately so. The guard inspects clipboard content on
    the device and reports detector identifiers; the matched text never reaches
    the receiver and must never reach here. portal/app/paste_guard.py has a
    test asserting that structurally rather than by review.

    The heartbeat shares this source and is excluded. It is how a device proves
    the guard works rather than merely being installed, and counting it as a
    detection would report every device's daily heartbeat as a paste somebody
    tried to make.
    """
    hours = hours or LOOKBACK_HOURS
    if refresh:
        _cache.pop("paste_guard", None)

    def build():
        findings = _findings(hours, request)
        reg = _registry(request)
        return paste_guard.paste_guard_from(
            findings, derive.load_domain_map_from(reg))

    value, at = _cached("paste_guard", hours, build)
    return JSONResponse(dict(value, derived_at=at, hours=hours))


@app.get("/api/register")
def register(request: Request,
             hours: float = Query(default=None, gt=0, le=24 * 90),
             fmt: str = Query(default="json", pattern="^(json|csv)$"),
             refresh: bool = Query(default=False),
             _=Depends(require_auth)):
    """The AI register: the AI tools actually in use, and what is known of them.

    Rows are the observed set. A register is a record of what an organisation
    uses, and padding it with every entry of a shipped registry makes it a
    worse record: it presents tools nobody there has heard of as things the
    organisation has a position on. The registry is a watchlist, and its size
    is returned as a count rather than as rows.

    A tool observed and absent from the registry is included and flagged. That
    is the anomaly worth acting on.

    Read-only and derived. The portal holds no governance state, so owner,
    review date and risk decision are absent rather than empty-but-editable.

    csv is a convenience export, not an evidence artifact, and it carries the
    same rows as the page. The filename carries when it was taken and over what
    window, because a register with no provenance is a screenshot with extra
    steps, and a filename survives being emailed around in a way a header
    comment does not.
    """
    hours = hours or LOOKBACK_HOURS
    if refresh:
        _cache.pop("register", None)

    # Fetched outside the cached build: the unmatched section below needs it
    # on every request, and in managed mode it carries the portal-recorded
    # decisions merged over the file.
    gov, exceptions, portal_decisions = _merged_governance(request)

    def build():
        findings = _findings(hours, request)
        reg = _registry(request)
        return derive.register_from(findings, reg,
                                    derive.load_domain_map_from(reg), gov,
                                    exceptions)

    all_rows, at = _cached("register", hours, build)
    # The register is what is in use. The rest of the join is the watchlist,
    # and it is reported as a count below rather than as rows.
    rows = [r for r in all_rows if r["observed"]]

    if fmt == "csv":
        stamp = time.strftime("%Y-%m-%dT%H%MZ", time.gmtime())
        window = ("%dh" % hours) if float(hours).is_integer() else ("%sh" % hours)
        name = "ai-register-%s-%s.csv" % (stamp, window)
        return PlainTextResponse(
            derive.register_csv(rows),
            headers={"Content-Disposition": 'attachment; filename="%s"' % name},
        )

    known = [t.get("id") for t in (
        _registry(request).get("tools") or [])]
    return JSONResponse({
        "rows": rows,
        "derived_at": at,
        "hours": hours,
        # A governance file, or at least one decision recorded in the
        # portal: either means somebody is deciding, and the "nothing is
        # configured" note would be false.
        "governance_configured": bool(GOVERNANCE_PATH) or portal_decisions > 0,
        "findings_truncated": _last_read_truncated,
        # Decisions naming a tool the registry does not know. Reported rather
        # than dropped: the likely cause is a typo, and a decision that
        # silently matches nothing is how an organisation believes it has
        # decided something it has not.
        "governance_unmatched": governance.unmatched(gov, known),
        # Exceptions naming a tool the registry does not know, same treatment
        # and for the same reason: usually a typo, and either way the exception
        # is applying to nothing.
        "exceptions_unmatched": governance.unmatched_exceptions(
            exceptions, known),
        "exceptions_active": sum(
            len(r.get("exceptions") or []) for r in rows),
        "exceptions_expired": sum(
            len(r.get("expired_exceptions") or []) for r in rows),
        # Both counts, deliberately. A register that reported only what it
        # found would let an estate with a silent source look complete.
        "tools_observed": len(rows),
        "tools_known": sum(1 for r in all_rows if r["in_registry"]),
        "observed_not_in_registry": sum(
            1 for r in rows if not r["in_registry"]),
        "known_not_observed": sum(
            1 for r in all_rows if r["in_registry"] and not r["observed"]),
    })


@app.get("/api/suggest-identities")
def suggest_identities(request: Request,
                       hours: float = Query(default=None, gt=0, le=24 * 90),
                       fmt: str = Query(default="json", pattern="^(json|csv)$"),
                       _=Depends(require_auth)):
    """Proposed device -> identity mappings, for review.

    The portal will not apply these itself. Identity resolution belongs to the
    deployer, against whatever they run, and a mapping this platform invented
    and then acted on is how the wrong name ends up on a report. Save the CSV,
    correct it, and point IDENTITY_MAP at it.
    """
    hours = hours or LOOKBACK_HOURS
    findings = _findings(hours, request)
    domain_map = derive.load_domain_map_from(_registry(request))
    devices, identities, _t, _b, _u = derive.build(findings, domain_map, {})
    matched, unmatched = derive.suggest_identity_rows(devices, identities)

    if fmt == "csv":
        return PlainTextResponse(
            derive.suggest_identity_csv(matched, unmatched),
            headers={"Content-Disposition":
                     'attachment; filename="identity-map.csv"'},
        )
    return JSONResponse({
        "matched": matched,
        "unmatched": unmatched,
        "identity_map_path": IDENTITY_MAP or None,
    })


# ----------------------------------------------------------- managed mode --
# The portal's write path, and it is deliberately a thin one: every route
# below forwards the operator's own session token to the receiver, which is
# the component that actually authorizes and records. The portal checks
# nothing but shape, stores nothing, and a portal database still does not
# exist: the session lives in the operator's browser (an HttpOnly cookie)
# and in the receiver's state DB, never here. Governance decisions remain
# in the file (docs/governance.md); these routes manage operational
# credentials, which is a different kind of thing.

# Receiver-assigned ids are hex, but the exact alphabet is the receiver's
# business; this guard only ensures a path segment cannot smuggle separators
# or dots into the URL built below.
_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _session_ok(token: str) -> bool:
    """Is this session live, by the receiver's word?

    The receiver owns sessions; the portal only asks. A yes is trusted for
    SESSION_CACHE_TTL so a page of API calls costs one validation rather
    than ten, which bounds revocation latency at a minute. A no is never
    cached, and a receiver that cannot be reached is a 502 rather than
    either answer: unreachable must not read as revoked, and it must
    certainly not read as valid.
    """
    now = time.time()
    hit = _session_cache.get(token)
    if hit and hit[0] > now:
        return True
    try:
        who = managed.receiver_request(RECEIVER_URL, "GET", "/admin/session",
                                       token)
    except managed.ReceiverError as e:
        if e.status == 502:
            log.warning("receiver call failed for %s: %s",
                        _redact_url(RECEIVER_URL), e.detail)
            raise HTTPException(
                502, "could not reach the receiver to validate the session")
        return False
    if len(_session_cache) > 512:
        # The cache is per live session and sessions expire in hours, so
        # growth past this is garbage from old logins; sweep it.
        for k in [k for k, v in _session_cache.items() if v[0] <= now]:
            _session_cache.pop(k, None)
    _session_cache[token] = (now + SESSION_CACHE_TTL,
                             str(who.get("username", "")),
                             str(who.get("role", "admin")))
    return True


def _cookie_secure(request: Request) -> bool:
    """Whether the session cookie should carry Secure.

    Judged from how the login actually arrived: direct TLS, or a TLS
    ingress saying so in X-Forwarded-Proto. A hard-coded True would break
    the documented localhost and plain-HTTP-behind-a-proxy paths silently -
    the cookie would simply never come back.
    """
    return (request.url.scheme == "https"
            or request.headers.get("x-forwarded-proto", "") == "https")


def _login_mode_only():
    if not LOGIN_MODE:
        # Classic portals have no login; the route should not advertise one.
        raise HTTPException(404, "Not Found")


def _session_response(out: dict, request: Request) -> JSONResponse:
    """The logged-in answer: session details for the page, token in an
    HttpOnly cookie the page can never read. SameSite=Strict plus the
    JSON-only rule on POSTs (middleware below) is the CSRF story."""
    resp = JSONResponse({"ok": True,
                         "username": str(out.get("username", "")),
                         "expires_at": out.get("expires_at")})
    resp.set_cookie(SESSION_COOKIE, str(out.get("token", "")),
                    httponly=True, samesite="strict",
                    secure=_cookie_secure(request), path="/")
    return resp


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class SetupRequest(BaseModel):
    setup_code: str = Field(min_length=1, max_length=128)
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=12, max_length=256)


@app.get("/api/auth")
def auth_state(request: Request):
    """What the login screen needs before anyone has authenticated.

    Unauthenticated on purpose, and it says nothing about the estate: the
    mode, whether this browser holds a live session, who that is, and
    whether the receiver is still waiting for its first admin account (so
    the page can honestly offer create-account instead of sign-in).
    """
    if not LOGIN_MODE:
        return {"mode": PORTAL_AUTH or "basic", "authenticated": None,
                "username": "", "setup_needed": False}
    token = request.cookies.get(SESSION_COOKIE, "")
    authenticated = bool(token) and _session_ok(token)
    setup_needed = False
    if not authenticated:
        try:
            setup_needed = bool(managed.receiver_request(
                RECEIVER_URL, "GET", "/admin/setup", "").get("needed"))
        except managed.ReceiverError as e:
            # A login screen that cannot say whether an account exists should
            # say why, not guess a form.
            raise HTTPException(e.status, e.detail)
    hit = _session_cache.get(token) or (0, "", "admin")
    return {"mode": "login" if PORTAL_AUTH != "none" else "none",
            "authenticated": authenticated,
            "username": hit[1],
            "role": hit[2] if authenticated else "",
            "setup_needed": setup_needed}


@app.post("/api/login")
def api_login(req: LoginRequest, request: Request):
    _login_mode_only()
    out = _receiver("POST", "/admin/login", "",
                    {"username": req.username, "password": req.password})
    return _session_response(out, request)


@app.post("/api/setup")
def api_setup(req: SetupRequest, request: Request):
    """First boot: claim the receiver's boot-printed setup code, create the
    admin account, and arrive signed in - the receiver returns a session."""
    _login_mode_only()
    out = _receiver("POST", "/admin/setup",  "",
                    {"setup_code": req.setup_code, "username": req.username,
                     "password": req.password})
    return _session_response(out, request)


@app.post("/api/logout")
def api_logout(request: Request):
    _login_mode_only()
    token = request.cookies.get(SESSION_COOKIE, "")
    _session_cache.pop(token, None)
    if token:
        try:
            managed.receiver_request(RECEIVER_URL, "POST", "/admin/logout",
                                     token)
        except managed.ReceiverError:
            # The cookie dies either way; a receiver hiccup must not trap
            # someone in a session they asked to leave. The receiver-side
            # session then simply expires on its own TTL.
            pass
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


def _merged_governance(request: Request):
    """(gov, exceptions, portal_decisions) - the effective governance.

    The file as ever, plus, in managed mode, the decisions recorded in the
    portal: merged per tool with the DB record winning and the file filling
    the gaps, the same DB-wins-when-set rule every setting follows. Each DB
    record carries origin "portal" so the register can label which kind of
    decision it shows. Exceptions stay file-only on purpose.

    A receiver that cannot answer is an error, not a silent fall-back to
    the file: showing yesterday's decisions as if they were current is the
    kind of quiet wrongness this project exists to avoid.
    """
    gov, exceptions = governance.load_governance(GOVERNANCE_PATH)
    portal_count = 0
    if LOGIN_MODE:
        token = request.cookies.get(SESSION_COOKIE, "")
        try:
            out = managed.receiver_request(
                RECEIVER_URL, "GET", "/admin/governance", token)
        except managed.ReceiverError as e:
            if e.status == 502:
                log.warning("receiver call failed for %s: %s",
                            _redact_url(RECEIVER_URL), e.detail)
            raise HTTPException(
                e.status, "could not read governance decisions from the "
                          "receiver (%s)" % e.detail)
        db = {}
        for d in out.get("decisions", []):
            db[str(d.get("tool_id"))] = {
                "status": str(d.get("status") or ""),
                "owner": str(d.get("owner") or ""),
                "review_due": governance._parse_date(d.get("review_due")),
                "reason": str(d.get("reason") or ""),
                "origin": "portal",
            }
        portal_count = len(db)
        gov = {**gov, **db}
    return gov, exceptions, portal_count


def _admin_forward(request: Request) -> str:
    """The operator's session, bound for the receiver's admin API.

    The receiver authorizes; the portal only carries. Nothing here checks
    the session first - the receiver's own answer comes back through the
    proxy, and checking twice would just be a second place to be wrong.
    """
    if not RECEIVER_URL:
        raise HTTPException(
            503, "RECEIVER_URL is not set. Managed mode needs the portal to "
                 "reach the receiver's admin API; see the portal README.")
    token = request.cookies.get(SESSION_COOKIE, "")
    if not token:
        raise HTTPException(
            401, "login required: managed actions use your portal session, "
                 "forwarded to the receiver per request and never stored.")
    return token


def _receiver(method: str, path: str, token: str, body: dict | None = None):
    try:
        return managed.receiver_request(RECEIVER_URL, method, path, token, body)
    except managed.ReceiverError as e:
        if e.status == 502:
            log.warning("receiver call failed for %s: %s",
                        _redact_url(RECEIVER_URL), e.detail)
        raise HTTPException(e.status, e.detail)


@app.get("/api/fleet")
def fleet(_=Depends(require_auth), token: str = Depends(_admin_forward)):
    """The enrolled devices, from the receiver's registry - who exists,
    rather than who has spoken lately, which is what /api/graph derives."""
    return _receiver("GET", "/admin/devices", token)


@app.get("/api/enrollment-tokens")
def enrollment_tokens(_=Depends(require_auth), token: str = Depends(_admin_forward)):
    return _receiver("GET", "/admin/enrollment-tokens", token)


class MintRequest(BaseModel):
    note: str = Field(default="", max_length=200)
    ttl_days: int = Field(default=180, ge=1, le=3650)


@app.post("/api/enrollment-tokens")
def mint_enrollment_token(req: MintRequest, _=Depends(require_auth),
                          token: str = Depends(_admin_forward)):
    """Mint via the receiver. The response carries the plaintext exactly
    once, which is the receiver's contract; the UI shows it once and the
    portal remembers nothing."""
    return _receiver("POST", "/admin/enrollment-tokens", token,
                     {"note": req.note, "ttl_days": req.ttl_days})


@app.post("/api/enrollment-tokens/{tid}/revoke")
def revoke_enrollment_token(tid: str, _=Depends(require_auth),
                            token: str = Depends(_admin_forward)):
    if not _ID_RE.match(tid):
        raise HTTPException(422, "malformed token id")
    return _receiver("POST", "/admin/enrollment-tokens/%s/revoke" % tid, token)


@app.post("/api/devices/{did}/revoke")
def revoke_device(did: str, _=Depends(require_auth),
                  token: str = Depends(_admin_forward)):
    if not _ID_RE.match(did):
        raise HTTPException(422, "malformed device id")
    return _receiver("POST", "/admin/devices/%s/revoke" % did, token)


# Settings and governance writes. POST rather than PUT on the portal side,
# because the CSRF rule (JSON-only POSTs) is what protects cookie-carried
# writes and widening it to more methods is more surface than one verb
# buys; the receiver side keeps its PUT.


class SettingsWrite(BaseModel):
    # extra=forbid, same as the receiver: an unknown key here would be
    # silently dropped from model_fields_set and someone would believe a
    # setting took effect. The receiver revalidates (URL shapes included);
    # this model only mirrors the keys and bounds.
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
    extension_xpi_url: str | None = Field(default=None, max_length=500)
    paste_guard_mode: str | None = Field(default=None, max_length=8)
    firefox_extension_id: str | None = Field(default=None, max_length=128)
    classification_markings: list[str] | None = Field(default=None,
                                                      max_length=50)


class DecisionWrite(BaseModel):
    model_config = {"extra": "forbid"}
    tool_id: str = Field(min_length=1, max_length=100)
    status: str = Field(min_length=1, max_length=32)
    owner: str = Field(default="", max_length=200)
    review_due: str = Field(default="", max_length=10)
    reason: str = Field(default="", max_length=1000)


class GovernanceWrite(BaseModel):
    model_config = {"extra": "forbid"}
    decisions: list[DecisionWrite] = Field(default_factory=list, max_length=200)
    delete: list[str] = Field(default_factory=list, max_length=200)


class PasswordWrite(BaseModel):
    current: str = Field(default="", max_length=256)
    new: str = Field(min_length=12, max_length=256)


@app.get("/api/settings")
def api_settings(_=Depends(require_auth), token: str = Depends(_admin_forward)):
    return _receiver("GET", "/admin/settings", token)


@app.post("/api/settings")
def api_settings_write(req: SettingsWrite, _=Depends(require_auth),
                       token: str = Depends(_admin_forward)):
    """Forward exactly the keys that were sent - a null deletes (fall back
    to env), an absent key is untouched - and the receiver validates and
    answers with the fresh effective view."""
    body = {k: getattr(req, k) for k in req.model_fields_set}
    out = _receiver("PUT", "/admin/settings", token, body)
    # The portal's cached views of these settings are now stale - a saved
    # log store must be read from on the very next page, not in 30s.
    _invalidate_settings_caches()
    return out


class FindingStatusWrite(BaseModel):
    model_config = {"extra": "forbid"}
    key: str = Field(min_length=1, max_length=500)
    # Empty status means clear: back to open.
    status: str = Field(default="", max_length=16)
    reason: str = Field(default="", max_length=500)


@app.get("/api/finding-status")
def api_finding_status(_=Depends(require_auth),
                       token: str = Depends(_admin_forward)):
    """The recorded answers to derived findings (acknowledged / accepted).
    The findings themselves come from /api/graph; the receiver holds only
    the human's response, keyed on a string the portal composes."""
    return _receiver("GET", "/admin/finding-status", token)


@app.post("/api/finding-status")
def api_finding_status_write(req: FindingStatusWrite, _=Depends(require_auth),
                             token: str = Depends(_admin_forward)):
    if not req.status:
        return _receiver("POST", "/admin/finding-status/clear", token,
                         {"key": req.key})
    return _receiver("PUT", "/admin/finding-status", token,
                     {"key": req.key, "status": req.status,
                      "reason": req.reason})


@app.get("/api/audit")
def api_audit(limit: int = Query(default=200, ge=1, le=1000),
              _=Depends(require_auth), token: str = Depends(_admin_forward)):
    """The receiver's admin activity trail, relayed as-is."""
    return _receiver("GET", "/admin/events?limit=%d" % limit, token)


class UserCreate(BaseModel):
    model_config = {"extra": "forbid"}
    username: str = Field(min_length=2, max_length=64)
    password: str = Field(min_length=12, max_length=256)
    role: str = Field(min_length=1, max_length=16)


class UserPasswordReset(BaseModel):
    model_config = {"extra": "forbid"}
    new: str = Field(min_length=12, max_length=256)


_UID_RE = re.compile(r"^[0-9a-f]{16}$")


@app.get("/api/users")
def api_users(_=Depends(require_auth), token: str = Depends(_admin_forward)):
    """The accounts, admin and viewer alike. The receiver owns them; the
    portal relays, and the receiver's role gate decides who may change
    what."""
    return _receiver("GET", "/admin/users", token)


@app.post("/api/users")
def api_users_create(req: UserCreate, _=Depends(require_auth),
                     token: str = Depends(_admin_forward)):
    return _receiver("POST", "/admin/users", token, req.model_dump())


@app.post("/api/users/{uid}/delete")
def api_users_delete(uid: str, _=Depends(require_auth),
                     token: str = Depends(_admin_forward)):
    if not _UID_RE.match(uid):
        raise HTTPException(422, "malformed user id")
    return _receiver("POST", "/admin/users/%s/delete" % uid, token)


@app.post("/api/users/{uid}/password")
def api_users_reset(uid: str, req: UserPasswordReset, _=Depends(require_auth),
                    token: str = Depends(_admin_forward)):
    if not _UID_RE.match(uid):
        raise HTTPException(422, "malformed user id")
    return _receiver("POST", "/admin/users/%s/password" % uid, token,
                     req.model_dump())


# ---------------------------------------------------------------- digest ---
# A weekly summary to a Slack-compatible webhook: the portal is a page
# somebody must remember to open, and the digest is what keeps the estate
# in front of them when they do not. Env-driven, because the task runs with
# no operator session to read portal-saved settings with - the receiver's
# own webhook_url setting covers the event-shaped notifications (a new
# discovery candidate) instead.
#
# The task reads findings either from the env log store (LOKI_URL), or -
# the managed-by-default path, where the log store was saved through the
# wizard - via RECEIVER_ADMIN_TOKEN: the receiver's ADMIN_TOKEN credential,
# which lets the background task read the saved log-store settings the way
# a session would. Without either it declines at startup and says why,
# rather than mailing a digest of an empty estate.
DIGEST_WEBHOOK_URL = require_http_url(
    "DIGEST_WEBHOOK_URL", os.environ.get("DIGEST_WEBHOOK_URL", ""))
RECEIVER_ADMIN_TOKEN = _secret("RECEIVER_ADMIN_TOKEN")
_DIGEST_DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
# `or` rather than a default arg: compose passes empty strings for unset
# variables, and int("") is a crash at startup rather than a default.
DIGEST_DAY = (os.environ.get("DIGEST_DAY") or "mon").lower()[:3]
DIGEST_HOUR = min(23, max(0, int(os.environ.get("DIGEST_HOUR") or "8")))


def next_digest(after, day=DIGEST_DAY, hour=DIGEST_HOUR):
    """The next scheduled send strictly after `after` (UTC). Restart-safe by
    construction: there is no cursor to lose, just the next slot."""
    target = _DIGEST_DAYS.index(day if day in _DIGEST_DAYS else "mon")
    cand = after.replace(hour=hour, minute=0, second=0, microsecond=0)
    while cand <= after or cand.weekday() != target:
        cand += timedelta(days=1)
    return cand


def digest_text(g, s, hours):
    """The digest body, from the same derivations every page reads.

    Slack mrkdwn, and deliberately short: the digest's job is to say
    whether the estate needs someone this week, not to be the report.
    """
    pa = g.get("personal_accounts") or []
    people = {r.get("user") or r.get("device")
              for r in pa if r.get("user") or r.get("device")}
    counts = g.get("counts") or {}
    silent = [r for grp in (s or {}).get("groups", [])
              for r in grp.get("sources", []) if not r.get("reporting")]
    top = sorted(((k, len(v.get("devices") or []))
                  for k, v in (g.get("tools") or {}).items()),
                 key=lambda kv: (-kv[1], kv[0]))[:5]
    n = len(pa)
    lines = ["*ai-guard: the last %d days*" % round(hours / 24),
             "• %d personal account%s across %d %s"
             % (n, "" if n == 1 else "s", len(people),
                "person" if len(people) == 1 else "people"),
             "• %d tools in use on %d devices"
             % (counts.get("tools", 0), counts.get("devices", 0))]
    if top:
        lines.append("• top tools: "
                     + ", ".join("%s (%d)" % t for t in top))
    if silent:
        lines.append("• %d detection source%s silent"
                     % (len(silent), "" if len(silent) == 1 else "s"))
    return "\n".join(lines)


@app.on_event("startup")
async def _digest_task():
    if not DIGEST_WEBHOOK_URL:
        return
    if LOGIN_MODE and not LOKI_URL and not RECEIVER_ADMIN_TOKEN:
        log.warning("DIGEST_WEBHOOK_URL is set but the background task has "
                    "no way to read findings: set RECEIVER_ADMIN_TOKEN (the "
                    "receiver's ADMIN_TOKEN) so it can use the log store "
                    "saved in the portal, or set LOKI_URL directly. No "
                    "digest will be sent.")
        return
    import asyncio

    def send():
        findings = _findings(LOOKBACK_HOURS, None)
        domain_map = derive.load_domain_map_from(_registry(None))
        g = derive.graph_from(findings, domain_map, {}, LOOKBACK_HOURS)
        s = derive.status_from(findings)
        body = json.dumps({"text": digest_text(g, s, LOOKBACK_HOURS)}).encode()
        req = urllib.request.Request(
            DIGEST_WEBHOOK_URL, data=body,
            headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10).read()

    async def loop():
        while True:
            now = datetime.now(timezone.utc)
            await asyncio.sleep(
                max(60.0, (next_digest(now) - now).total_seconds()))
            try:
                await asyncio.to_thread(send)
                log.info("weekly digest sent")
            except Exception as e:  # noqa: BLE001 - the log line is the story
                log.warning("weekly digest failed: %s", e)

    asyncio.get_running_loop().create_task(loop())


@app.get("/api/governance-decisions")
def api_governance(_=Depends(require_auth), token: str = Depends(_admin_forward)):
    return _receiver("GET", "/admin/governance", token)


@app.post("/api/governance-decisions")
def api_governance_write(req: GovernanceWrite, _=Depends(require_auth),
                         token: str = Depends(_admin_forward)):
    out = _receiver("PUT", "/admin/governance", token, req.model_dump())
    # The register is derived with governance folded in and cached for
    # CACHE_TTL; a decision just changed, so that cache is now a view of
    # the world before the operator acted.
    _cache.pop("register", None)
    return out


@app.post("/api/test/receiver-url")
def test_receiver_url(_=Depends(require_auth),
                      token: str = Depends(_admin_forward)):
    """Probe the EFFECTIVE public receiver URL - the saved setting, else
    the deployment's env value - before an artifact bakes it.

    Server-side on purpose: the browser's CSP keeps it on 'self', and the
    point is to catch the URL that LOOKS right in a browser on this machine
    and resolves nowhere else. Deliberately not a requester-supplied URL,
    matching the log-store tests: save first, then probe what was saved.
    That is one more click in the wizard and one fewer route that fetches
    whatever the request names.
    """
    import urllib.request as _urlreq

    stored = _receiver("GET", "/admin/settings", token).get("settings", {})
    url = (((stored.get("receiver_public_url") or {}).get("value")
            or RECEIVER_PUBLIC_URL) or "").strip().rstrip("/")
    if not url:
        raise HTTPException(
            400, "no public receiver URL to probe: save one in Settings "
                 "first (or set RECEIVER_PUBLIC_URL)")
    if not url.startswith(("http://", "https://")):
        raise HTTPException(422, "the URL must be http:// or https://")
    warnings = []
    host = urllib.parse.urlsplit(url).hostname or ""
    if "." not in host:
        warnings.append(
            "the host has no dot: machines other than this one cannot "
            "resolve a short name. On Tailscale use the full .ts.net "
            "address, not the ingress short name.")
    try:
        with _urlreq.urlopen(url + "/healthz", timeout=5) as resp:
            body = json.loads(resp.read() or b"{}")
    except Exception as e:
        # This probe runs from the portal's own pod, which is a different
        # network from the endpoints the URL is FOR. A URL only reachable
        # over a VPN or tailnet (a .ts.net name, say) can be exactly right
        # and still fail here - the pod cannot even resolve it. Say so,
        # and name the check that actually settles it.
        return {"ok": False, "warnings": warnings,
                "detail": "could not reach %s/healthz from inside the "
                          "cluster (%s). That can be normal: if the URL is "
                          "only reachable from your endpoints' network (a "
                          "VPN or tailnet), confirm from one of those "
                          "machines instead - curl %s/healthz - and if it "
                          "answers, the saved URL is right and this result "
                          "can be ignored."
                          % (_redact_url(url), type(e).__name__,
                             _redact_url(url))}
    if not body.get("ok"):
        return {"ok": False, "warnings": warnings,
                "detail": "%s answered, but not like an ai-guard receiver"
                          % _redact_url(url)}
    return {"ok": True, "warnings": warnings,
            "version": str(body.get("version", ""))}


@app.post("/api/test/log-store-read")
def test_log_store_read(request: Request, _=Depends(require_auth)):
    """One tiny query with the effective read configuration: can the portal
    get findings back out? The other half of the receiver's push test -
    together they catch the write-only-token trap during setup instead of
    on the first quiet dashboard."""
    url, username, password, source = _log_store(request)
    if not url:
        raise HTTPException(
            400, "no log store is configured: save its base URL in "
                 "Settings, or set LOKI_URL")
    try:
        derive.fetch_from_loki(url, 1, LOKI_TOKEN if source == "env" else None,
                               limit=1, username=username or None,
                               password=password or None)
    except Exception as e:
        out = {"ok": False, "url": _redact_url(url),
               "detail": "read failed (%s)" % type(e).__name__}
        code = getattr(e, "code", None)
        if code in (401, 403):
            out["hint"] = ("the credentials are wrong or lack read access; "
                           "on Grafana Cloud the token needs logs:read as "
                           "well as logs:write")
        return out
    return {"ok": True, "url": _redact_url(url)}


@app.post("/api/test/log-store-push")
def test_log_store_push(_=Depends(require_auth),
                        token: str = Depends(_admin_forward)):
    """The receiver pushes one synthetic line with ITS effective config
    and reports what happened, hints included."""
    return _receiver("POST", "/admin/test/log-store-push", token)


def _fetch_hosted(url: str, cap: int):
    """(status, content-type, first `cap` bytes) of a saved hosting URL.

    Server-side like the receiver-url probe, and reading at most `cap`
    bytes: the .xpi check needs the file, but a probe must not be a way to
    pull something huge through the portal pod.
    """
    import urllib.request as _urlreq

    req = _urlreq.Request(url, headers={"User-Agent": "ai-guard-portal"})
    with _urlreq.urlopen(req, timeout=10) as resp:
        return (resp.status, resp.headers.get("Content-Type", ""),
                resp.read(cap))


_HOSTING_CAVEAT = ("could not reach %s from inside the cluster (%s). These "
                   "files must be reachable by every browser in the fleet, "
                   "so unlike the receiver probe this usually IS a problem - "
                   "but if your artifact host is only visible from the "
                   "corporate network, confirm from a fleet machine instead.")


@app.post("/api/test/extension-updates")
def test_extension_updates(_=Depends(require_auth),
                           token: str = Depends(_admin_forward)):
    """Fetch the saved Chromium update manifest URL and check it against
    the saved extension id: the failure this catches is a hosted file that
    answers 200 and quietly describes some other id or version, which
    browsers treat as 'no update for you', forever."""
    stored = _receiver("GET", "/admin/settings", token).get("settings", {})
    url = ((stored.get("extension_update_url") or {}).get("value") or "").strip()
    if not url:
        raise HTTPException(
            400, "no update manifest URL to probe: save one first")
    try:
        status, ctype, body = _fetch_hosted(url, 64 * 1024)
    except Exception as e:
        return {"ok": False,
                "detail": _HOSTING_CAVEAT % (_redact_url(url),
                                             type(e).__name__)}
    warnings = []
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(body.decode("utf-8", "replace"))
        ns = "{http://www.google.com/update2/response}"
        apps = root.findall(ns + "app") or root.findall("app")
        appids = [a.get("appid", "") for a in apps]
        saved_id = ((stored.get("extension_id") or {}).get("value") or "")
        if saved_id and saved_id not in appids:
            return {"ok": False, "url": url,
                    "detail": "the hosted manifest describes %s, not the "
                              "saved extension id - browsers pointed at it "
                              "will never install or update this extension"
                              % (", ".join(appids) or "no extension")}
        checks = [u for a in apps
                  for u in a.findall(ns + "updatecheck") + a.findall("updatecheck")]
        versions = sorted({c.get("version", "?") for c in checks})
        try:
            bundled = managed.extension_version(EXTENSION_SRC_DIR)
            if bundled not in versions:
                warnings.append(
                    "the hosted manifest says version %s; the source this "
                    "portal serves is %s. Fine if you packed a different "
                    "version on purpose."
                    % (", ".join(versions) or "?", bundled))
        except managed.ArtifactError:
            pass
    except ET.ParseError:
        return {"ok": False, "url": url,
                "detail": "%s answered, but not with XML an update manifest "
                          "could parse as" % _redact_url(url)}
    return {"ok": True, "url": url, "warnings": warnings,
            "detail": "the hosted manifest matches the saved extension id"}


@app.post("/api/test/extension-xpi")
def test_extension_xpi(_=Depends(require_auth),
                       token: str = Depends(_admin_forward)):
    """Fetch the saved .xpi URL and check it is the SIGNED file.

    The trap this exists for: hosting the .xpi you built instead of the one
    AMO returned. Both are valid zips, both download fine, and Firefox
    refuses one of them on every machine in the fleet. A signed .xpi
    contains META-INF/mozilla.rsa; an unsigned one does not."""
    import io
    import zipfile

    stored = _receiver("GET", "/admin/settings", token).get("settings", {})
    url = ((stored.get("extension_xpi_url") or {}).get("value") or "").strip()
    if not url:
        raise HTTPException(400, "no signed .xpi URL to probe: save one first")
    try:
        status, ctype, body = _fetch_hosted(url, 32 * 1024 * 1024)
    except Exception as e:
        return {"ok": False,
                "detail": _HOSTING_CAVEAT % (_redact_url(url),
                                             type(e).__name__)}
    warnings = []
    if ctype and "xpinstall" not in ctype and "octet-stream" not in ctype:
        warnings.append(
            "served as %s; Firefox expects application/x-xpinstall "
            "(some hosts need the content type set per file)" % ctype)
    try:
        names = zipfile.ZipFile(io.BytesIO(body)).namelist()
    except zipfile.BadZipFile:
        return {"ok": False, "url": url,
                "detail": "%s answered, but the file is not a zip (an .xpi "
                          "is one), or is larger than this probe reads"
                          % _redact_url(url)}
    if "META-INF/mozilla.rsa" not in names:
        return {"ok": False, "url": url,
                "detail": "the hosted .xpi is not Mozilla-signed (no "
                          "META-INF/mozilla.rsa) - this is your own build; "
                          "Firefox will refuse it. Host the file AMO "
                          "returned after signing."}
    return {"ok": True, "url": url, "warnings": warnings,
            "detail": "the hosted .xpi is Mozilla-signed"}


@app.post("/api/password")
def api_password(req: PasswordWrite, _=Depends(require_auth),
                 token: str = Depends(_admin_forward)):
    """The receiver enforces the rules (current password on the session
    path, other sessions revoked); this session survives because it is the
    bearer of the request."""
    return _receiver("POST", "/admin/password",  token,
                     {"current": req.current, "new": req.new})


# Artifacts generated from templates rather than substituted into script
# copies. Same minting and download shape as the collector kinds.
GENERATED_ARTIFACTS = ("extension-policy", "extension-windows",
                       "firefox-policy", "firefox-windows",
                       "scanner-cronjob", "discovery-cronjob",
                       "extension-source", "extension-updates-xml",
                       "firefox-updates-json")

# The extension-hosting downloads carry no credential - the source zip and
# the update manifests bake URLs and ids, never a token - so generating one
# must not mint. A minted-but-unused token in the list reads as a rollout
# that never happened.
TOKENLESS_ARTIFACTS = ("extension-source", "extension-updates-xml",
                       "firefox-updates-json")


@app.post("/api/artifacts/{kind}")
def artifact(kind: str, _=Depends(require_auth),
             token: str = Depends(_admin_forward)):
    """A pre-configured deployment artifact, with a fresh enrollment token.

    POST, not GET, because generating one mints: each download gets its own
    token, noted with the artifact kind, so the tokens list shows where
    every credential went and any single artifact can be revoked without
    touching the others. For the collector scripts, values are baked as the
    scripts' own fallback defaults, so MDM-supplied parameters still win,
    and corporate domains are not baked - the receiver serves those at
    runtime. The extension policy is the exception: the extension reads no
    central config, so its policy bakes the domains and needs regenerating
    when they change (the file's header says so).
    """
    if kind not in managed.ARTIFACTS and kind not in GENERATED_ARTIFACTS:
        raise HTTPException(404, "no such artifact")

    # Settings first: the wizard-saved receiver public URL wins over the
    # deployment's env value, same as every setting. Fetched before minting,
    # so a refusal does not leave a token dangling behind an artifact that
    # never existed.
    stored = _receiver("GET", "/admin/settings", token).get("settings", {})
    public_url = ((stored.get("receiver_public_url") or {}).get("value")
                  or RECEIVER_PUBLIC_URL)
    if not public_url:
        raise HTTPException(
            503, "no public receiver URL is set. Artifacts bake the ingest "
                 "URL agents reach from outside; save it in Settings (or "
                 "set RECEIVER_PUBLIC_URL). It is not the portal's internal "
                 "RECEIVER_URL; see the portal README.")

    def setting(key):
        return (stored.get(key) or {}).get("value") or ""

    if kind in TOKENLESS_ARTIFACTS:
        try:
            if kind == "extension-source":
                filename, content = managed.generate_extension_source(
                    EXTENSION_SRC_DIR, public_url)
                return Response(content, media_type="application/zip",
                                headers={"Content-Disposition":
                                         'attachment; filename="%s"' % filename})
            if kind == "extension-updates-xml":
                if not setting("extension_id"):
                    raise HTTPException(
                        409, "set the extension ID in Settings first: the "
                             "update manifest is keyed on it")
                if not setting("extension_crx_url"):
                    raise HTTPException(
                        409, "set the packed .crx URL in Settings first: "
                             "the update manifest points browsers at it")
                filename, content = managed.generate_updates_xml(
                    setting("extension_id"), setting("extension_crx_url"),
                    managed.extension_version(EXTENSION_SRC_DIR))
            else:
                if not setting("firefox_extension_id"):
                    raise HTTPException(
                        409, "set the Firefox extension ID (the gecko id) "
                             "in Settings first: the update manifest is "
                             "keyed on it")
                if not setting("extension_xpi_url"):
                    raise HTTPException(
                        409, "set the signed .xpi URL in Settings first: "
                             "the update manifest points Firefox at it")
                filename, content = managed.generate_firefox_updates_json(
                    setting("firefox_extension_id"),
                    setting("extension_xpi_url"),
                    managed.extension_version(EXTENSION_SRC_DIR))
        except managed.ArtifactError as e:
            raise HTTPException(500, str(e))
        return PlainTextResponse(content, headers={
            "Content-Disposition": 'attachment; filename="%s"' % filename})

    extension_kinds = ("extension-policy", "extension-windows",
                       "firefox-policy", "firefox-windows")
    extension_id = corp_domains = mode = markings = None
    if kind in extension_kinds:
        corp_domains = setting("corp_domains") or []
        mode = setting("paste_guard_mode") or "warn"
        # value may be a stored empty list (a real choice: no markings);
        # only an absent setting falls back to the default set.
        raw = stored.get("classification_markings") or {}
        markings = raw.get("value") if raw.get("source") == "db" else None
        if kind in ("extension-policy", "extension-windows"):
            extension_id = setting("extension_id")
            if not extension_id:
                raise HTTPException(
                    409, "set the extension ID in Settings first: the "
                         "policy is keyed on it")
        else:
            extension_id = setting("firefox_extension_id")
            if not extension_id:
                raise HTTPException(
                    409, "set the Firefox extension ID (the gecko id) in "
                         "Settings first: Firefox policy is keyed on it")
        if kind == "extension-windows" and not setting("extension_update_url"):
            raise HTTPException(
                409, "set the extension update URL in Settings first: "
                     "Windows installs the extension from it")
        if kind in ("firefox-policy", "firefox-windows") \
                and not setting("extension_xpi_url"):
            raise HTTPException(
                409, "set the signed .xpi URL in Settings first: Firefox "
                     "installs only the Mozilla-signed file, from that URL")

    minted = _receiver("POST", "/admin/enrollment-tokens", token,
                       {"note": "portal artifact: %s" % kind})
    try:
        if kind == "extension-policy":
            filename, content = managed.generate_extension_policy(
                extension_id, public_url, minted["token"],
                corp_domains, mode, markings)
        elif kind == "extension-windows":
            filename, content = managed.generate_extension_windows(
                COLLECTOR_SCRIPTS_DIR, extension_id,
                setting("extension_update_url"), public_url,
                minted["token"], corp_domains, mode, markings)
        elif kind == "firefox-policy":
            filename, content = managed.generate_firefox_policy(
                extension_id, setting("extension_xpi_url"), public_url,
                minted["token"], corp_domains, mode, markings)
        elif kind == "firefox-windows":
            filename, content = managed.generate_firefox_windows(
                COLLECTOR_SCRIPTS_DIR, extension_id,
                setting("extension_xpi_url"), public_url,
                minted["token"], corp_domains, mode, markings)
        elif kind == "scanner-cronjob":
            # A release build's version is the image tag on ghcr; a dev
            # build has no matching image, and "latest" is the honest
            # nearest thing.
            tag = APP_VERSION if APP_VERSION[:1].isdigit() else "latest"
            filename, content = managed.generate_scanner_cronjob(
                public_url, minted["token"], tag)
        elif kind == "discovery-cronjob":
            tag = APP_VERSION if APP_VERSION[:1].isdigit() else "latest"
            filename, content = managed.generate_discovery_cronjob(
                public_url, minted["token"], tag)
        else:
            filename, content = managed.generate(
                kind, COLLECTOR_SCRIPTS_DIR, public_url,
                minted["token"])
    except managed.ArtifactError as e:
        # The token is already minted; say which one so it can be revoked
        # rather than left dangling behind a failed download.
        raise HTTPException(500, "%s (enrollment token %s was minted for "
                                 "this artifact and can be revoked)"
                                 % (e, minted.get("id", "?")))
    return PlainTextResponse(content, headers={
        "Content-Disposition": 'attachment; filename="%s"' % filename,
        "X-Enrollment-Token-Id": minted.get("id", ""),
    })


@app.get("/api/registry-tools")
def registry_tools(request: Request, _=Depends(require_auth)):
    """The registry watchlist, id and name only, portal-defined entries
    included and labelled.

    For the wizard's governance baseline and the register's watchlist:
    unlike /api/register it needs no findings and no log store, because a
    fresh install has neither and the baseline is exactly the thing you
    record before anything reports.
    """
    reg = _registry(request)
    return {"tools": [
        {"id": t["id"], "name": t.get("name") or t["id"],
         "vendor": t.get("vendor") or "", "approved": bool(t.get("approved")),
         "custom": t.get("added_by") == "portal"}
        for t in (reg.get("tools") or []) if t.get("id")]}


class RegistryEntriesWrite(BaseModel):
    model_config = {"extra": "forbid"}
    entries: list[dict] = Field(default_factory=list, max_length=100)
    delete: list[str] = Field(default_factory=list, max_length=100)


@app.get("/api/registry-entries")
def api_registry_entries(_=Depends(require_auth),
                         token: str = Depends(_admin_forward)):
    return _receiver("GET", "/admin/registry-entries", token)


@app.post("/api/registry-entries")
def api_registry_entries_write(req: RegistryEntriesWrite,
                               _=Depends(require_auth),
                               token: str = Depends(_admin_forward)):
    """Forward to the receiver, which owns validation (the registry's own
    schema and rules), then drop every derived cache: the registry feeds
    the domain maps, so the graph, the register and their kin are all
    views of the world before this write."""
    out = _receiver("PUT", "/admin/registry-entries", token, req.model_dump())
    _registry_entries_cache.update(at=0.0, data=None)
    _cache.clear()
    return out


class CandidateDismiss(BaseModel):
    model_config = {"extra": "forbid"}
    key: str = Field(min_length=1, max_length=100)


@app.get("/api/candidates")
def api_candidates(_=Depends(require_auth), token: str = Depends(_admin_forward)):
    """The discovery queue: tools the estate observed that nobody has
    defined. The receiver annotates each row resolved/dismissed; what to
    show is the page's business, so this forwards unfiltered."""
    return _receiver("GET", "/admin/candidates", token)


@app.post("/api/candidates/dismiss")
def api_candidate_dismiss(req: CandidateDismiss, _=Depends(require_auth),
                          token: str = Depends(_admin_forward)):
    return _receiver(
        "POST", "/admin/candidates/%s/dismiss"
        % urllib.parse.quote(req.key, safe=""), token)


# ------------------------------------------------------------- budget --
# The spend view's write path: thin proxies to the receiver, which owns
# storage, validation and the role gate, exactly like governance and the
# registry above. POST throughout on the portal side (the JSON-only CSRF
# rule covers POST); the receiver keeps its PUTs. The vendor API key
# passes through one request on its way in and no route reads it back -
# the receiver spends it server-side when the portal asks for a sync.


class BudgetSeatTier(BaseModel):
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
    seat_tiers: list[BudgetSeatTier] = Field(default_factory=list,
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
    source: str = Field(min_length=1, max_length=16)
    members: list[BudgetMemberWrite] = Field(default_factory=list,
                                             max_length=5000)


class BudgetConnectionWrite(BaseModel):
    model_config = {"extra": "forbid"}
    tool_id: str = Field(min_length=1, max_length=100)
    provider: str = Field(min_length=1, max_length=32)
    api_key: str = Field(min_length=8, max_length=512)


class BudgetToolRef(BaseModel):
    model_config = {"extra": "forbid"}
    tool_id: str = Field(min_length=1, max_length=100)


@app.get("/api/budget")
def api_budget(_=Depends(require_auth), token: str = Depends(_admin_forward)):
    return _receiver("GET", "/admin/budget", token)


@app.post("/api/budget/subscription")
def api_budget_subscription(req: BudgetSubscriptionWrite,
                            _=Depends(require_auth),
                            token: str = Depends(_admin_forward)):
    return _receiver("PUT", "/admin/budget/subscription", token,
                     req.model_dump())


@app.post("/api/budget/subscription-delete")
def api_budget_subscription_delete(req: BudgetToolRef,
                                   _=Depends(require_auth),
                                   token: str = Depends(_admin_forward)):
    return _receiver("POST", "/admin/budget/subscription/delete", token,
                     req.model_dump())


@app.post("/api/budget/members")
def api_budget_members(req: BudgetMembersWrite, _=Depends(require_auth),
                       token: str = Depends(_admin_forward)):
    return _receiver("PUT", "/admin/budget/members", token, req.model_dump())


@app.post("/api/budget/connection")
def api_budget_connection(req: BudgetConnectionWrite,
                          _=Depends(require_auth),
                          token: str = Depends(_admin_forward)):
    return _receiver("PUT", "/admin/budget/connection", token,
                     req.model_dump())


@app.post("/api/budget/connection-delete")
def api_budget_connection_delete(req: BudgetToolRef, _=Depends(require_auth),
                                 token: str = Depends(_admin_forward)):
    return _receiver("POST", "/admin/budget/connection/delete", token,
                     req.model_dump())


@app.post("/api/budget/sync")
def api_budget_sync(req: BudgetToolRef, _=Depends(require_auth),
                    token: str = Depends(_admin_forward)):
    return _receiver("POST", "/admin/budget/sync", token, req.model_dump())


@app.get("/")
def index(_=Depends(require_page_auth)):
    return FileResponse(STATIC / "index.html")


# Served by name rather than mounting the whole static directory. A mount would
# also expose index.html without the auth dependency above, and the point of
# the dependency is that this portal does not answer to anyone who has not
# authenticated.
@app.get("/logo.png")
def logo(_=Depends(require_page_auth)):
    return FileResponse(STATIC / "logo.png", media_type="image/png")


# There is no /static route, deliberately. The UI is one self-contained file
# with its CSS and JS inline, served by / above, so a route that resolved a
# caller-supplied path under a directory would exist only to serve nothing.
#
# It did exist briefly, guarded by a prefix check, and CodeQL was right to flag
# it: comparing resolved paths with startswith is a weak guard - /srv/static-x
# has /srv/static as a prefix - and the safe version of a route that serves no
# files is no route.