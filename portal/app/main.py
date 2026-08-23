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
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
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
_session_cache: dict[str, tuple[float, str]] = {}  # token -> (until, username)

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

STATIC = Path(__file__).parent / "static"

# Set at build time from the release tag, or the commit for a build off main.
# "dev" for a local build, which is honest.
APP_VERSION = os.environ.get("APP_VERSION", "dev")

app = FastAPI(title="ai-guard portal", version=APP_VERSION,
              docs_url=None, redoc_url=None)


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
        "frame-src " + (GRAFANA_URL or "'none'") + "; "
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


def _cached(key, hours, builder):
    now = time.time()
    hit = _cache.get(key)
    if hit and hit["hours"] == hours and now - hit["at"] < CACHE_TTL:
        return hit["value"], hit["at"]
    value = builder()
    _cache[key] = {"value": value, "at": now, "hours": hours}
    return value, now


def _findings(hours):
    if not LOKI_URL:
        raise HTTPException(
            status_code=503,
            detail="LOKI_URL is not set. The portal reads findings from Loki; "
                   "point it at the same Loki the receiver writes to.",
        )
    global _last_loki_ok, _last_loki_error
    try:
        out = derive.fetch_from_loki(
            LOKI_URL, hours, LOKI_TOKEN,
            username=LOKI_USERNAME, password=LOKI_PASSWORD)
        _last_loki_ok = time.time()
        _last_loki_error = ""
        return out
    except Exception as e:
        # The detail goes to the log, not to the caller. An exception message
        # is written for an operator reading a stack trace, not for an HTTP
        # body, and LOKI_URL may carry credentials in its userinfo.
        log.warning(
            "Loki read failed for %s: %s", _redact_url(LOKI_URL), e,
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
                   % (_redact_url(LOKI_URL), type(e).__name__),
        )


# Deliberately unauthenticated: a liveness probe that needs a credential is a
# probe that fails for the wrong reason. It returns nothing about the estate.
@app.get("/healthz")
def healthz():
    return {"ok": True, "version": APP_VERSION}


@app.get("/api/config")
def config(_=Depends(require_auth)):
    """What the browser needs to know about this deployment."""
    panels = []
    for spec in GRAFANA_PANELS.split(";"):
        spec = spec.strip()
        if not spec:
            continue
        parts = spec.split(":", 2)
        if len(parts) < 2:
            # Said out loud rather than skipped: a panel that silently does not
            # appear looks like Grafana refusing the frame, which sends someone
            # off debugging headers for a typo in an environment variable.
            panels.append({"error": "malformed GRAFANA_PANELS entry: %s" % spec})
            continue
        panels.append({
            "uid": parts[0],
            "panel_id": parts[1],
            "title": parts[2] if len(parts) > 2 else "",
        })

    return {
        "loki_configured": bool(LOKI_URL),
        "grafana_url": GRAFANA_URL,
        "grafana_panels": panels,
        "grafana_dashboard_uid": GRAFANA_DASHBOARD_UID,
        "lookback_hours": LOOKBACK_HOURS,
        "identity_map_configured": bool(IDENTITY_MAP and Path(IDENTITY_MAP).exists()),
        "cache_ttl_seconds": CACHE_TTL,
        "version": APP_VERSION,
        "overview_widgets": _widgets(),
        # enabled says the portal can reach an admin API; artifacts_ready
        # says downloads can bake a URL agents can reach. Separate flags,
        # because a deployment can sensibly have the first without the
        # second and the UI should name which one is missing.
        "managed": {
            "enabled": bool(RECEIVER_URL),
            "artifacts_ready": bool(RECEIVER_URL and RECEIVER_PUBLIC_URL),
        },
    }


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
}

DEFAULT_WIDGETS = ["stat_row", "top_tools", "recent_personal_accounts",
                   "detection_coverage"]


def _widgets():
    """Parse OVERVIEW_WIDGETS into what the browser should draw.

    grafana:<panel-title> entries are resolved against GRAFANA_PANELS rather
    than repeating panel ids in two places.
    """
    raw = [w.strip() for w in OVERVIEW_WIDGETS.split(",") if w.strip()]
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
def graph(hours: float = Query(default=None, gt=0, le=24 * 90),
          refresh: bool = Query(default=False),
          _=Depends(require_auth)):
    """refresh=true skips the cache. A cache you cannot see past is
    indistinguishable from a portal that is not working."""
    hours = hours or LOOKBACK_HOURS
    if refresh:
        _cache.pop("graph", None)
    def build():
        findings = _findings(hours)
        domain_map = derive.load_domain_map(REGISTRY_PATH)
        identity_map = derive.load_identity_map(IDENTITY_MAP) if IDENTITY_MAP else {}
        return derive.graph_from(findings, domain_map, identity_map)

    value, at = _cached("graph", hours, build)
    return JSONResponse(dict(value, derived_at=at, hours=hours))


@app.get("/api/status")
def status(hours: float = Query(default=None, gt=0, le=24 * 90),
           refresh: bool = Query(default=False),
           _=Depends(require_auth)):
    hours = hours or LOOKBACK_HOURS
    if refresh:
        _cache.pop("status", None)
    def build():
        return derive.status_from(_findings(hours))

    value, at = _cached("status", hours, build)
    return JSONResponse(dict(value, derived_at=at, hours=hours))


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
    findings = _findings(hours)
    reg = derive.load_registry(REGISTRY_PATH)
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
def paste_guard_events(hours: float = Query(default=None, gt=0, le=24 * 90),
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
        findings = _findings(hours)
        reg = derive.load_registry(REGISTRY_PATH)
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
        findings = _findings(hours)
        reg = derive.load_registry(REGISTRY_PATH)
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
        derive.load_registry(REGISTRY_PATH).get("tools") or [])]
    return JSONResponse({
        "rows": rows,
        "derived_at": at,
        "hours": hours,
        # A governance file, or at least one decision recorded in the
        # portal: either means somebody is deciding, and the "nothing is
        # configured" note would be false.
        "governance_configured": bool(GOVERNANCE_PATH) or portal_decisions > 0,
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
def suggest_identities(hours: float = Query(default=None, gt=0, le=24 * 90),
                       fmt: str = Query(default="json", pattern="^(json|csv)$"),
                       _=Depends(require_auth)):
    """Proposed device -> identity mappings, for review.

    The portal will not apply these itself. Identity resolution belongs to the
    deployer, against whatever they run, and a mapping this platform invented
    and then acted on is how the wrong name ends up on a report. Save the CSV,
    correct it, and point IDENTITY_MAP at it.
    """
    hours = hours or LOOKBACK_HOURS
    findings = _findings(hours)
    domain_map = derive.load_domain_map(REGISTRY_PATH)
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
                             str(who.get("username", "")))
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
    return {"mode": "login" if PORTAL_AUTH != "none" else "none",
            "authenticated": authenticated,
            "username": (_session_cache.get(token) or (0, ""))[1],
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
    # setting took effect.
    model_config = {"extra": "forbid"}
    corp_domains: list[str] | None = Field(default=None, max_length=200)
    extension_id: str | None = Field(default=None, max_length=128)
    onboarding_done: bool | None = None


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
    return _receiver("PUT", "/admin/settings", token, body)


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
GENERATED_ARTIFACTS = ("extension-policy", "scanner-cronjob")


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
    if not RECEIVER_PUBLIC_URL:
        raise HTTPException(
            503, "RECEIVER_PUBLIC_URL is not set. Artifacts bake the ingest "
                 "URL agents reach from outside, which is not the portal's "
                 "internal RECEIVER_URL; see the portal README.")

    # The extension policy's preconditions are checked before minting, so a
    # refusal does not leave a token dangling behind an artifact that never
    # existed.
    extension_id, corp_domains = "", []
    if kind == "extension-policy":
        stored = _receiver("GET", "/admin/settings", token).get("settings", {})
        extension_id = (stored.get("extension_id") or {}).get("value") or ""
        corp_domains = (stored.get("corp_domains") or {}).get("value") or []
        if not extension_id:
            raise HTTPException(
                409, "set the extension ID in Settings first: the policy "
                     "names the per-browser upload domains with it")

    minted = _receiver("POST", "/admin/enrollment-tokens", token,
                       {"note": "portal artifact: %s" % kind})
    try:
        if kind == "extension-policy":
            filename, content = managed.generate_extension_policy(
                extension_id, RECEIVER_PUBLIC_URL, minted["token"],
                corp_domains)
        elif kind == "scanner-cronjob":
            # A release build's version is the image tag on ghcr; a dev
            # build has no matching image, and "latest" is the honest
            # nearest thing.
            tag = APP_VERSION if APP_VERSION[:1].isdigit() else "latest"
            filename, content = managed.generate_scanner_cronjob(
                RECEIVER_PUBLIC_URL, minted["token"], tag)
        else:
            filename, content = managed.generate(
                kind, COLLECTOR_SCRIPTS_DIR, RECEIVER_PUBLIC_URL,
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
def registry_tools(_=Depends(require_auth)):
    """The registry watchlist, id and name only.

    For the wizard's governance baseline: unlike /api/register it needs no
    findings and no log store, because a fresh install has neither and the
    baseline is exactly the thing you record before anything reports.
    """
    reg = derive.load_registry(REGISTRY_PATH)
    return {"tools": [
        {"id": t["id"], "name": t.get("name") or t["id"],
         "vendor": t.get("vendor") or "", "approved": bool(t.get("approved"))}
        for t in (reg.get("tools") or []) if t.get("id")]}


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