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
refuses to start rather than come up open by accident. Set PORTAL_USER and
PORTAL_PASSWORD, or set PORTAL_AUTH=none deliberately for localhost. Basic auth
is a floor, not a ceiling: it is one shared credential with no per-user trail,
so anyone already running a reverse proxy should authenticate there instead and
run this with PORTAL_AUTH=none behind it.

Configuration, all optional except LOKI_URL and the auth pair:
  PORTAL_USER       basic auth username
  PORTAL_PASSWORD   basic auth password

Any of PORTAL_USER, PORTAL_PASSWORD and LOKI_TOKEN can be given as
NAME_FILE pointing at a file instead. Compose has no real secret story: an
environment variable is visible in docker inspect and in every child process's
environment, while a file is at least confined to the filesystem. It is not
encryption.

  PORTAL_AUTH       set to "none" to run without auth. Logs a warning on every
                    start, because an unauthenticated deployment should never
                    be something nobody noticed
  LOKI_URL          Loki base URL, e.g. http://loki:3100
  LOKI_TOKEN        bearer token, if your Loki needs one
  LOOKBACK_HOURS    default window, default 168
  REGISTRY_PATH     registry.yaml, for resolving domains to tool ids
  IDENTITY_MAP      CSV of key,identity for attaching people to devices
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

import logging
import os
import secrets
import time
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from app import derive

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

# Fail closed. Coming up open because a variable was missed is the failure
# that matters here: the portal is reachable, it looks like it works, and
# nothing says the door is off. Refusing to start is loud and immediate.
if PORTAL_AUTH == "none":
    log.warning(
        "PORTAL_AUTH=none: this portal is running WITHOUT AUTHENTICATION. It "
        "shows which people use which AI tools on which machines. That is fine "
        "on localhost and behind a proxy that authenticates for it, and it is "
        "not fine on anything reachable."
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

_basic = HTTPBasic(auto_error=False)


def require_auth(creds: HTTPBasicCredentials = Depends(_basic)):
    """Compared with compare_digest so a wrong username and a wrong password
    take the same time to reject: a difference there is enough to enumerate a
    valid username one character at a time."""
    if PORTAL_AUTH == "none":
        return
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


LOKI_URL = os.environ.get("LOKI_URL", "")
LOKI_TOKEN = _secret("LOKI_TOKEN") or None
LOOKBACK_HOURS = float(os.environ.get("LOOKBACK_HOURS", "168"))
REGISTRY_PATH = os.environ.get("REGISTRY_PATH", "/srv/registry/registry.yaml")
IDENTITY_MAP = os.environ.get("IDENTITY_MAP", "")
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

STATIC = Path(__file__).parent / "static"

# Set at build time from the release tag, or the commit for a build off main.
# "dev" for a local build, which is honest.
APP_VERSION = os.environ.get("APP_VERSION", "dev")

app = FastAPI(title="ai-guard portal", version=APP_VERSION,
              docs_url=None, redoc_url=None)

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
        out = derive.fetch_from_loki(LOKI_URL, hours, LOKI_TOKEN)
        _last_loki_ok = time.time()
        _last_loki_error = ""
        return out
    except Exception as e:
        _last_loki_error = str(e)
        # Say which of the two this is. A portal that shows an empty graph
        # when it cannot reach Loki is indistinguishable from one reporting a
        # clean estate, which is the failure this project keeps finding.
        raise HTTPException(
            status_code=502,
            detail="Could not read findings from Loki at %s: %s" % (LOKI_URL, e),
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
        reg_err = str(e)

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
            "auth_mode": PORTAL_AUTH or "basic",
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


@app.get("/")
def index(_=Depends(require_auth)):
    return FileResponse(STATIC / "index.html")


# Served by name rather than mounting the whole static directory. A mount would
# also expose index.html without the auth dependency above, and the point of
# the dependency is that this portal does not answer to anyone who has not
# authenticated.
@app.get("/logo.png")
def logo(_=Depends(require_auth)):
    return FileResponse(STATIC / "logo.png", media_type="image/png")


# There is no /static route, deliberately. The UI is one self-contained file
# with its CSS and JS inline, served by / above, so a route that resolved a
# caller-supplied path under a directory would exist only to serve nothing.
#
# It did exist briefly, guarded by a prefix check, and CodeQL was right to flag
# it: comparing resolved paths with startswith is a weak guard - /srv/static-x
# has /srv/static as a prefix - and the safe version of a route that serves no
# files is no route.