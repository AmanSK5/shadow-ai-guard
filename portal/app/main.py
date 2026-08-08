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
  CACHE_TTL_SECONDS how long a derived graph is reused, default 300
"""

import logging
import os
import secrets
import time
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles

from app import derive

log = logging.getLogger("portal")

PORTAL_USER = os.environ.get("PORTAL_USER", "")
PORTAL_PASSWORD = os.environ.get("PORTAL_PASSWORD", "")
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
LOKI_TOKEN = os.environ.get("LOKI_TOKEN") or None
LOOKBACK_HOURS = float(os.environ.get("LOOKBACK_HOURS", "168"))
REGISTRY_PATH = os.environ.get("REGISTRY_PATH", "/srv/registry/registry.yaml")
IDENTITY_MAP = os.environ.get("IDENTITY_MAP", "")
GRAFANA_URL = os.environ.get("GRAFANA_URL", "").rstrip("/")
GRAFANA_PANELS = os.environ.get("GRAFANA_PANELS", "")
GRAFANA_DASHBOARD_UID = os.environ.get("GRAFANA_DASHBOARD_UID", "")
CACHE_TTL = int(os.environ.get("CACHE_TTL_SECONDS", "300"))

STATIC = Path(__file__).parent / "static"

app = FastAPI(title="ai-guard portal", docs_url=None, redoc_url=None)

# A derived graph, kept briefly. Not state in any meaningful sense: it rebuilds
# from Loki on the next miss and on every restart. Without it, a 7 day query
# runs on every page load, which is slow for the reader and unkind to Loki.
_cache: dict = {}


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
    try:
        return derive.fetch_from_loki(LOKI_URL, hours, LOKI_TOKEN)
    except Exception as e:
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
    return {"ok": True}


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
    }


@app.get("/api/graph")
def graph(hours: float = Query(default=None, gt=0, le=24 * 90),
          _=Depends(require_auth)):
    hours = hours or LOOKBACK_HOURS
    def build():
        findings = _findings(hours)
        domain_map = derive.load_domain_map(REGISTRY_PATH)
        identity_map = derive.load_identity_map(IDENTITY_MAP) if IDENTITY_MAP else {}
        return derive.graph_from(findings, domain_map, identity_map)

    value, at = _cached("graph", hours, build)
    return JSONResponse(dict(value, derived_at=at, hours=hours))


@app.get("/api/status")
def status(hours: float = Query(default=None, gt=0, le=24 * 90),
           _=Depends(require_auth)):
    hours = hours or LOOKBACK_HOURS
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


# The UI is inert without the APIs above, but an unauthenticated mount is
# still a hole worth not leaving open.
@app.get("/static/{path:path}")
def static_files(path: str, _=Depends(require_auth)):
    target = (STATIC / path).resolve()
    if not str(target).startswith(str(STATIC.resolve())) or not target.is_file():
        raise HTTPException(status_code=404, detail="not found")
    return FileResponse(target)
