"""Managed-mode proxy and deployment-artifact generation.

The portal's CSP keeps the browser on 'self', so every admin action goes
through here to the receiver. The portal holds no write credential: the
operator's admin token arrives per request in the X-Admin-Token header, is
forwarded verbatim, and the receiver authorizes. A compromised portal
therefore yields readable findings - which it always did - and nothing that
can mint or revoke.

Artifacts are the collector scripts with the receiver URL and a freshly
minted enrollment token substituted in as *defaults*, not hardcodes: every
substitution targets the script's existing fallback syntax, so a value the
MDM supplies still wins. Corporate domains are deliberately not baked - the
receiver serves those to every collector at runtime via /registry/collector.

The scripts themselves are verified copies of endpoint/* (a test asserts
byte equality, the same pattern as the chart's bundled registry), because
the portal image cannot see the endpoint/ tree at build time.
"""

import json
import urllib.error
import urllib.request
from pathlib import Path

TIMEOUT_SECONDS = 10


class ReceiverError(Exception):
    """A failed receiver call, carrying the HTTP status it should become."""

    def __init__(self, status: int, detail: str):
        self.status = status
        self.detail = detail
        super().__init__(detail)


def receiver_request(base: str, method: str, path: str, admin_token: str,
                     body: dict | None = None) -> dict:
    """One call to the receiver's admin API, the operator's token forwarded.

    stdlib urllib, matching derive.fetch_from_loki, so the portal gains no
    HTTP dependency. Receiver 4xx passes through with its own detail when
    that detail is a plain string (the receiver's are fixed messages, and a
    401 must reach the operator as "bad token", not as a portal error);
    anything unreachable is a 502 naming only the exception class, because
    the URL and the error text are for the log, not the browser.
    """
    data = json.dumps(body).encode() if body is not None else b""
    req = urllib.request.Request(
        base.rstrip("/") + path,
        method=method,
        data=data if method in ("POST", "PUT") else None,
        headers={
            "Authorization": "Bearer " + admin_token,
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
            return json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        detail = "receiver refused with HTTP %d" % e.code
        try:
            parsed = json.loads(e.read() or b"{}").get("detail")
            if isinstance(parsed, str) and parsed:
                detail = parsed
        except (ValueError, OSError):
            pass
        raise ReceiverError(e.code, detail)
    except Exception as e:
        raise ReceiverError(502, "could not reach the receiver (%s)"
                            % type(e).__name__)


# Each artifact names the exact fallback syntax it substitutes. An anchor
# that stops matching means the collector script changed shape; the fix is
# updating the anchor, and the loud failure below is what makes that a
# build-time task instead of a fleet quietly deployed with no configuration.
ARTIFACTS = {
    "collector-macos": {
        "file": "collector-macos.sh",
        "download": "ai-guard-collector.sh",
        "anchors": [
            ('RECEIVER_BASE="${4:-}"', 'RECEIVER_BASE="${4:-%(url)s}"'),
            ('TOKEN="${5:-}"', 'TOKEN="${5:-%(token)s}"'),
        ],
    },
    "collector-linux": {
        "file": "collector-linux.sh",
        "download": "ai-guard-collector.sh",
        "anchors": [
            ('RECEIVER_BASE="${AIGUARD_RECEIVER_BASE:-}"',
             'RECEIVER_BASE="${AIGUARD_RECEIVER_BASE:-%(url)s}"'),
            ('TOKEN="${AIGUARD_TOKEN:-}"',
             'TOKEN="${AIGUARD_TOKEN:-%(token)s}"'),
        ],
    },
    "collector-windows": {
        "file": "collector-windows.ps1",
        "download": "ai-guard-collector.ps1",
        "anchors": [
            ("$ReceiverBase    = 'https://ai-guard.example.com'",
             "$ReceiverBase    = '%(url)s'"),
            ("$Token           = '__RECEIVER_TOKEN__'",
             "$Token           = '%(token)s'"),
        ],
    },
}


class ArtifactError(Exception):
    pass


def generate(kind: str, scripts_dir: str, url: str, token: str) -> tuple[str, str]:
    """(download filename, content) for one pre-configured collector.

    Values are embedded inside shell and PowerShell quoting, so anything that
    could escape it is refused outright rather than escaped: the URL is
    operator-supplied configuration and the token alphabet is URL-safe
    base64, so a rejection here is a misconfiguration being named, not a
    case to handle gracefully.
    """
    spec = ARTIFACTS.get(kind)
    if spec is None:
        raise ArtifactError("no such artifact: %s" % kind)
    for value, name in ((url, "receiver URL"), (token, "token")):
        if any(c in value for c in "'\"\\$`\n\r\t ") or not value:
            raise ArtifactError("the %s cannot be embedded in a script" % name)

    path = Path(scripts_dir) / spec["file"]
    try:
        content = path.read_text()
    except OSError as e:
        raise ArtifactError("collector script not readable: %s (%s)"
                            % (path.name, type(e).__name__))

    for anchor, template in spec["anchors"]:
        if content.count(anchor) != 1:
            raise ArtifactError(
                "substitution anchor not found exactly once in %s: %r - the "
                "collector script changed shape; update ARTIFACTS to match"
                % (spec["file"], anchor))
        content = content.replace(anchor, template % {"url": url, "token": token})
    return spec["download"], content
