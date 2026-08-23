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
import re
import urllib.error
import urllib.request
from pathlib import Path
from xml.sax.saxutils import escape as _xml

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


def _refuse_unembeddable(pairs):
    """The same refusal generate() applies: these values land inside quoted
    contexts, and anything that could escape one is a misconfiguration to
    name, not a case to handle gracefully."""
    for value, name in pairs:
        if not value or any(c in value for c in "'\"\\$`\n\r\t <>&"):
            raise ArtifactError("the %s cannot be embedded in an artifact"
                               % name)


# The extension's own default set, baked when the operator has not chosen
# their own in Settings. Mirrors extension/deploy/*'s hand-written files.
DEFAULT_MARKINGS = (
    "Client Confidential",
    "Internal Confidential",
    "Internal Use Only",
    "Strictly Confidential",
    "Commercial in Confidence",
)


def _checked_markings(markings):
    """The markings list an artifact will carry, validated for every
    context it lands in (XML text and PowerShell single-quoted strings).
    Spaces are legitimate here - these are document classification phrases
    - so this is a narrower refusal than _refuse_unembeddable."""
    out = list(DEFAULT_MARKINGS) if markings is None else list(markings)
    for m in out:
        if not m or any(c in m for c in "'\"\\$`\n\r\t<>&"):
            raise ArtifactError(
                "a classification marking cannot be embedded in an artifact:"
                " %r" % m[:60])
    return out


def _checked_mode(mode):
    mode = mode or "warn"
    if mode not in ("off", "warn", "block"):
        raise ArtifactError("paste guard mode must be off, warn or block")
    return mode


def generate_extension_policy(extension_id: str, url: str, token: str,
                              corp_domains: list[str],
                              paste_guard_mode: str = "warn",
                              markings: list[str] | None = None
                              ) -> tuple[str, str]:
    """The browser extension's managed-storage policy, ready to deploy.

    One plist body serves every Chromium browser - the browser is chosen by
    the preference domain it is uploaded under, which is why the extension
    id must exist in Settings first: without it the header cannot name the
    domains and the Windows command line, and an unconfigured policy is an
    extension that reports nothing.

    Unlike the collectors, corp domains ARE baked here: the extension reads
    allowedDomains from managed storage and fetches no central config, so
    the policy is the only channel. The header says so, and says a domain
    change means regenerating this file.
    """
    _refuse_unembeddable(((url, "receiver URL"), (token, "token")))
    # A Chromium extension id is exactly 32 letters a-p (a hex digest
    # transposed). Enforcing the shape here doubles as XML safety: the id
    # lands inside an XML comment, where an arbitrary string could carry
    # "--" and break the document.
    if not re.fullmatch(r"[a-p]{32}", extension_id or ""):
        raise ArtifactError(
            "the extension id does not look like a Chromium extension id"
            " (32 letters a-p); check Settings")
    for d in corp_domains:
        _refuse_unembeddable(((d, "corp domain"),))

    domains_xml = "\n".join("        <string>%s</string>" % _xml(d)
                            for d in corp_domains) or (
        "        <!-- no corporate domains set; every account will read as"
        " personal until Settings has them and this file is regenerated -->")
    markings_xml = "\n".join("        <string>%s</string>" % _xml(m)
                             for m in _checked_markings(markings))
    return "ai-guard-extension-policy.plist", _EXTENSION_POLICY_TEMPLATE % {
        "id": _xml(extension_id), "url": _xml(url), "token": _xml(token),
        "domains": domains_xml, "mode": _checked_mode(paste_guard_mode),
        "markings": markings_xml,
    }


# The plist body mirrors extension/deploy/macos/<browser>/managed-storage
# .plist; the keys are the extension's managed-storage schema
# (reportEndpoint, authToken, deviceIdentifier, allowedDomains,
# pasteGuardMode, classificationMarkings - see extension/src/background.js).
_EXTENSION_POLICY_TEMPLATE = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!--
  ai-guard browser extension: managed-storage policy, generated by the
  portal with a fresh enrollment token baked in. Each browser profile
  exchanges the token once at /enroll for its own credential; revoke this
  artifact's token in the portal and profiles that have not yet enrolled
  with it stop being able to.

  macOS (Jamf or another MDM): upload this file as an "Application & Custom
  Settings" payload under the per-extension preference domain -
    Chrome  com.google.Chrome.extensions.%(id)s
    Edge    com.microsoft.Edge.extensions.%(id)s
    Brave   com.brave.Browser.extensions.%(id)s
  alongside the install.plist from extension/deploy/macos/<browser>/
  (forcelist + update URL - both payloads are needed).

  Windows: use the deploy script from extension/deploy/windows/ instead;
  this file's values map onto its parameters:
    .\\Deploy-AiGuardExtension.ps1 -ExtensionId %(id)s ^
      -Endpoint %(url)s/report -AuthToken <the token below> ^
      -AllowedDomains <the domains below>

  deviceIdentifier: $SERIALNUMBER is substituted per machine by Jamf;
  other MDMs have equivalents. allowedDomains is baked because the
  extension reads no central config - changing corporate domains in the
  portal means regenerating and re-pushing this policy.
-->
<plist version="1.0">
<dict>
    <key>reportEndpoint</key>
    <string>%(url)s/report</string>
    <key>authToken</key>
    <string>%(token)s</string>
    <key>deviceIdentifier</key>
    <string>$SERIALNUMBER</string>
    <key>allowedDomains</key>
    <array>
%(domains)s
    </array>
    <key>pasteGuardMode</key>
    <string>%(mode)s</string>
    <key>classificationMarkings</key>
    <array>
%(markings)s
    </array>
</dict>
</plist>
"""


def _ps_str(v: str) -> str:
    """A PowerShell single-quoted literal. The only escape in single quotes
    is doubling the quote itself, and quotes are refused upstream anyway -
    this keeps the property even if a refusal is ever loosened."""
    return "'" + v.replace("'", "''") + "'"


def _ps_arr(values) -> str:
    return "@(" + ", ".join(_ps_str(v) for v in values) + ")"


# The config block both Windows deploy scripts carry verbatim (a test
# asserts the copies match extension/deploy/windows/). Substituted as one
# anchor each so a script that changes shape fails loudly at generate time.
_PS_SHARED_ANCHORS = (
    "$AllowedDomains = @('example.com')",
    "$PasteGuardMode = 'warn'",
    """$ClassificationMarkings = @(
    'Client Confidential'
    'Internal Confidential'
    'Internal Use Only'
    'Strictly Confidential'
    'Commercial in Confidence'
)""",
)


def _generate_ps_deploy(scripts_dir: str, script: str, download: str,
                        head_anchors: list, url: str, token: str,
                        corp_domains: list[str], mode: str,
                        markings) -> tuple[str, str]:
    """One pre-configured Windows deploy script: the head anchors are the
    script's own REPLACE_WITH placeholders, the shared trio is domains,
    paste guard mode and markings."""
    for d in corp_domains:
        _refuse_unembeddable(((d, "corp domain"),))
    marks = _checked_markings(markings)
    path = Path(scripts_dir) / script
    try:
        content = path.read_text()
    except OSError as e:
        raise ArtifactError("deploy script not readable: %s (%s)"
                            % (path.name, type(e).__name__))

    subs = list(head_anchors) + [
        # An empty list bakes @() - every account reads as personal until
        # Settings has domains and the script is regenerated. Leaving the
        # placeholder would deploy example.com as a corporate domain.
        (_PS_SHARED_ANCHORS[0],
         "$AllowedDomains = %s" % _ps_arr(corp_domains)),
        (_PS_SHARED_ANCHORS[1],
         "$PasteGuardMode = %s" % _ps_str(_checked_mode(mode))),
        (_PS_SHARED_ANCHORS[2],
         "$ClassificationMarkings = %s" % _ps_arr(marks)),
    ]
    for anchor, repl in subs:
        if content.count(anchor) != 1:
            raise ArtifactError(
                "substitution anchor not found exactly once in %s: %r - the "
                "deploy script changed shape; update the anchors to match"
                % (script, anchor.splitlines()[0]))
        content = content.replace(anchor, repl)
    return download, content


def generate_extension_windows(scripts_dir: str, extension_id: str,
                               update_url: str, url: str, token: str,
                               corp_domains: list[str], mode: str = "warn",
                               markings=None) -> tuple[str, str]:
    """The Chromium Windows deploy script, pre-configured: Intune-ready,
    same trust story as every artifact (fresh token, values baked as the
    script's own config block)."""
    _refuse_unembeddable(((url, "receiver URL"), (token, "token"),
                          (update_url, "extension update URL")))
    if not re.fullmatch(r"[a-p]{32}", extension_id or ""):
        raise ArtifactError(
            "the extension id does not look like a Chromium extension id"
            " (32 letters a-p); check Settings")
    head = [
        ("$ExtensionId = 'REPLACE_WITH_EXTENSION_ID'",
         "$ExtensionId = %s" % _ps_str(extension_id)),
        ("$UpdatesXml  = 'https://REPLACE_WITH_HOST/updates.xml'",
         "$UpdatesXml  = %s" % _ps_str(update_url)),
        ("$Endpoint    = 'https://REPLACE_WITH_HOST/report'",
         "$Endpoint    = %s" % _ps_str(url.rstrip("/") + "/report")),
        ("$AuthToken   = 'REPLACE_WITH_TOKEN'",
         "$AuthToken   = %s" % _ps_str(token)),
    ]
    return _generate_ps_deploy(scripts_dir, "extension-windows.ps1",
                               "Deploy-AiGuardExtension.ps1", head, url,
                               token, corp_domains, mode, markings)


def generate_firefox_windows(scripts_dir: str, gecko_id: str, xpi_url: str,
                             url: str, token: str, corp_domains: list[str],
                             mode: str = "warn",
                             markings=None) -> tuple[str, str]:
    """The Firefox Windows deploy script, pre-configured. The .xpi it
    installs must be the Mozilla-signed one - no policy can waive that -
    which is why the signed file's URL is a setting the operator supplies
    rather than something the portal can invent."""
    _refuse_unembeddable(((url, "receiver URL"), (token, "token"),
                          (xpi_url, "signed .xpi URL"),
                          (gecko_id, "Firefox extension id")))
    head = [
        ("$GeckoId   = 'REPLACE_WITH_GECKO_ID'",
         "$GeckoId   = %s" % _ps_str(gecko_id)),
        ("$XpiUrl    = 'https://REPLACE_WITH_HOST/ai-guard-1.0.0.xpi'",
         "$XpiUrl    = %s" % _ps_str(xpi_url)),
        ("$Endpoint  = 'https://REPLACE_WITH_HOST/report'",
         "$Endpoint  = %s" % _ps_str(url.rstrip("/") + "/report")),
        ("$AuthToken = 'REPLACE_WITH_TOKEN'",
         "$AuthToken = %s" % _ps_str(token)),
    ]
    return _generate_ps_deploy(scripts_dir, "firefox-windows.ps1",
                               "Deploy-AiGuardExtensionFirefox.ps1", head,
                               url, token, corp_domains, mode, markings)


def generate_firefox_policy(gecko_id: str, xpi_url: str, url: str,
                            token: str, corp_domains: list[str],
                            mode: str = "warn",
                            markings=None) -> tuple[str, str]:
    """Firefox's install-and-configure payload for macOS, in one plist.

    Mirrors extension/deploy/macos/firefox/managed-storage.plist: policy
    lives under org.mozilla.firefox (not a per-extension domain), managed
    storage under 3rdparty > Extensions > the gecko id, and install_url
    (not update_url) pointing at the Mozilla-SIGNED .xpi - Firefox refuses
    unsigned extensions on release builds and no enterprise policy changes
    that, so the signed file's URL is an operator-supplied setting."""
    _refuse_unembeddable(((url, "receiver URL"), (token, "token"),
                          (xpi_url, "signed .xpi URL"),
                          (gecko_id, "Firefox extension id")))
    for d in corp_domains:
        _refuse_unembeddable(((d, "corp domain"),))
    domains_xml = "\n".join(
        "                <string>%s</string>" % _xml(d)
        for d in corp_domains) or (
        "                <!-- no corporate domains set; every account will"
        " read as personal until Settings has them and this file is"
        " regenerated -->")
    markings_xml = "\n".join(
        "                <string>%s</string>" % _xml(m)
        for m in _checked_markings(markings))
    return "ai-guard-firefox-policy.plist", _FIREFOX_POLICY_TEMPLATE % {
        "id": _xml(gecko_id), "xpi": _xml(xpi_url), "url": _xml(url),
        "token": _xml(token), "domains": domains_xml,
        "mode": _checked_mode(mode), "markings": markings_xml,
    }


_FIREFOX_POLICY_TEMPLATE = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!--
  ai-guard browser extension: Firefox install-and-configure payload,
  generated by the portal with a fresh enrollment token baked in.

  Upload as an "Application &amp; Custom Settings" payload under the
  preference domain org.mozilla.firefox. Unlike the Chromium browsers,
  Firefox reads install and configuration from this one payload.

  install_url points at the Mozilla-SIGNED .xpi (Settings holds its URL).
  Firefox refuses unsigned extensions on release builds, and no enterprise
  policy changes that; sign by submitting to addons.mozilla.org as a
  self-distributed add-on. See extension/README.md.

  deviceIdentifier: $SERIALNUMBER is substituted per machine by Jamf;
  other MDMs have equivalents. allowedDomains and the paste guard settings
  are baked because the extension reads no central config - changing them
  in the portal means regenerating and re-pushing this policy.
-->
<plist version="1.0">
<dict>
    <key>EnterprisePoliciesEnabled</key>
    <true/>

    <key>ExtensionSettings</key>
    <dict>
        <key>%(id)s</key>
        <dict>
            <key>installation_mode</key>
            <string>force_installed</string>
            <key>install_url</key>
            <string>%(xpi)s</string>
            <key>updates_disabled</key>
            <false/>
        </dict>
    </dict>

    <key>3rdparty</key>
    <dict>
        <key>Extensions</key>
        <dict>
            <key>%(id)s</key>
            <dict>
                <key>reportEndpoint</key>
                <string>%(url)s/report</string>
                <key>authToken</key>
                <string>%(token)s</string>
                <key>deviceIdentifier</key>
                <string>$SERIALNUMBER</string>
                <key>pasteGuardMode</key>
                <string>%(mode)s</string>
                <key>allowedDomains</key>
                <array>
%(domains)s
                </array>
                <key>classificationMarkings</key>
                <array>
%(markings)s
                </array>
            </dict>
        </dict>
    </dict>
</dict>
</plist>
"""


def generate_scanner_cronjob(url: str, token: str,
                             image_tag: str) -> tuple[str, str]:
    """A Kubernetes CronJob for the cloud/fleet scanners, plus the Secret
    its enrollment token lives in.

    The token goes in a Secret rather than inline env, because manifests
    end up in git and Secrets are the one shape everyone already knows not
    to commit. Scanner-specific credentials (Entra, Jamf, SentinelOne) are
    named as comments, not baked - the portal never sees them.
    """
    _refuse_unembeddable(((url, "receiver URL"), (token, "token"),
                          (image_tag, "image tag")))
    return "ai-guard-scanner-cronjob.yaml", _SCANNER_CRONJOB_TEMPLATE % {
        "url": url, "token": token, "tag": image_tag,
    }


def generate_discovery_cronjob(url: str, token: str,
                               image_tag: str) -> tuple[str, str]:
    """A Kubernetes CronJob for the discovery service: daily unknown-tool
    discovery feeding the portal's review queue.

    Same shape and same reasoning as the scanner CronJob. The telemetry and
    classification credentials (SentinelOne, Anthropic) are named as
    comments, never baked - the portal never sees them.
    """
    _refuse_unembeddable(((url, "receiver URL"), (token, "token"),
                          (image_tag, "image tag")))
    return "ai-guard-discovery-cronjob.yaml", _DISCOVERY_CRONJOB_TEMPLATE % {
        "url": url, "token": token, "tag": image_tag,
    }


_DISCOVERY_CRONJOB_TEMPLATE = """\
# ai-guard discovery: CronJob + the Secret its enrollment token lives in.
# Generated by the portal with a fresh token baked in - treat this file as
# a credential (kubectl apply it, do not commit it; the Secret is why).
#
# Discovery reads fleet DNS telemetry, drops every domain the registry
# already knows, classifies the residue ("is this an AI service?"), and
# posts the candidates to the receiver. They appear in the portal's review
# queue, where defining or dismissing them is the human gate - nothing is
# detected until someone decides.
#
# Two credentials are yours to add before applying (from your own Secret,
# never this file):
#   SentinelOne Deep Visibility:  S1_BASE_URL, S1_API_TOKEN
#   Anthropic (classification):   ANTHROPIC_API_KEY
apiVersion: v1
kind: Secret
metadata:
  name: ai-guard-discovery
type: Opaque
stringData:
  enrollmentToken: %(token)s
---
apiVersion: batch/v1
kind: CronJob
metadata:
  name: ai-guard-discovery
spec:
  schedule: "41 6 * * *"
  concurrencyPolicy: Forbid
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: Never
          containers:
            - name: discovery
              image: ghcr.io/amansk5/shadow-ai-guard/discovery:%(tag)s
              env:
                - name: RECEIVER_URL
                  value: "%(url)s"
                - name: RECEIVER_TOKEN
                  valueFrom:
                    secretKeyRef:
                      name: ai-guard-discovery
                      key: enrollmentToken
                - name: AIGUARD_SCANNER_ID
                  value: "discovery"
                # - name: S1_BASE_URL
                #   value: "https://<your-tenant>.sentinelone.net"
                # - name: S1_API_TOKEN
                #   valueFrom: {secretKeyRef: {name: <yours>, key: <yours>}}
                # - name: ANTHROPIC_API_KEY
                #   valueFrom: {secretKeyRef: {name: <yours>, key: <yours>}}
"""


_SCANNER_CRONJOB_TEMPLATE = """\
# ai-guard scanners: CronJob + the Secret its enrollment token lives in.
# Generated by the portal with a fresh token baked in - treat this file as
# a credential (kubectl apply it, do not commit it; the Secret is why).
#
# The scanner enrolls on every run and the receiver reissues the same
# device's credential in place, so it shows as one row in Fleet whatever
# the schedule. Revoking that row only cuts the current run; the lever for
# a scanner is revoking this artifact's enrollment token in the portal.
#
# Each scanner runs only when its credentials are present. Add the ones
# you use to the env below (from your own Secret, never this file):
#   Entra/Exchange/Intune: AIGUARD_ENTRA_TENANT_ID, AIGUARD_ENTRA_CLIENT_ID,
#                          AIGUARD_ENTRA_CLIENT_SECRET
#   Jamf:                  AIGUARD_JAMF_URL, AIGUARD_JAMF_CLIENT_ID,
#                          AIGUARD_JAMF_CLIENT_SECRET
#   SentinelOne:           AIGUARD_S1_URL, AIGUARD_S1_TOKEN
apiVersion: v1
kind: Secret
metadata:
  name: ai-guard-scanner
type: Opaque
stringData:
  enrollmentToken: %(token)s
---
apiVersion: batch/v1
kind: CronJob
metadata:
  name: ai-guard-scanner
spec:
  schedule: "17 */6 * * *"
  concurrencyPolicy: Forbid
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: Never
          containers:
            - name: scanner
              image: ghcr.io/amansk5/shadow-ai-guard/scanner:%(tag)s
              env:
                - name: RECEIVER_URL
                  value: "%(url)s"
                - name: RECEIVER_TOKEN
                  valueFrom:
                    secretKeyRef:
                      name: ai-guard-scanner
                      key: enrollmentToken
                - name: AIGUARD_SCANNER_ID
                  value: "scanner"
"""
