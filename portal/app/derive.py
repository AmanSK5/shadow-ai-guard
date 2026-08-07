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

import json
import os
import sys
import time
import urllib.parse
import urllib.request
from collections import defaultdict

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


def fetch_from_loki(base, hours, token=None, limit=5000):
    """Pull findings from Loki. Returns a list of parsed finding dicts."""
    import time

    end = int(time.time() * 1e9)
    start = end - int(hours * 3600 * 1e9)
    params = urllib.parse.urlencode({
        "query": '{app="ai-guard-receiver", kind="finding"}',
        "start": start,
        "end": end,
        "limit": limit,
        "direction": "backward",
    })
    req = urllib.request.Request(base.rstrip("/") + "/loki/api/v1/query_range?" + params)
    if token:
        req.add_header("Authorization", "Bearer " + token)

    with urllib.request.urlopen(req, timeout=30) as resp:
        payload = json.load(resp)

    out = []
    for stream in payload.get("data", {}).get("result", []):
        for _ts, line in stream.get("values", []):
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
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
            parts = [c.strip() for c in line.split(",", 1)]
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
        if hit:
            matched.append({"key": dev, "identity": hit[1], "via": hit[0],
                            "device_name": d["device_name"]})
        else:
            unmatched.append({"key": dev, "local_users": sorted(d["local_users"]),
                              "device_name": d["device_name"]})
    return matched, unmatched


def suggest_identity_csv(matched, unmatched):
    """The same proposals as a CSV a deployer can save, edit and feed back."""
    out = [
        "# key,identity",
        "# Proposed from local usernames. REVIEW BEFORE USE: these are string",
        "# matches, not authoritative. Anything wrong here puts the wrong name",
        "# on a report.",
    ]
    for m in matched:
        out.append("%s,%s  # via local user %s" % (m["key"], m["identity"], m["via"]))
    if unmatched:
        out.append("#")
        out.append("# No candidate identity. Fill these in from your MDM, RMM or CMDB:")
        for u in unmatched:
            out.append("# %s,   # local users: %s"
                       % (u["key"], ", ".join(u["local_users"]) or "(none)"))
    return "\n".join(out) + "\n"


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
        "person": "", "collector_seen": False, "scanner_seen": False,
        "collector_version": "",
    })
    identities = defaultdict(lambda: {
        "tools": set(), "surfaces": set(), "sources": set(),
        "accounts": set(), "findings": 0, "devices": set(),
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

        t = tools[tool]
        t["surfaces"].add(surface)
        t["findings"] += 1
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
            if acct:
                d["accounts"].add(acct)
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

    # Attach a person to each device, if the deployer supplied a mapping.
    # Device key first, then any local username: an MDM keys on the serial, a
    # spreadsheet is more likely to key on the name someone logs in with.
    for key, d in devices.items():
        person = identity_map.get(key)
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

    return devices, identities, tools, bridges, unattributed


def jsonable(d):
    return {k: (sorted(v) if isinstance(v, set) else v) for k, v in d.items()}


def graph_from(findings, domain_map=None, identity_map=None):
    """Everything above, assembled into the shape the API and the UI read."""
    devices, identities, tools, bridges, unattributed = build(
        findings, domain_map, identity_map)
    return {
        "devices": {k: jsonable(v) for k, v in devices.items()},
        "identities": {k: jsonable(v) for k, v in identities.items()},
        "tools": {
            k: dict(jsonable(v),
                    devices_by_surface={s2: sorted(d2) for s2, d2
                                        in v["devices_by_surface"].items()})
            for k, v in tools.items()
        },
        "bridges": {k: jsonable(v) for k, v in bridges.items()},
        "unattributed": unattributed,
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
        if ts > e["last_seen"]:
            e["last_seen"] = ts
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
         "Deploy ai-guard-collector.sh as a Jamf policy running as root on a "
         "recurring check-in. Set AIGUARD_RECEIVER_BASE, AIGUARD_TOKEN and "
         "AIGUARD_CORP_DOMAINS as script parameters."),
        ("endpoint", "collector-linux", "Linux collector", "endpoint/linux/README.md",
         "Run ai-guard-collector.sh as root on a schedule: an RMM, a cron job "
         "or a systemd timer. Same three environment variables as macOS."),
        ("endpoint", "collector-windows", "Windows collector", "endpoint/windows/README.md",
         "Deploy ai-guard-collector.ps1 as an Intune platform script. Same "
         "three variables, set at the top of the script or as parameters."),
        ("browser", "paste_guard", "Browser extension", "extension/README.md",
         "Push the extension by managed policy (Jamf for Chrome/Edge on macOS, "
         "Intune ADMX on Windows) with the receiver URL and token in the "
         "managed configuration."),
        ("cloud", "entra_sign_in", "Entra sign-ins", "scanner/README.md",
         "Register an app in Entra with AuditLog.Read.All and Directory.Read.All, "
         "then set AIGUARD_ENTRA_TENANT_ID, _CLIENT_ID and _CLIENT_SECRET."),
        ("cloud", "entra_delegated_access", "Entra delegated access", "scanner/README.md",
         "Same app registration as sign-ins. Covers non-interactive use that "
         "sign-in logs miss."),
        ("cloud", "entra_consent_grant", "Entra consent grants", "scanner/README.md",
         "Same app registration. Reports OAuth grants users have given to "
         "third-party applications."),
        ("cloud", "entra_service_principal", "Entra service principals", "scanner/README.md",
         "Same app registration. Reports non-human identities, which are how "
         "hidden agents usually appear."),
        ("cloud", "exchange_email", "Exchange signup evidence", "scanner/README.md",
         "Add Mail.Read to the Entra app registration. Finds accounts created "
         "with a work email outside SSO, which disabling Entra does not close."),
        ("fleet", "jamf_app", "Jamf applications", "scanner/README.md",
         "A Jamf Pro API client with read access to computer inventory. Set "
         "AIGUARD_JAMF_URL, _CLIENT_ID and _CLIENT_SECRET."),
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
         "AIGUARD_S1_URL and AIGUARD_S1_TOKEN."),
        ("network", "sentinelone_network", "SentinelOne network", "scanner/README.md",
         "Same SentinelOne token. Catches local process bridges that never "
         "touch a browser."),
        ("network", "sentinelone_bridge", "SentinelOne bridge targets", "scanner/README.md",
         "Same SentinelOne token. Reports where an AI tool reached, not tools "
         "someone installed."),
        ("mcp", "mcp_scan", "MCP integration scan", "scanner/README.md",
         "Produced by the endpoint collectors reading AI tool config files. If "
         "a collector is reporting and this is not, nobody has wired up an MCP "
         "server yet."),
    ]
    rows = []
    for group, src, label, doc, needs in expected:
        e = by_source.get(src)
        rows.append({
            "group": group,
            "source": src,
            "label": label,
            "doc": doc,
            "needs": needs,
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