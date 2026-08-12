"""Paste guard events: what was stopped, on which tool, and how often.

Placed in its own module rather than derive.py because of what it must not do.
The paste guard inspects clipboard content on the device and reports detector
identifiers only; the matched text never leaves the page, and nothing in this
file may reintroduce a path that carries it. Every field here comes from the
finding's own metadata, and there is a test asserting that no function in this
module returns anything resembling content.

A finding looks like this:

    tool: chatgpt.com   surface: browser   source: paste_guard
    severity: warn      evidence: "paste warned: aws_access_key,payment_card"

Two things about that shape matter.

The heartbeat uses the same source. It is `tool: paste-guard`, `severity:
info`, `evidence: "heartbeat version=1.3.0 mode=warn reason=installed"`, and it
is how a device proves the guard is working rather than merely installed.
Counting it as a detection would report every device's daily heartbeat as a
paste someone tried to make, which is a number wrong in the direction nobody
checks.

The action is the interesting part. `warned` is the guard working: somebody was
shown what they were about to paste and stopped. `overridden` is the same
person deciding to paste it anyway, which is a deliberate act by someone who
had been told, and the strongest single signal this platform produces.
`blocked` is the guard in block mode refusing outright.
"""

import re
from collections import defaultdict

# Only these are paste events. Anything else on this source is the heartbeat or
# something that has not been written yet, and is left alone rather than
# guessed at.
ACTIONS = ("warned", "blocked", "overridden")

# What a detector id may contain. Every id in guard.js is lowercase, digits and
# underscores, and constraining it here is not tidiness: evidence is a 2048
# character operator-adjacent string, and a parser that split on commas and
# passed the rest through would carry anything appended to an id straight into
# the output. A test caught exactly that, with the matched secret written into
# the evidence field.
_DETECTOR_ID = re.compile(r"^[a-z0-9_]{1,64}$")

# The tool name the heartbeat reports under. It is the guard itself, not a tool
# anybody uses, and derive.NOT_A_TOOL excludes it from the register for the
# same reason.
GUARD_TOOL = "paste-guard"


def _parse_heartbeat(evidence):
    """(version, mode) from a heartbeat, or (None, None).

    The heartbeat is deliberately not a detection, and it is not noise either.
    It is the only thing that distinguishes an estate where nobody pasted a
    secret from one where the guard was never deployed, and those look
    identical in an event count of zero. The extension writes lastHeartbeat
    only on confirmed delivery, so a device appearing here has a working chain
    end to end rather than merely having the extension installed.

    version and mode come free in the same string, and both matter: a fleet
    split across versions is a rollout that stalled, and a device in warn mode
    where policy says block is a policy that is not in force.
    """
    ev = (evidence or "").strip()
    if not ev.startswith("heartbeat"):
        return None, None
    fields = {}
    for part in ev.split():
        if "=" in part:
            k, _, v = part.partition("=")
            fields[k] = v
    return fields.get("version") or "", fields.get("mode") or ""


def _parse(evidence):
    """(action, [detector ids]) from an evidence string, or (None, []).

    Returns None for anything that is not a paste event, which is how the
    heartbeat is excluded: it shares this source and its evidence starts with
    "heartbeat", so a parser keyed on the action prefix skips it without
    needing to know what a heartbeat is.
    """
    ev = (evidence or "").strip()
    if not ev.startswith("paste "):
        return None, []
    rest = ev[len("paste "):]
    action, _, listed = rest.partition(":")
    action = action.strip().lower()
    if action not in ACTIONS:
        return None, []
    # Anything that is not shaped like an id is discarded rather than cleaned
    # up. A malformed entry means the evidence is not what this parser expects,
    # and the safe reading of that is fewer detectors, never more content.
    detectors = [d.strip() for d in listed.split(",")
                 if _DETECTOR_ID.match(d.strip())]
    return action, detectors


def paste_guard_from(findings, domain_map=None):
    """Paste guard activity, as counts and per-tool rows.

    Metadata only. tool, action, detector ids, device, and when. The content
    that triggered the detector is not in the finding and must never be.

    Rows are per tool rather than per event, because the question a governance
    reader has is which tools people are pasting secrets into, not a
    chronological log. The event count and the device count are both kept: five
    pastes on one machine and five pastes across five machines are different
    situations and a single number cannot tell them apart.
    """
    from app.derive import normalise_tool

    domain_map = domain_map or {}
    tools = defaultdict(lambda: {
        "warned": 0, "blocked": 0, "overridden": 0,
        "detectors": defaultdict(int), "devices": set(),
        "first_seen": "", "last_seen": "",
    })
    detectors_total = defaultdict(int)
    devices = set()
    counts = {"warned": 0, "blocked": 0, "overridden": 0}
    # Devices whose guard checked in, and what they are running. Kept apart
    # from the event counts on purpose: a heartbeat is not something somebody
    # tried to paste.
    guard_devices = set()
    guard_versions = defaultdict(set)
    guard_modes = defaultdict(set)

    for f in findings:
        if (f.get("source") or "") != "paste_guard":
            continue
        device = (f.get("device") or "").strip()

        version, mode = _parse_heartbeat(f.get("evidence"))
        if version is not None:
            if device:
                guard_devices.add(device)
                if version:
                    guard_versions[version].add(device)
                if mode:
                    guard_modes[mode].add(device)
            continue

        action, detectors = _parse(f.get("evidence"))
        if not action:
            continue

        tool = f.get("tool") or ""
        if not tool or tool == GUARD_TOOL:
            # A paste event should never carry the guard's own name, but if it
            # did it would be the heartbeat leaking through a future change,
            # and counting it as a detection is the failure this guards.
            continue
        tool = normalise_tool(tool, domain_map)

        t = tools[tool]
        t[action] += 1
        counts[action] += 1

        if device:
            t["devices"].add(device)
            devices.add(device)

        for d in detectors:
            t["detectors"][d] += 1
            detectors_total[d] += 1

        ts = f.get("reported_at") or ""
        if ts:
            if not t["first_seen"] or ts < t["first_seen"]:
                t["first_seen"] = ts
            if ts > t["last_seen"]:
                t["last_seen"] = ts

    rows = []
    for tool, t in tools.items():
        rows.append({
            "tool": tool,
            "warned": t["warned"],
            "blocked": t["blocked"],
            "overridden": t["overridden"],
            "events": t["warned"] + t["blocked"] + t["overridden"],
            "devices": len(t["devices"]),
            # Which detectors fired here, commonest first. Identifiers only:
            # "aws_access_key", never what matched it.
            "detectors": [d for d, _ in sorted(
                t["detectors"].items(), key=lambda kv: (-kv[1], kv[0]))],
            "first_seen": t["first_seen"],
            "last_seen": t["last_seen"],
        })

    # Overrides first. Someone shown a warning naming the detector and pasting
    # anyway is the row worth following up, and sorting by total events would
    # bury one override under twenty warnings that worked.
    rows.sort(key=lambda r: (-r["overridden"], -r["events"], r["tool"]))

    return {
        "rows": rows,
        "warned": counts["warned"],
        "blocked": counts["blocked"],
        "overridden": counts["overridden"],
        "events": sum(counts.values()),
        "devices": len(devices),
        "tools": len(rows),
        "detectors": [
            {"detector": d, "count": c}
            for d, c in sorted(detectors_total.items(),
                               key=lambda kv: (-kv[1], kv[0]))
        ],
        # Devices whose guard checked in during the window. Without this,
        # "0 pastes stopped" reads as an estate where nobody pasted a secret
        # and an estate where the extension was never deployed, and those are
        # the same number.
        "guard_devices": len(guard_devices),
        "guard_versions": [
            {"version": v, "devices": len(d)}
            for v, d in sorted(guard_versions.items(), reverse=True)
        ],
        "guard_modes": [
            {"mode": m, "devices": len(d)}
            for m, d in sorted(guard_modes.items())
        ],
    }