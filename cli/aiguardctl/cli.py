"""aiguardctl upgrade [--portal URL] [--context CTX] [--namespace NS] [--yes] [--dry-run]"""
from __future__ import annotations

import argparse
import sys

from . import __version__, api, auth, detect, upgrade


def say(msg: str = "") -> None:
    print(msg, file=sys.stderr)


def cmd_upgrade(a) -> int:
    portal = a.portal.rstrip("/")
    if not portal.startswith(("http://", "https://")):
        say("--portal must be an http(s) URL"); return 2
    # What is deployed, with the operator's own tools, before asking anyone.
    try:
        found = None
        if not a.compose:
            found = detect.kubernetes(a.context, a.namespace)
        if found is None and not a.kubernetes:
            found = detect.compose()
    except detect.DetectError as e:
        say("Could not read the deployment: %s" % e); return 1
    if found is None:
        say("Nothing of this project's was found with kubectl or docker. Check the "
            "context you are pointed at, or say --namespace / --compose."); return 1
    try:
        token = "" if a.dry_run else auth.authorize(portal, say)
        plan = api.request(portal, "GET", "/api/upgrade/plan", token=token) if token else {}
    except auth.Denied as e:
        say("Not approved: %s" % e); return 3
    except api.ApiError as e:
        say("The portal refused: %s" % e.detail); return 1
    target = a.version or (plan.get("latest") or "")
    if not target:
        say("No target version: the portal does not know the latest release and "
            "--version was not given."); return 1
    for line in upgrade.describe(found, plan, target):
        say(line)
    if a.dry_run:
        say("Dry run: nothing was run and nothing was approved."); return 0
    if not a.yes:
        try:
            answer = input("Proceed? [y/N] ").strip().lower()
        except EOFError:
            answer = ""
        if answer not in ("y", "yes"):
            say("Stopped before running anything."); return 3
    run = api.request(portal, "POST", "/api/upgrade/runs", {
        "route": found["route"],
        "from_version": str(plan.get("portal_version") or "unknown"),
        "to_version": target,
        "plan": {"route": found["route"], "namespace": found.get("namespace"),
                 "release": found.get("release"), "project": found.get("project"),
                 "objects": [d["name"] for d in found.get("deployments", [])]
                 + [c["name"] for c in found.get("cronjobs", [])]
                 + [s["service"] for s in found.get("services", [])]}},
        token=token)
    rep = upgrade.Reporter(portal, token, run["id"], say)
    ok = upgrade.apply(found, target, rep)
    if not ok:
        rep.finish("failed", "a command exited non-zero; see the terminal")
        return 1
    result = upgrade.verify(portal, token, target, say)
    if result is None:
        rep.finish("failed", "the portal did not come back as %s in time" % target)
        return 1
    srcs = result.get("sources") or {}
    detail = "portal %s, receiver %s" % (result.get("portal_version"), result.get("receiver_version"))
    if srcs:
        detail += ", %s of %s sources reporting" % (srcs.get("reporting"), srcs.get("total"))
    rep.finish("succeeded", detail)
    say("Done. " + detail)
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="aiguardctl",
                                description="Upgrade a Shadow AI Guard deployment from "
                                            "your own machine with your own credentials.")
    p.add_argument("--version", action="version", version="aiguardctl %s" % __version__)
    sub = p.add_subparsers(dest="cmd", required=True)
    u = sub.add_parser("upgrade", help="upgrade the deployment the portal describes")
    u.add_argument("--portal", required=True, help="the portal's URL, e.g. https://ai-guard-portal.example.com")
    u.add_argument("--context", help="kubeconfig context (default: current)")
    u.add_argument("--namespace", help="namespace, when more than one release is found")
    u.add_argument("--kubernetes", action="store_true", help="do not look for a compose project")
    u.add_argument("--compose", action="store_true", help="do not look at Kubernetes")
    u.add_argument("--version", dest="version", help="target version (default: the latest release the portal knows)")
    u.add_argument("--yes", action="store_true", help="do not ask before running")
    u.add_argument("--dry-run", action="store_true", help="show the plan and the commands; run and approve nothing")
    u.set_defaults(func=cmd_upgrade)
    a = p.parse_args(argv)
    return a.func(a)


if __name__ == "__main__":
    sys.exit(main())
