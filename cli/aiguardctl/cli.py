# Copyright 2026 Aman Karir
# SPDX-License-Identifier: Apache-2.0
# Part of Shadow AI Guard, https://github.com/AmanSK5/shadow-ai-guard

"""aiguardctl upgrade [--portal URL] [--context CTX] [--namespace NS] [--yes] [--dry-run]"""
from __future__ import annotations

import argparse
import sys

from . import __version__, api, auth, detect, edition, upgrade


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
    if a.edition:
        return cmd_edition(a, portal, found)
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
    # Whatever happens from here, the run is closed with an outcome: a run
    # left "running" on System health after the terminal is gone is the one
    # thing an owner cannot tell apart from an upgrade still in progress.
    try:
        ok = upgrade.apply(found, target, rep)
        if not ok:
            rep.finish("failed", "a command exited non-zero; see the terminal")
            return 1
        result = upgrade.verify(portal, token, target, say)
    except KeyboardInterrupt:
        rep.finish("aborted", "interrupted at the terminal")
        say("Interrupted. The commands that already ran are not undone; "
            "System health shows how far it got.")
        return 130
    except Exception as e:  # noqa: BLE001 - closed with a reason, then re-raised
        rep.finish("failed", ("the command stopped: %s" % e)[:300])
        raise
    if result is None:
        rep.finish("unverified", "the commands ran, but the portal did not confirm "
                   "%s within the wait; check System health" % target)
        say("The upgrade commands ran, but the portal did not confirm %s in time. "
            "Open System health: if it shows %s, the upgrade is done and only the "
            "confirmation was missed." % (target, target))
        return 1
    srcs = result.get("sources") or {}
    detail = "portal %s, receiver %s" % (result.get("portal_version"), result.get("receiver_version"))
    if srcs:
        detail += ", %s of %s sources reporting" % (srcs.get("reporting"), srcs.get("total"))
    rep.finish("succeeded", detail)
    say("Done. " + detail)
    return 0


def cmd_edition(a, portal: str, found: dict) -> int:
    """`upgrade --edition nyxus`: the same approval and the same reporting as an
    upgrade, with the plan from edition.py."""
    if not a.nyxus_version:
        say("--nyxus-version is required with --edition nyxus: the release comes with your subscription."); return 2
    try:
        key = edition.load_key(a.key_file)
    except edition.EditionError as e:
        say(str(e)); return 2
    if found["route"] == "kubernetes":
        say("This deployment was not installed with Helm. Moving it to Nyxus in place is a Helm or "
            "Docker Compose operation; docs/upgrading-to-nyxus.md has the steps by hand."); return 2
    if found["route"] == "compose" and not a.nyxus_compose_file:
        say("This deployment runs on Docker Compose: pass --nyxus-compose-file with Nyxus's compose file."); return 2
    try:
        token = "" if a.dry_run else auth.authorize(portal, say)
        plan = api.request(portal, "GET", "/api/upgrade/plan", token=token) if token else {}
    except auth.Denied as e:
        say("Not approved: %s" % e); return 3
    except api.ApiError as e:
        say("The portal refused: %s" % e.detail); return 1
    host = edition.REGISTRY
    if token:
        try:
            host = edition.check_key(key, plan.get("activation"))
        except edition.EditionError as e:
            say("Stopped before changing anything: %s" % e); return 3
    try:
        moving = edition.plan(found, key, host, a.nyxus_version, a.nyxus_release, a.nyxus_compose_file,
                              pull=not a.no_pull)
    except (edition.EditionError, detect.DetectError) as e:
        say("Could not plan the move: %s" % e); return 1
    try:
        for line in edition.describe(found, moving, a.nyxus_version, host, key):
            say(line)
        if a.dry_run:
            say("Dry run: nothing was run and nothing was approved. The key is checked against this "
                "deployment once an owner approves."); return 0
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
            "to_version": ("nyxus-" + a.nyxus_version.lstrip("v"))[:64],
            "plan": {"route": found["route"], "edition": "nyxus", "objects": moving.objects}}, token=token)
        rep = upgrade.Reporter(portal, token, run["id"], say)
        try:
            ok = edition.apply(moving, rep)
            if not ok:
                rep.finish("failed", "a step failed; see the terminal")
                say("The move stopped. The database as it was is at %s." % moving.backup)
                return 1
            rep.patient = True
            result = upgrade.verify(portal, token, a.nyxus_version, say)
        except KeyboardInterrupt:
            rep.finish("aborted", "interrupted at the terminal")
            say("Interrupted. The steps that already ran are not undone; the database as it was "
                "is at %s." % moving.backup)
            return 130
        if result is None:
            rep.finish("unverified", "Nyxus did not confirm %s within the wait" % a.nyxus_version)
            say("The steps ran, but the portal did not answer as Nyxus %s in time. Open System health." % a.nyxus_version)
            return 1
        rep.finish("succeeded", "Nyxus %s" % result.get("portal_version"))
        say("Done: this deployment runs Nyxus %s. Next, replace the collector scripts in your MDM with "
            "Nyxus's, in the same policies; each machine keeps its identity." % result.get("portal_version"))
        return 0
    finally:
        edition.cleanup(moving)


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
    u.add_argument("--edition", choices=["nyxus"], help="move this deployment to another edition, in place: nyxus")
    u.add_argument("--nyxus-version", help="the Nyxus release to install (with --edition nyxus)")
    u.add_argument("--key-file", help="read the activation key from this file rather than NYXUS_KEY")
    u.add_argument("--nyxus-compose-file", help="Nyxus's docker-compose.yml, for a Docker Compose deployment")
    u.add_argument("--nyxus-release", default="nyxus", help="the Helm release name for Nyxus (default: nyxus)")
    u.add_argument("--no-pull", action="store_true",
                   help="on Docker Compose, Nyxus's images are already on this host (loaded for an air-gapped install): "
                        "do not sign in to the registry or pull")
    u.set_defaults(func=cmd_upgrade)
    a = p.parse_args(argv)
    return a.func(a)


if __name__ == "__main__":
    sys.exit(main())
