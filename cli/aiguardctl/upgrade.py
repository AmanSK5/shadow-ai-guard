# Copyright 2026 Aman Karir
# SPDX-License-Identifier: Apache-2.0
# Part of Shadow AI Guard, https://github.com/AmanSK5/shadow-ai-guard

"""Plan, confirm, apply, report. The plan names every object the command
will touch and every command it will run; nothing runs before the person
has seen it. Progress reports carry step names and outcomes only - never
command output, which can hold values or errors with secrets in them."""
from __future__ import annotations

import os
import time

from . import api, detect

CHART = "oci://ghcr.io/amansk5/shadow-ai-guard/charts/ai-guard"


class Reporter:
    """Posts steps to the portal and shrugs when it cannot: the portal
    restarts mid-rollout by design, and a missed report must never fail
    the upgrade. Retries a few times with a pause, then moves on."""

    def __init__(self, portal: str, token: str, run_id: str, say, sleep=time.sleep,
                 request=api.request):
        self.portal, self.token, self.run_id = portal, token, run_id
        self.say, self.sleep, self.request = say, sleep, request
        # Off while the portal is known to be down - between stopping one
        # edition and starting the next - so a report tries once and moves
        # on, rather than holding the next step back for two minutes.
        self.patient = True
        # Said once per outage. A portal that is down stays down for several
        # steps, and the same line after each of them buries the steps.
        self._unreachable = False

    def _post(self, path: str, body: dict) -> None:
        for attempt in range(6 if self.patient else 1):
            try:
                self.request(self.portal, "POST", path, body, token=self.token)
                self._unreachable = False
                return
            except api.ApiError as e:
                if e.status in (401, 403, 404, 409, 413, 422):
                    self.say("  (the portal refused a progress report: %s)" % e.detail)
                    return
                if self.patient:
                    self.sleep(min(30, 5 * (attempt + 1)))
        if not self._unreachable:
            self._unreachable = True
            self.say("  (could not reach the portal to report progress; carrying on, and saying so "
                     "once: reports resume when it answers)")

    def step(self, step: str, status: str, detail: str = "") -> None:
        self.say("  [%s] %s%s" % (status, step, (" - " + detail) if detail else ""))
        self._post("/api/upgrade/runs/%s/steps" % self.run_id,
                   {"step": step[:80], "status": status, "detail": detail[:300]})

    def finish(self, outcome: str, detail: str = "") -> None:
        self._post("/api/upgrade/runs/%s/finish" % self.run_id,
                   {"outcome": outcome, "detail": detail[:300]})


def _tag_of(line: str) -> str | None:
    """The value if this .env line sets IMAGE_TAG, else None."""
    name, eq, value = line.partition("=")
    if not eq or name.strip() != "IMAGE_TAG":
        return None
    return value.strip().strip("'\"")


def compose_tag(found: dict, target: str) -> dict:
    """Where a compose project's version lives, and what it becomes.

    `pull` and `up -d` alone change nothing: they fetch the tag the project
    already names and restart it, and the plan used to report that as an
    upgrade. The version has to change where every later `docker compose up`
    reads it again, which for the shipped compose file is IMAGE_TAG in the
    project's .env.

    Raises DetectError rather than guessing when the project does not read
    its version from there - a compose file with its own tags written in is
    somebody's edit, and rewriting it is not this command's to do.
    """
    wd = found.get("working_dir") or ""
    if not wd or not os.path.isdir(wd):
        raise detect.DetectError(
            "the compose project's directory (%s) is not on this machine. Run "
            "this on the machine the stack runs on" % (wd or "unknown"))
    files = [f for f in (found.get("config_files") or "").split(",") if f]
    text = ""
    for f in files or [os.path.join(wd, "docker-compose.yml")]:
        try:
            with open(f) as fh:
                text += fh.read()
        except OSError as e:
            raise detect.DetectError("cannot read %s: %s" % (f, e.strerror))
    if "${IMAGE_TAG" not in text:
        raise detect.DetectError(
            "%s names its image tags itself rather than reading IMAGE_TAG from "
            ".env. Change them to %s and run `docker compose up -d`, or use "
            "${IMAGE_TAG} the way the shipped file does"
            % (", ".join(files) or "the compose file", target.lstrip("v")))
    path = os.path.join(wd, ".env")
    old = ""
    try:
        with open(path) as fh:
            for line in fh:
                if _tag_of(line) is not None:
                    old = _tag_of(line)
    except FileNotFoundError:
        pass
    return {"path": path, "old": old, "new": target.lstrip("v")}


def set_tag(edit: dict) -> str | None:
    """Write IMAGE_TAG into .env, keeping every other line. Returns what was
    there before, or None if there was no file, so a failed pull can put it
    back."""
    try:
        with open(edit["path"]) as fh:
            before = fh.read()
    except FileNotFoundError:
        before = None
    lines = (before or "").splitlines(keepends=True)
    out, done = [], False
    for line in lines:
        if _tag_of(line) is not None:
            if not done:
                out.append("IMAGE_TAG=%s\n" % edit["new"])
                done = True
            continue                  # a second definition would win; drop it
        out.append(line if line.endswith("\n") else line + "\n")
    if not done:
        out.append("IMAGE_TAG=%s\n" % edit["new"])
    with open(edit["path"], "w") as fh:
        fh.write("".join(out))
    return before


def put_back(edit: dict, before: str | None) -> None:
    if before is None:
        try:
            os.unlink(edit["path"])
        except OSError:
            pass
        return
    with open(edit["path"], "w") as fh:
        fh.write(before)


def commands(found: dict, target: str) -> list[list[str]]:
    """Exactly what will run, in order. Shown before anything runs and used
    verbatim afterwards, so the plan and the action cannot differ."""
    v = target.lstrip("v")
    cmds: list[list[str]] = []
    if found["route"] == "helm":
        base = ["helm"] + (["--kube-context", found["context"]] if found.get("context") else [])
        # --reset-then-reuse-values, NOT --reuse-values.
        #
        # --reuse-values takes the previous release's computed values as the
        # base and drops every default the new chart carries underneath them.
        # Where the old chart had no such section at all - scanner, discovery
        # and portal were each added after 0.32.0 - the section does not arrive
        # partially filled, it does not arrive at all, and the template
        # dereferences nil. An upgrade from 0.32.0 to 0.35.0 died on
        # `.Values.scanner.enabled: nil pointer evaluating interface {}.enabled`,
        # which tells the operator nothing about what they did.
        #
        # The chart's guards now catch that and say what to do, but the right
        # fix is not to send the flag that causes it. charts/ai-guard/README.md
        # has said "--reset-then-reuse-values, not --reuse-values" since the
        # portal was added; this is the command catching up with it.
        cmds.append(base + ["upgrade", found["release"], CHART, "--version", v,
                            "--namespace", found["namespace"],
                            "--reset-then-reuse-values", "--wait",
                            "--timeout", "10m"])
    elif found["route"] == "kubernetes":
        base = ["kubectl"] + (["--context", found["context"]] if found.get("context") else [])
        for d in found["deployments"]:
            comp = d["image"][len(detect.IMAGE_REPO) + 1:].split(":")[0].split("@")[0]
            cmds.append(base + ["-n", found["namespace"], "set", "image",
                                "deployment/" + d["name"],
                                "%s=%s/%s:%s" % (d["container"], detect.IMAGE_REPO, comp, v)])
    if found["route"] in ("helm", "kubernetes"):
        base = ["kubectl"] + (["--context", found["context"]] if found.get("context") else [])
        for cj in found.get("cronjobs", []):
            comp = cj["image"][len(detect.IMAGE_REPO) + 1:].split(":")[0].split("@")[0]
            cmds.append(base + ["-n", found["namespace"], "set", "image",
                                "cronjob/" + cj["name"],
                                "%s=%s/%s:%s" % (cj["container"], detect.IMAGE_REPO, comp, v)])
        if found["route"] == "kubernetes":
            for d in found["deployments"]:
                cmds.append(base + ["-n", found["namespace"], "rollout", "status",
                                    "deployment/" + d["name"], "--timeout=10m"])
    if found["route"] == "compose":
        # The project by name, as well as by directory. Without it Compose takes
        # the name from the file (`name: ai-guard` in the shipped one), so a
        # stack started under any other name with -p or COMPOSE_PROJECT_NAME was
        # not upgraded: a second stack came up beside it, on empty volumes.
        base = ["docker", "compose", "--project-directory", found["working_dir"],
                "-p", found["project"]]
        for f in [x for x in (found.get("config_files") or "").split(",") if x]:
            base += ["-f", f]
        services = sorted({s["service"] for s in found["services"]})
        cmds.append(base + ["pull"] + services)
        cmds.append(base + ["up", "-d", "--no-deps"] + services)
    return cmds


def describe(found: dict, plan: dict, target: str) -> list[str]:
    lines = ["Upgrade plan", ""]
    lines.append("  Portal   %s   Receiver %s   Target %s" % (
        plan.get("portal_version"), plan.get("receiver_version"), target))
    if found["route"] in ("helm", "kubernetes"):
        lines.append("  Route    %s, release %s in namespace %s" % (
            found["route"], found.get("release") or "-", found["namespace"]))
        for d in found["deployments"]:
            lines.append("  Deploy   %s (%s) %s -> %s" % (d["name"], d["container"], d["tag"], target.lstrip("v")))
        for cj in found.get("cronjobs", []):
            lines.append("  CronJob  %s (%s) %s -> %s" % (cj["name"], cj["container"], cj["tag"], target.lstrip("v")))
        if not found.get("cronjobs"):
            lines.append("  CronJob  none running this project's scanner or discovery images")
    else:
        lines.append("  Route    compose, project %s in %s" % (found["project"], found["working_dir"]))
        edit = found.get("tag_edit")
        if edit:
            lines.append("  Edit     %s: IMAGE_TAG %s -> %s" % (
                edit["path"], edit["old"] or "(unset)", edit["new"]))
        for s in found["services"]:
            lines.append("  Service  %s %s -> %s" % (s["service"], s["tag"], target.lstrip("v")))
    lines.append("")
    lines.append("Commands, in order:")
    for c in commands(found, target):
        lines.append("  $ " + " ".join(c))
    lines.append("")
    lines.append("The receiver and the portal restart. Collectors keep reporting through it;")
    lines.append("nothing stored is touched. Progress is shown on System health.")
    return lines


def apply(found: dict, target: str, reporter: Reporter, runner=detect.run) -> bool:
    edit, before, started = found.get("tag_edit"), None, False
    if edit:
        reporter.step("set IMAGE_TAG", "running")
        try:
            before = set_tag(edit)
        except OSError as e:
            reporter.step("set IMAGE_TAG", "failed", e.strerror or "")
            return False
        reporter.step("set IMAGE_TAG", "done")
    for argv in commands(found, target):
        name = " ".join(argv[:3]) if argv[0] != "kubectl" else " ".join(
            [a for a in argv if a not in ("-n", found.get("namespace", ""))][:5])
        reporter.step(name, "running")
        code, out, err = runner(argv, timeout=900)
        if code != 0:
            reporter.step(name, "failed", "exit %d" % code)
            reporter.say(err.strip()[-2000:] or out.strip()[-2000:])
            if edit and not started:
                # Nothing was restarted, so nothing runs the new tag yet. Left
                # in place, the next `docker compose up` for any reason would
                # be the upgrade that just failed, unannounced.
                put_back(edit, before)
                reporter.say("  IMAGE_TAG put back to %s" % (edit["old"] or "(unset)"))
            return False
        if "up" in argv:
            started = True
        reporter.step(name, "done")
    return True


def verify(portal: str, token: str, target: str, say, request=api.request,
           sleep=time.sleep, timeout: int = 600) -> dict | None:
    """Wait for the portal to answer with the target version, then ask it
    whether the receiver did too and whether sources are reporting."""
    want = target.lstrip("v")
    deadline = time.time() + timeout
    say("  waiting for the portal to come back as %s" % want)
    while time.time() < deadline:
        # Anything the network throws while the portal is coming back is
        # a reason to wait, not to stop: the upgrade itself already ran.
        try:
            health = request(portal, "GET", "/healthz")
        except (api.ApiError, OSError):
            health = {}
        if str(health.get("version", "")).lstrip("v") == want:
            for _ in range(6):
                try:
                    return request(portal, "GET", "/api/upgrade/verify", token=token)
                except (api.ApiError, OSError):
                    sleep(5)
            return None
        sleep(5)
    return None
