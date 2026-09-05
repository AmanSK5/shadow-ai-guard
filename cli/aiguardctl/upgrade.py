"""Plan, confirm, apply, report. The plan names every object the command
will touch and every command it will run; nothing runs before the person
has seen it. Progress reports carry step names and outcomes only - never
command output, which can hold values or errors with secrets in them."""
from __future__ import annotations

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

    def _post(self, path: str, body: dict) -> None:
        for attempt in range(6):
            try:
                self.request(self.portal, "POST", path, body, token=self.token)
                return
            except api.ApiError as e:
                if e.status in (401, 403, 404, 409, 413, 422):
                    self.say("  (the portal refused a progress report: %s)" % e.detail)
                    return
                self.sleep(min(30, 5 * (attempt + 1)))
        self.say("  (could not reach the portal to report progress; carrying on)")

    def step(self, step: str, status: str, detail: str = "") -> None:
        self.say("  [%s] %s%s" % (status, step, (" - " + detail) if detail else ""))
        self._post("/api/upgrade/runs/%s/steps" % self.run_id,
                   {"step": step[:80], "status": status, "detail": detail[:300]})

    def finish(self, outcome: str, detail: str = "") -> None:
        self._post("/api/upgrade/runs/%s/finish" % self.run_id,
                   {"outcome": outcome, "detail": detail[:300]})


def commands(found: dict, target: str) -> list[list[str]]:
    """Exactly what will run, in order. Shown before anything runs and used
    verbatim afterwards, so the plan and the action cannot differ."""
    v = target.lstrip("v")
    cmds: list[list[str]] = []
    if found["route"] == "helm":
        base = ["helm"] + (["--kube-context", found["context"]] if found.get("context") else [])
        cmds.append(base + ["upgrade", found["release"], CHART, "--version", v,
                            "--namespace", found["namespace"], "--reuse-values", "--wait",
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
        base = ["docker", "compose", "--project-directory", found["working_dir"]]
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
    for argv in commands(found, target):
        name = " ".join(argv[:3]) if argv[0] != "kubectl" else " ".join(
            [a for a in argv if a not in ("-n", found.get("namespace", ""))][:5])
        reporter.step(name, "running")
        code, out, err = runner(argv, timeout=900)
        if code != 0:
            reporter.step(name, "failed", "exit %d" % code)
            reporter.say(err.strip()[-2000:] or out.strip()[-2000:])
            return False
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
        try:
            health = request(portal, "GET", "/healthz")
            if str(health.get("version", "")).lstrip("v") == want:
                return request(portal, "GET", "/api/upgrade/verify", token=token)
        except api.ApiError:
            pass
        sleep(5)
    return None
