# Copyright 2026 Aman Karir
# SPDX-License-Identifier: Apache-2.0
# Part of Shadow AI Guard, https://github.com/AmanSK5/shadow-ai-guard

"""`aiguardctl upgrade --edition nyxus`: move this deployment to Nyxus, in place.

The same shape as an upgrade and the same promises (SECURITY.md, "Upgrading"):
what is deployed is read with the operator's own tools, the plan names every
command before anything runs, an owner approves it in the portal, and progress
reports carry step names, never output.

In place, because Nyxus opens this receiver's own database. The database is
backed up beside itself first; Shadow AI Guard stops; Nyxus starts on the same
storage with the same credentials, and reads the findings Shadow AI Guard
stored for as far back as its reporting window reaches.

The activation key is the registry credential. It is read from NYXUS_KEY or a
file, checked against the key stored in this deployment by fingerprint, and
only handed to docker, helm and kubectl on standard input or in a file only
this user can read - never in a command's arguments, which every local user
can see.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from . import detect

REGISTRY = "registry.nyxus.co.uk"
REPOSITORY = "nyxus-enterprise"
STATE_DB = "/var/lib/ai-guard/state.db"
# Kubernetes Secrets holding the credentials the release made, copied before
# the release is removed, because uninstalling it removes its Secrets too.
CARRIED = {"auth": "nyxus-carried-auth", "admin": "nyxus-carried-admin", "portal": "nyxus-carried-portal"}
PULL_SECRET = "nyxus-registry"


class EditionError(Exception):
    pass


def run(argv: list[str], timeout: int = 900, input: str | None = None) -> tuple[int, str, str]:
    p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, input=input)
    return p.returncode, p.stdout, p.stderr


def fingerprint(key: str) -> str:
    """What the receiver shows for a stored key (activation.fingerprint)."""
    digest = hashlib.sha256(key.strip().encode()).hexdigest()
    return "-".join(digest[i:i + 4] for i in range(0, 12, 4))


def load_key(key_file: str | None, environ=os.environ) -> str:
    if key_file:
        try:
            key = Path(key_file).read_text().strip()
        except OSError as e:
            raise EditionError("could not read %s: %s" % (key_file, e.strerror)) from None
    else:
        key = (environ.get("NYXUS_KEY") or "").strip()
    if not key.startswith("nyxl_"):
        raise EditionError("no activation key: export NYXUS_KEY='<your activation key>', or pass --key-file")
    return key


def check_key(key: str, activation: dict | None) -> str:
    """The registry host to pull from, once the key handed to the command is
    shown to be the one stored in this deployment, stored as active."""
    a = activation or {}
    state = a.get("state")
    if state != "active":
        raise EditionError({
            "none": "this deployment has no activation key stored; activate it on System health first",
            "expired": "the activation key stored in this deployment has expired",
            "invalid": "the activation key stored in this deployment does not verify",
        }.get(state, "the portal did not say which key this deployment holds"))
    if fingerprint(key) != a.get("fingerprint"):
        raise EditionError("the key given is not the one stored in this deployment "
                           "(key %s is stored, key %s was given)" % (a.get("fingerprint"), fingerprint(key)))
    host = (a.get("registry") or REGISTRY).strip().split("/")[0]
    if not re.fullmatch(r"[A-Za-z0-9.-]+(:[0-9]+)?", host):
        raise EditionError("the key names a registry that is not a host name")
    return host


class Step:
    """One thing the move does. A command runs as given, with any secret on
    standard input; an action writes files or Secrets the plan describes."""

    def __init__(self, name: str, argv: list[str] | None = None, stdin: str | None = None,
                 action=None, shows: str = "", stops: bool = False):
        self.name, self.argv, self.stdin, self.action = name, argv, stdin, action
        self.shows = shows or " ".join(argv or [])
        # After this step the portal is down until Nyxus answers.
        self.stops = stops


class Plan:
    def __init__(self, route: str, steps: list[Step], workdir: str, backup: str, keeps: list[str], objects: list[str]):
        self.route, self.steps, self.workdir, self.backup = route, steps, workdir, backup
        self.keeps, self.objects = keeps, objects
        self.context: dict = {}


def _backup_code(stamp: str) -> tuple[str, str]:
    target = "%s.before-nyxus-%s" % (STATE_DB, stamp)
    code = ("import sqlite3;s=sqlite3.connect(%r);d=sqlite3.connect(%r);"
            "s.backup(d);d.close();s.close()" % (STATE_DB, target))
    return code, target


def _private_file(directory: str, name: str, content: str) -> str:
    path = os.path.join(directory, name)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(content)
    return path


def _group_of(path: str) -> int:
    return os.stat(path).st_gid


def _stamp(now) -> str:
    return now.strftime("%Y%m%dT%H%M%SZ")


def _instant(now) -> str:
    return now.strftime("%Y-%m-%dT%H:%M:%SZ")


# ------------------------------------------------------------------ helm --

def manifest_objects(text: str) -> list[dict]:
    """Kind, name and data keys of each object in `helm get manifest`."""
    objs = []
    for doc in re.split(r"^---[^\n]*$", text, flags=re.M):
        kind = re.search(r"^kind:\s*(\S+)", doc, re.M)
        meta = re.search(r"^metadata:\s*\n((?:[ \t]+.*\n?)*)", doc, re.M)
        name = re.search(r"^\s{2}name:\s*\"?([^\s\"]+)", meta.group(1), re.M) if meta else None
        if not (kind and name):
            continue
        keys = []
        data = re.search(r"^data:\s*\n((?:[ \t]+.*\n?)*)", doc, re.M)
        if data:
            keys = re.findall(r"^\s{2}([A-Za-z0-9_.-]+):", data.group(1), re.M)
        objs.append({"kind": kind.group(1), "name": name.group(1), "data": keys})
    return objs


def _get(d: dict, path: tuple):
    for p in path:
        if not isinstance(d, dict) or p not in d:
            return None
        d = d[p]
    return d


def _set(d: dict, path: tuple, value) -> None:
    for p in path[:-1]:
        d = d.setdefault(p, {})
    d[path[-1]] = value


def _drop(d: dict, path: tuple) -> None:
    parent = _get(d, path[:-1]) if len(path) > 1 else d
    if isinstance(parent, dict):
        parent.pop(path[-1], None)


def nyxus_values(user: dict, carried: dict, claim: str, stopped_at: str) -> dict:
    """The values Nyxus is installed with: the release's own, pointed at the
    storage and credentials it already had, and pulling from the registry."""
    v = json.loads(json.dumps(user or {}))
    for path in (("image",), ("portal", "image"), ("scanner", "image"), ("discovery", "image")):
        _drop(v, path)
    if "auth" in carried:
        _drop(v, ("auth", "value"))
        _set(v, ("auth", "existingSecret"), CARRIED["auth"])
    if "admin" in carried:
        _drop(v, ("managed", "adminToken", "value"))
        _set(v, ("managed", "adminToken", "existingSecret"), CARRIED["admin"])
    if "portal" in carried:
        _drop(v, ("portal", "auth", "password"))
        _set(v, ("portal", "auth", "existingSecret"), CARRIED["portal"])
    if claim:
        _set(v, ("managed", "persistence", "existingClaim"), claim)
    pulls = [p for p in (v.get("imagePullSecrets") or []) if p.get("name") != PULL_SECRET]
    v["imagePullSecrets"] = pulls + [{"name": PULL_SECRET}]
    _set(v, ("portal", "shadowAiGuardFindingsBefore"), stopped_at)
    return v


def helm_plan(found: dict, key: str, host: str, version: str, release: str,
              runner=run, now=None) -> Plan:
    now = now or datetime.now(timezone.utc)
    ns, rel = found["namespace"], found["release"]
    kube = ["kubectl"] + (["--context", found["context"]] if found.get("context") else [])
    helm = ["helm"] + (["--kube-context", found["context"]] if found.get("context") else [])
    code, out, err = runner(helm + ["get", "values", rel, "-n", ns, "-o", "json"], timeout=120)
    if code != 0:
        raise EditionError("helm could not read the release's values: %s" % err.strip()[:200])
    user = json.loads(out or "null") or {}
    code, out, err = runner(helm + ["get", "manifest", rel, "-n", ns], timeout=120)
    if code != 0:
        raise EditionError("helm could not read the release's manifest: %s" % err.strip()[:200])
    objs = manifest_objects(out)
    secrets_made = {}
    for o in (o for o in objs if o["kind"] == "Secret"):
        if "authToken" in o["data"]:
            secrets_made["auth"] = (o["name"], "authToken")
        elif "adminToken" in o["data"]:
            secrets_made["admin"] = (o["name"], "adminToken")
        elif "password" in o["data"] and o["name"].endswith("-portal"):
            secrets_made["portal"] = (o["name"], "password")
    claim = _get(user, ("managed", "persistence", "existingClaim")) or next(
        (o["name"] for o in objs if o["kind"] == "PersistentVolumeClaim"), "")
    if not claim:
        raise EditionError("this release has no receiver storage to keep; it may not run in managed mode")
    receiver = next((d["name"] for d in found["deployments"] if "/receiver:" in d["image"] or "/receiver@" in d["image"]), None)
    if not receiver:
        raise EditionError("no receiver Deployment of this release was found")

    workdir = tempfile.mkdtemp(prefix="aiguardctl-nyxus-")
    os.chmod(workdir, 0o700)
    values_path = os.path.join(workdir, "values.json")
    backup_code, backup_path = _backup_code(_stamp(now))
    plan = Plan("helm", [], workdir, backup_path, [], [])

    def carry(runner):
        for purpose, (name, data_key) in secrets_made.items():
            c, o, e = runner(kube + ["get", "secret", name, "-n", ns, "-o", "json"], timeout=120)
            if c != 0:
                raise EditionError("could not read Secret %s" % name)
            value = (json.loads(o).get("data") or {}).get(data_key)
            if not value:
                raise EditionError("Secret %s has no %s" % (name, data_key))
            doc = {"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
                   "metadata": {"name": CARRIED[purpose], "namespace": ns,
                                "labels": {"app.kubernetes.io/part-of": "nyxus"}},
                   "data": {data_key: value}}
            path = _private_file(workdir, CARRIED[purpose] + ".json", json.dumps(doc))
            try:
                c, _, e = runner(kube + ["apply", "-n", ns, "-f", path], timeout=120)
            finally:
                os.remove(path)
            if c != 0:
                raise EditionError("could not create Secret %s: %s" % (CARRIED[purpose], e.strip()[:200]))

    def pull_secret(runner):
        auth = base64.b64encode(("licence:" + key).encode()).decode()
        config = {"auths": {host: {"username": "licence", "password": key, "auth": auth}}}
        doc = {"apiVersion": "v1", "kind": "Secret", "type": "kubernetes.io/dockerconfigjson",
               "metadata": {"name": PULL_SECRET, "namespace": ns, "labels": {"app.kubernetes.io/part-of": "nyxus"}},
               "data": {".dockerconfigjson": base64.b64encode(json.dumps(config).encode()).decode()}}
        path = _private_file(workdir, PULL_SECRET + ".json", json.dumps(doc))
        try:
            c, _, e = runner(kube + ["apply", "-n", ns, "-f", path], timeout=120)
        finally:
            os.remove(path)
        if c != 0:
            raise EditionError("could not create the pull secret: %s" % e.strip()[:200])

    def wait_stopped(runner):
        c, _, e = runner(kube + ["wait", "--for=delete", "pod", "-n", ns,
                                 "-l", "app.kubernetes.io/instance=" + rel, "--timeout=5m"], timeout=360)
        if c != 0 and "no matching resources" not in e:
            raise EditionError("Shadow AI Guard's pods did not stop: %s" % e.strip()[:200])
        plan.context["stopped_at"] = _instant(datetime.now(timezone.utc))

    def write_values(runner):
        values = nyxus_values(user, secrets_made, claim, plan.context.get("stopped_at") or _instant(now))
        _private_file(workdir, "values.json", json.dumps(values, indent=2))

    chart = "oci://%s/%s/charts/nyxus" % (host, REPOSITORY)
    plan.steps = [
        Step("back up the receiver database", kube + ["-n", ns, "exec", "deployment/" + receiver, "--",
                                                     "python", "-c", backup_code]),
        Step("carry the release's credentials", action=carry,
             shows="copy %s into %s" % (", ".join(n for n, _ in secrets_made.values()) or "no Secrets",
                                          ", ".join(CARRIED[p] for p in secrets_made) or "-")),
        Step("sign in to the registry", helm + ["registry", "login", host, "--username", "licence", "--password-stdin"],
             stdin=key),
        Step("create the pull secret", action=pull_secret,
             shows="create Secret %s (docker-registry, %s) from the key, in a file only you can read" % (PULL_SECRET, host)),
    ] + [Step("stop " + d["name"], kube + ["-n", ns, "scale", "deployment/" + d["name"], "--replicas=0"])
         for d in found["deployments"]] + [
        Step("wait for Shadow AI Guard to stop", action=wait_stopped, stops=True,
             shows=" ".join(kube + ["wait", "--for=delete", "pod", "-n", ns, "-l", "app.kubernetes.io/instance=" + rel, "--timeout=5m"])),
        Step("remove the Shadow AI Guard release", helm + ["uninstall", rel, "-n", ns, "--wait"]),
        Step("write Nyxus's values", action=write_values,
             shows="write %s: this release's values, on %s, with the carried credentials" % (values_path, claim)),
        Step("install Nyxus", helm + ["install", release, chart, "--version", version.lstrip("v"),
                                      "-n", ns, "-f", values_path, "--wait", "--timeout", "10m"]),
    ]
    plan.keeps = ["the receiver database, on %s (backed up first to %s)" % (claim, backup_path),
                  "the shared token, the admin token and the portal password",
                  "this release's other values: ingress, log store, scanner and discovery settings"]
    plan.objects = [rel, claim, receiver] + [n for n, _ in secrets_made.values()]
    return plan


# --------------------------------------------------------------- compose --

def _translate_env(text: str) -> str:
    """Shadow AI Guard's variable names in Nyxus's: AIGUARD_ becomes NYXUS_."""
    return "\n".join(re.sub(r"^(\s*(?:export\s+)?)AIGUARD_", r"\1NYXUS_", line) for line in text.splitlines()) + "\n"


def compose_plan(found: dict, key: str, host: str, version: str, compose_file: str,
                 runner=run, now=None, pull: bool = True) -> Plan:
    now = now or datetime.now(timezone.utc)
    nyx_file = os.path.abspath(compose_file)
    if not os.path.isfile(nyx_file):
        raise EditionError("no compose file at %s" % nyx_file)
    nyx_dir = os.path.dirname(nyx_file)
    old_dir = found["working_dir"]
    for name in (".env", "secrets", "scanner.env", "discovery.env"):
        if os.path.exists(os.path.join(nyx_dir, name)):
            raise EditionError("%s already exists beside Nyxus's compose file; point --nyxus-compose-file "
                               "at a fresh copy so nothing there is overwritten" % os.path.join(nyx_dir, name))
    token_file = os.path.join(old_dir, "secrets", "auth_token")
    if not os.path.isfile(token_file):
        raise EditionError("no %s: the running deployment's shared token was not found" % token_file)
    project = found["project"]
    old = ["docker", "compose", "-p", project, "--project-directory", old_dir]
    for f in [x for x in (found.get("config_files") or "").split(",") if x]:
        old += ["-f", f]
    env_path = os.path.join(nyx_dir, ".env")
    new = ["docker", "compose", "-p", project, "--project-directory", nyx_dir, "-f", nyx_file, "--env-file", env_path]
    services = sorted({s["service"] for s in found["services"]})
    backup_code, backup_path = _backup_code(_stamp(now))
    workdir = tempfile.mkdtemp(prefix="aiguardctl-nyxus-")
    plan = Plan("compose", [], workdir, backup_path, [], [])

    def prepare(runner):
        st = os.stat(token_file)
        secrets_dir = os.path.join(nyx_dir, "secrets")
        os.makedirs(secrets_dir, mode=0o700)
        shutil.copystat(os.path.dirname(token_file), secrets_dir)

        def place(name, content=None, source=None):
            dst = os.path.join(secrets_dir, name)
            if source:
                shutil.copyfile(source, dst)
            else:
                with open(dst, "w") as f:
                    f.write(content)
            # The same owner group and mode as the token the running
            # deployment already reads, which is what its container can open.
            os.chmod(dst, st.st_mode & 0o777)
            try:
                os.chown(dst, -1, st.st_gid)
            except OSError:
                pass
            if _group_of(dst) != st.st_gid and not st.st_mode & 0o004:
                # A file its container cannot read would start a receiver with
                # no token. Found here, before anything has stopped.
                raise EditionError("could not give %s the group of the running deployment's token "
                                   "(gid %d); run the command as a user who can, for example with sudo"
                                   % (dst, st.st_gid))
        place("auth_token", source=token_file)
        pw = os.path.join(old_dir, "secrets", "portal_password")
        if os.path.isfile(pw):
            place("portal_password", source=pw)
        place("portal_token", content=secrets.token_hex(32) + "\n")
        place("report_signing_key", content=base64.b64encode(secrets.token_bytes(32)).decode() + "\n")
        old_env = os.path.join(old_dir, ".env")
        env = _translate_env(open(old_env).read()) if os.path.isfile(old_env) else ""
        env = re.sub(r"(?m)^IMAGE_TAG=.*\n?", "", env)
        _private_file(nyx_dir, ".env", env + "IMAGE_TAG=%s\n" % version.lstrip("v"))
        for name in ("scanner.env", "discovery.env"):
            src = os.path.join(old_dir, name)
            if os.path.isfile(src):
                _private_file(nyx_dir, name, _translate_env(open(src).read()))

    def mark_stopped(runner):
        at = _instant(datetime.now(timezone.utc))
        plan.context["stopped_at"] = at
        with open(env_path, "a") as f:
            f.write("SHADOW_AI_GUARD_FINDINGS_BEFORE=%s\n" % at)

    plan.steps = [
        Step("prepare Nyxus's project", action=prepare,
             shows="in %s: copy secrets/auth_token and portal_password, make portal_token and report_signing_key, "
                   "write .env, scanner.env and discovery.env with AIGUARD_ names as NYXUS_" % nyx_dir),
    ] + ([
        Step("sign in to the registry", ["docker", "login", host, "--username", "licence", "--password-stdin"], stdin=key),
        Step("pull Nyxus's images", new + ["pull"] + services),
    ] if pull else []) + [
        Step("back up the receiver database", old + ["exec", "-T", "receiver", "python", "-c", backup_code]),
        Step("stop Shadow AI Guard", old + ["stop"] + services, stops=True),
        Step("note when it stopped", action=mark_stopped,
             shows="add SHADOW_AI_GUARD_FINDINGS_BEFORE=<that moment> to %s" % env_path),
        Step("start Nyxus", new + ["up", "-d", "--no-deps"] + services),
    ]
    plan.keeps = ["the receiver database, in project %s's volume (backed up first to %s)" % (project, backup_path),
                  "the log store and every other service of the project, which keep running",
                  "the shared token and the portal password, and every setting in .env"]
    plan.objects = [project, old_dir, nyx_dir] + services
    return plan


def plan(found: dict, key: str, host: str, version: str, release: str = "nyxus",
         compose_file: str | None = None, runner=run, now=None, pull: bool = True) -> Plan:
    if found["route"] == "helm":
        return helm_plan(found, key, host, version, release, runner=runner, now=now)
    if found["route"] == "compose":
        if not compose_file:
            raise EditionError("this deployment runs on Docker Compose: pass --nyxus-compose-file with Nyxus's compose file")
        return compose_plan(found, key, host, version, compose_file, runner=runner, now=now, pull=pull)
    raise EditionError("this deployment was not installed with Helm or Docker Compose; "
                       "docs/upgrading-to-nyxus.md has the steps by hand")


def describe(found: dict, p: Plan, version: str, host: str, key: str) -> list[str]:
    lines = ["Move to Nyxus", ""]
    where = ("release %s in namespace %s" % (found["release"], found["namespace"]) if p.route == "helm"
             else "compose project %s in %s" % (found["project"], found["working_dir"]))
    lines.append("  Route    %s, %s" % (p.route, where))
    lines.append("  Target   Nyxus %s from %s" % (version.lstrip("v"), host))
    lines.append("  Key      %s (checked against the key stored here once approved)" % fingerprint(key))
    lines.append("")
    lines.append("Kept:")
    lines.extend("  - " + k for k in p.keeps)
    lines.append("")
    lines.append("Steps, in order:")
    for s in p.steps:
        lines.append("  %s" % s.name)
        lines.append("    $ " + s.shows + ("   (the key on standard input)" if s.stdin else ""))
    lines.append("")
    lines.append("Shadow AI Guard is stopped before Nyxus starts. If a step fails, nothing after it runs;")
    lines.append("the backup above is the database as it was.")
    return lines


def apply(p: Plan, reporter, runner=run) -> bool:
    for s in p.steps:
        reporter.step(s.name, "running")
        try:
            if s.argv:
                code, out, err = runner(s.argv, timeout=900, input=s.stdin)
                if code != 0:
                    reporter.step(s.name, "failed", "exit %d" % code)
                    reporter.say((err.strip() or out.strip())[-2000:])
                    return False
            else:
                s.action(runner)
        except (EditionError, OSError, detect.DetectError) as e:
            reporter.step(s.name, "failed", str(e)[:300])
            reporter.say(str(e))
            return False
        if s.stops and hasattr(reporter, "patient"):
            # Nothing answers until Nyxus is up: waiting on each report would
            # only keep the deployment down for longer.
            reporter.patient = False
        reporter.step(s.name, "done")
    return True


def cleanup(p: Plan) -> None:
    shutil.rmtree(p.workdir, ignore_errors=True)
