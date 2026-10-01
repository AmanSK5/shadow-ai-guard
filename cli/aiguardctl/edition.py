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
import shlex
import shutil
import subprocess
import tempfile
import time
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
# Named once: apply() watches for it to know whether a backup really exists.
BACKUP_STEP = "back up the receiver database"

# The Tailscale operator deletes an Ingress's machine from the tailnet before
# it lets the Ingress go. When its OAuth client may not delete devices, that
# never happens and the Ingress is held for good.
TAILSCALE_FINALIZER = "tailscale.com/finalizer"
# A controller that can clean up does so in seconds; one that cannot will not
# manage it in ten minutes. After STALL_AFTER the move says what holds the
# release's objects; after GONE_TIMEOUT it stops waiting.
STALL_AFTER = 60
GONE_TIMEOUT = 600
NAMES_TIMEOUT = 180
POLL = 3
# Looked up at call time, so the tests can run a ten-minute wait instantly.
_sleep = time.sleep
_clock = time.monotonic


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
                 action=None, shows: str = "", stops: bool = False, removes: bool = False):
        self.name, self.argv, self.stdin, self.action = name, argv, stdin, action
        self.shows = shows or " ".join(argv or [])
        # After this step the portal is down until Nyxus answers.
        self.stops = stops
        # After this step Shadow AI Guard's release no longer exists, so a
        # failure leaves a deployment that only finishing by hand can start.
        self.removes = removes


class Plan:
    def __init__(self, route: str, steps: list[Step], workdir: str, backup: str, keeps: list[str], objects: list[str]):
        self.route, self.steps, self.workdir, self.backup = route, steps, workdir, backup
        self.keeps, self.objects = keeps, objects
        self.context: dict = {}
        # The release's Ingresses the Tailscale operator serves, read before
        # anything runs: {ingress, host, address, machine}.
        self.tailscale: list[dict] = []
        # Said when the move stops after the release is removed. The workdir is
        # then kept, because its values file is what finishing by hand needs.
        self.resume: list[str] = []
        self.keep_workdir = False
        # Whether the backup step actually finished. The command used to name
        # the backup path whatever had happened, including when the backup step
        # itself was what failed - and connecting to the target creates it, so
        # there was a zero-byte file sitting at the path it named. Somebody
        # trusting that sentence had no backup at all.
        self.backed_up = False


def _backup_code(stamp: str) -> tuple[str, str]:
    """`VACUUM INTO`, not Connection.backup(), and the result is checked.

    `Connection.backup(target)` requires the target to be a real
    sqlite3.Connection and rejects anything else. OpenTelemetry's Python
    auto-instrumentation replaces sqlite3.connect so it can trace queries, and
    what comes back is a TracedConnectionProxy. The backup then dies with

        TypeError: backup() argument 'target' must be sqlite3.Connection,
                   not TracedConnectionProxy

    on the first step of the move, in any cluster where that instrumentation is
    injected - which is not unusual. Seen on a real deployment.

    Worse than failing: connecting to the target CREATES it, so a zero-byte
    file was left behind at the path the command then named as "the database as
    it was". Anybody trusting that had no backup at all.

    `VACUUM INTO` is one SQL statement through the connection that already
    works, whatever wraps it. It writes an equally consistent snapshot of a
    live WAL database, and it refuses rather than overwrites if the target
    exists. The size check afterwards is because this runs unattended and the
    only thing worse than no backup is a backup nobody checked.
    """
    target = "%s.before-nyxus-%s" % (STATE_DB, stamp)
    code = ("import os,sqlite3;s=sqlite3.connect(%r);"
            "s.execute('VACUUM INTO ?',(%r,));s.close();"
            "n=os.path.getsize(%r);"
            "raise SystemExit('the backup is empty' if n==0 else 0)"
            % (STATE_DB, target, target))
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


def _shell(argv: list[str]) -> str:
    return " ".join(shlex.quote(a) for a in argv)


# ------------------------------------------------------------------ helm --

def manifest_objects(text: str) -> list[dict]:
    """Kind, name, data keys and keep policy of each object in `helm get manifest`."""
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
        keep = bool(meta and re.search(r"^\s+helm\.sh/resource-policy:\s*\"?keep\"?\s*$", meta.group(1), re.M))
        objs.append({"kind": kind.group(1), "name": name.group(1), "data": keys, "keep": keep})
    return objs


def _items(text: str) -> list[dict]:
    """`kubectl get -o json` answers a List for several objects, the object
    itself for one, and nothing at all when --ignore-not-found found none."""
    if not (text or "").strip():
        return []
    doc = json.loads(text)
    return doc.get("items") or [] if "items" in doc else [doc]


def tailscale_ingresses(items: list[dict]) -> list[dict]:
    """The Ingresses among these that the Tailscale operator serves, and the
    machine each one is on the tailnet."""
    found = []
    for i in items:
        md, spec = i.get("metadata") or {}, i.get("spec") or {}
        cls = spec.get("ingressClassName") or (md.get("annotations") or {}).get("kubernetes.io/ingress.class", "")
        # The exact finalizer, not a prefix of it. Only one is ever removed, so
        # recognising a family of them here would be wider than anything this
        # acts on - and a prefix test on a domain-qualified name is the kind of
        # loose match that is wrong far more often than it is useful.
        if cls != "tailscale" and TAILSCALE_FINALIZER not in (md.get("finalizers") or []):
            continue
        tls = next((h for t in spec.get("tls") or [] for h in t.get("hosts") or [] if h), "")
        rule = next((r["host"] for r in spec.get("rules") or [] if r.get("host")), "")
        host = tls or rule
        lb = ((i.get("status") or {}).get("loadBalancer") or {}).get("ingress") or []
        address = next((x["hostname"] for x in lb if x.get("hostname")), "")
        found.append({"ingress": md.get("name", ""), "host": host, "address": address,
                      "machine": (address or host).split(".")[0]})
    return found


def _release_patch(index: int) -> str:
    """Remove the operator's finalizer, and only if it is still the one at
    that position: another controller's finalizer is never touched."""
    path = "/metadata/finalizers/%d" % index
    return json.dumps([{"op": "test", "path": path, "value": TAILSCALE_FINALIZER},
                       {"op": "remove", "path": path}], separators=(",", ":"))


# The Nyxus release that first ships `nyxusctl move`. Below it the command
# does not exist, and a closing line naming one that is not there is the same
# fault as the dead link it is meant to replace.
MOVE_FROM = (0, 5, 0)


def has_move(version: str) -> bool:
    """Whether the Nyxus being installed ships `nyxusctl move`.

    Unreadable or short versions answer False. Saying nothing costs a reader
    one command they could have run; saying it wrongly costs them the time to
    find out it does not exist, and some of their trust in the rest.
    """
    parts = []
    for piece in (version or "").strip().lstrip("v").split("."):
        digits = "".join(c for c in piece if c.isdigit())
        if not digits:
            break
        parts.append(int(digits))
    return len(parts) >= 3 and tuple(parts[:3]) >= MOVE_FROM


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

    # Every Deployment the release made is stopped, whatever found it: one
    # left running keeps its pods, and the wait for them never ends.
    made = [o["name"] for o in objs if o["kind"] == "Deployment"]
    running = [d["name"] for d in found["deployments"]]
    missing = [n for n in made if n not in running]
    if missing:
        raise EditionError("the release made Deployment %s, which was not found running this project's images; "
                           "nothing was changed" % ", ".join(missing))
    stopping = [d for d in found["deployments"] if d["name"] in made] if made else found["deployments"]
    # Only the pods of those Deployments. A finished scanner or discovery Job
    # keeps its pod, with the release's instance label, until the Job itself
    # goes - a selector on the instance alone waits on it for ever.
    selector = "app.kubernetes.io/instance=%s,app.kubernetes.io/name in (%s)" % (
        rel, ",".join(sorted({d.get("label") or d["name"] for d in stopping})))

    ingresses = [o["name"] for o in objs if o["kind"] == "Ingress"]
    tailscale: list[dict] = []
    if ingresses:
        code, out, err = runner(kube + ["get", "ingress"] + ingresses + ["-n", ns, "-o", "json"], timeout=120)
        if code != 0:
            raise EditionError("kubectl could not read the release's Ingresses: %s" % err.strip()[:200])
        tailscale = tailscale_ingresses(_items(out))
    # What uninstalling removes. A kept object - the storage claim - stays.
    watched = ["%s/%s" % (o["kind"].lower(), o["name"]) for o in objs if not o["keep"]]

    workdir = tempfile.mkdtemp(prefix="aiguardctl-nyxus-")
    os.chmod(workdir, 0o700)
    values_path = os.path.join(workdir, "values.json")
    backup_code, backup_path = _backup_code(_stamp(now))
    plan = Plan("helm", [], workdir, backup_path, [], [])
    plan.tailscale = tailscale

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

    wait_argv = kube + ["wait", "--for=delete", "pod", "-n", ns, "-l", selector, "--timeout=5m"]

    def wait_stopped(runner):
        c, _, e = runner(wait_argv, timeout=360)
        if c != 0 and "no matching resources" not in e:
            raise EditionError("Shadow AI Guard's pods did not stop: %s" % e.strip()[:200])
        plan.context["stopped_at"] = _instant(datetime.now(timezone.utc))

    def write_values(runner):
        values = nyxus_values(user, secrets_made, claim, plan.context.get("stopped_at") or _instant(now))
        _private_file(workdir, "values.json", json.dumps(values, indent=2))

    machines = {t["ingress"]: t for t in tailscale}

    def held_by_tailscale(left: list[dict]) -> list[dict]:
        return [i for i in left if i.get("kind") == "Ingress"
                and TAILSCALE_FINALIZER in ((i.get("metadata") or {}).get("finalizers") or [])]

    def patch_argv(item: dict) -> list[str]:
        md = item["metadata"]
        return kube + ["-n", ns, "patch", "ingress/" + md["name"], "--type=json",
                       "-p", _release_patch(md["finalizers"].index(TAILSCALE_FINALIZER))]

    def stalled(held: list[dict], asking: bool) -> list[str]:
        lines = ["",
                 "  Removing Shadow AI Guard has waited %d seconds on the Tailscale operator, which still holds"
                 % STALL_AFTER,
                 "  %s %s." % ("Ingresses" if len(held) > 1 else "Ingress",
                              " and ".join(i["metadata"]["name"] for i in held)),
                 "  The operator deletes each Ingress's machine from the tailnet before letting it go, and stops",
                 "  here when its OAuth client is not allowed to delete devices. Nyxus's Ingresses ask for the",
                 "  same names, so while those machines exist Nyxus's would be registered as <name>-1.",
                 "",
                 "  In the Tailscale admin console, under Machines, delete:"]
        for i in held:
            t = machines.get(i["metadata"]["name"]) or tailscale_ingresses([i])[0]
            lines.append("    %s%s" % (t["machine"], "   (%s)" % t["address"] if t["address"] else ""))
        lines.append("")
        if asking:
            lines += ["  Once they are deleted, answer y: the operator's finalizer is removed from those Ingresses -",
                      "  that finalizer only, nothing else of theirs - and the move carries on."]
        else:
            lines += ["  Nothing is asked with --yes or without a terminal, so the move stops here. The commands",
                      "  below remove the operator's finalizer from those Ingresses - that finalizer only - once",
                      "  the machines are deleted."]
        lines += ["  Afterwards, let the operator's OAuth client delete devices, or removing any Tailscale Ingress",
                  "  in this cluster will stall the same way.",
                  ""]
        return lines

    def wait_gone(runner):
        say, ask = plan.context.get("say") or (lambda m: None), plan.context.get("ask")
        start, asked = _clock(), False
        while True:
            c, o, e = runner(kube + ["get"] + watched + ["-n", ns, "-o", "json", "--ignore-not-found"], timeout=120)
            if c != 0:
                raise EditionError("kubectl could not check what is left of the release: %s" % e.strip()[:200])
            left = _items(o)
            if not left:
                return
            waited = _clock() - start
            held = held_by_tailscale(left)
            if held and waited >= STALL_AFTER and not asked:
                if not (ask and ask(stalled(held, True), "Have you deleted them in the Tailscale admin console? [y/N] ")):
                    # The first line is what the step reports, so it is a whole sentence.
                    summary = "the Tailscale operator still holds %s %s, whose machines must be deleted in the admin console" % (
                        "Ingresses" if len(held) > 1 else "Ingress", " and ".join(i["metadata"]["name"] for i in held))
                    raise EditionError("\n".join(
                        [summary] + (stalled(held, False) if not ask else [""])
                        + ["  Once they are deleted, release the Ingresses:"]
                        + ["    " + _shell(patch_argv(i)) for i in held]))
                asked = True
                for i in held:
                    c, _, e = runner(patch_argv(i), timeout=120)
                    if c != 0:
                        raise EditionError("could not remove the Tailscale finalizer from Ingress %s: %s"
                                           % (i["metadata"]["name"], e.strip()[:200]))
                    say("  released Ingress %s" % i["metadata"]["name"])
                continue
            if waited >= GONE_TIMEOUT:
                raise EditionError("after %d minutes the release still has %s" % (GONE_TIMEOUT // 60, ", ".join(
                    "%s/%s%s" % (i.get("kind", "").lower(), (i.get("metadata") or {}).get("name", ""),
                                 " (held by %s)" % ", ".join(i["metadata"]["finalizers"])
                                 if (i.get("metadata") or {}).get("finalizers") else "")
                    for i in left)))
            _sleep(POLL)

    def check_names(runner):
        # Never fails the move: Nyxus is installed by now, and a name that came
        # back wrong is something to tell the operator, not a reason to stop.
        say = plan.context.get("say") or (lambda m: None)
        want = {t["host"]: t for t in tailscale}
        start = _clock()
        while True:
            c, o, _ = runner(kube + ["get", "ingress", "-n", ns, "-l", "app.kubernetes.io/instance=" + release,
                                     "-o", "json"], timeout=120)
            got = [g for g in (tailscale_ingresses(_items(o)) if c == 0 else []) if g["host"] in want]
            if got and all(g["address"] for g in got):
                break
            if _clock() - start >= NAMES_TIMEOUT:
                say("  Tailscale had not given Nyxus's Ingresses an address after %d minutes. Check the operator's "
                    "logs in its namespace." % (NAMES_TIMEOUT // 60))
                return
            _sleep(POLL)
        for g in got:
            old = want[g["host"]]["machine"]
            if g["machine"] != old:
                say("  Tailscale registered Nyxus as %s, not %s: a machine called %s was still on the tailnet. "
                    "Until that is put right Nyxus is reached at %s. In the Tailscale admin console, delete the old "
                    "%s, then rename %s to %s (Edit machine name)." % (g["machine"], old, old, g["address"], old,
                                                                        g["machine"], old))

    chart = "oci://%s/%s/charts/nyxus" % (host, REPOSITORY)
    install = helm + ["install", release, chart, "--version", version.lstrip("v"),
                      "-n", ns, "-f", values_path, "--wait", "--timeout", "10m"]
    plan.steps = [
        Step(BACKUP_STEP, kube + ["-n", ns, "exec", "deployment/" + receiver, "--",
                                                     "python", "-c", backup_code]),
        Step("carry the release's credentials", action=carry,
             shows="copy %s into %s" % (", ".join(n for n, _ in secrets_made.values()) or "no Secrets",
                                          ", ".join(CARRIED[p] for p in secrets_made) or "-")),
        Step("sign in to the registry", helm + ["registry", "login", host, "--username", "licence", "--password-stdin"],
             stdin=key),
        Step("create the pull secret", action=pull_secret,
             shows="create Secret %s (docker-registry, %s) from the key, in a file only you can read" % (PULL_SECRET, host)),
    ] + [Step("stop " + d["name"], kube + ["-n", ns, "scale", "deployment/" + d["name"], "--replicas=0"])
         for d in stopping] + [
        Step("wait for Shadow AI Guard to stop", action=wait_stopped, stops=True, shows=_shell(wait_argv)),
        Step("write Nyxus's values", action=write_values,
             shows="write %s: this release's values, on %s, with the carried credentials" % (values_path, claim)),
        Step("remove the Shadow AI Guard release", helm + ["uninstall", rel, "-n", ns], removes=True),
        Step("wait for the release's objects to be deleted", action=wait_gone,
             shows="%s, until nothing is left%s" % (
                 _shell(kube + ["get"] + watched + ["-n", ns, "-o", "json", "--ignore-not-found"]),
                 "; if the Tailscale operator holds an Ingress, ask before removing its finalizer" if tailscale else "")),
        Step("install Nyxus", install),
    ] + ([Step("check the Tailscale machine names", action=check_names,
               shows="%s, until each has its address" % _shell(
                   kube + ["get", "ingress", "-n", ns, "-l", "app.kubernetes.io/instance=" + release, "-o", "json"]))]
         if tailscale else [])
    finish = helm + ["upgrade", "--install", release, chart, "--version", version.lstrip("v"),
                     "-n", ns, "-f", values_path, "--wait", "--timeout", "10m"]
    plan.resume = [
        "",
        "Shadow AI Guard's release is removed and Nyxus is not running yet. The database, its storage and the",
        "carried credentials are untouched. Once the cause above is dealt with, finish the move by hand:",
        "",
        "  " + _shell(finish),
        "",
        "and then delete %s - the values file in it holds this release's settings." % workdir,
    ]
    plan.keeps = ["the receiver database, on %s (backed up first to %s)" % (claim, backup_path),
                  "the shared token, the admin token and the portal password",
                  "this release's other values: ingress, log store, scanner and discovery settings"]
    plan.objects = [rel, claim] + [d["name"] for d in stopping] + [n for n, _ in secrets_made.values()] + ingresses
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
        Step(BACKUP_STEP, old + ["exec", "-T", "receiver", "python", "-c", backup_code]),
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
    if p.tailscale:
        lines.append("Tailscale:")
        lines.append("  This release is reached through the Tailscale operator, as %s." % ", ".join(
            "%s%s" % (t["machine"], " (%s)" % t["address"] if t["address"] else "") for t in p.tailscale))
        lines += ["  Removing the release asks the operator to delete those machines. Nyxus's Ingresses ask for the",
                  "  same names, so the old machines have to be gone first or the new ones are registered as <name>-1.",
                  "  If the operator cannot delete them - usually because its OAuth client may not delete devices - the",
                  "  move stops at that point, names the machines for you to delete in the admin console, and removes",
                  "  the operator's finalizer from those Ingresses once you say they are gone. With --yes, or with no",
                  "  terminal to ask in, it stops there and prints the steps instead.",
                  ""]
    lines.append("Steps, in order:")
    for s in p.steps:
        lines.append("  %s" % s.name)
        lines.append("    $ " + s.shows + ("   (the key on standard input)" if s.stdin else ""))
    lines.append("")
    lines.append("Shadow AI Guard is stopped before Nyxus starts. If a step fails, nothing after it runs;")
    lines.append("the backup above is the database as it was.")
    return lines


def _stopped(p: Plan, reporter, removed: bool) -> None:
    if removed and p.resume:
        p.keep_workdir = True
        for line in p.resume:
            reporter.say(line)


def apply(p: Plan, reporter, runner=run, ask=None) -> bool:
    """Run the steps in order. `ask(lines, question)` shows lines and returns
    whether the person answered yes; without it nothing is asked, and a step
    that needs an answer stops the move with instructions instead."""
    p.context["say"], p.context["ask"] = reporter.say, ask
    removed = False
    for s in p.steps:
        reporter.step(s.name, "running")
        try:
            if s.argv:
                code, out, err = runner(s.argv, timeout=900, input=s.stdin)
                if code != 0:
                    reporter.step(s.name, "failed", "exit %d" % code)
                    reporter.say((err.strip() or out.strip())[-2000:])
                    _stopped(p, reporter, removed)
                    return False
            else:
                s.action(runner)
            if s.name == BACKUP_STEP:
                p.backed_up = True
        except (EditionError, OSError, detect.DetectError) as e:
            reporter.step(s.name, "failed", str(e).strip().splitlines()[0][:300] if str(e).strip() else "")
            reporter.say(str(e))
            _stopped(p, reporter, removed)
            return False
        except KeyboardInterrupt:
            _stopped(p, reporter, removed)
            raise
        if s.stops and hasattr(reporter, "patient"):
            # Nothing answers until Nyxus is up: waiting on each report would
            # only keep the deployment down for longer.
            reporter.patient = False
        removed = removed or s.removes
        reporter.step(s.name, "done")
    return True


def cleanup(p: Plan) -> None:
    if not p.keep_workdir:
        shutil.rmtree(p.workdir, ignore_errors=True)
