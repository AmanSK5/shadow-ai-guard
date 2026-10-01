# Copyright 2026 Aman Karir
# SPDX-License-Identifier: Apache-2.0
# Part of Shadow AI Guard, https://github.com/AmanSK5/shadow-ai-guard

"""`aiguardctl upgrade --edition nyxus` without a cluster, a host or a portal.

The properties under test: the key is the one stored in this deployment or
nothing happens, and it never appears in a command's arguments; Helm keeps the
release's storage, credentials and values, backs the database up before
anything stops, stops every Deployment the release made and waits for their
pods alone, and removes Shadow AI Guard only after its credentials are copied;
an Ingress the Tailscale operator will not let go of is named, released only
once the operator says its machines are gone, and never left to stall the
move in silence; a move stopped after the release is removed says how to
finish it and keeps what finishing needs; Compose prepares Nyxus's project
from the running one without overwriting anything, and starts Nyxus under the
same project so its volumes are the same volumes; and the findings Shadow AI
Guard stored are marked for Nyxus to read.
"""
import base64
import hashlib
import json
import os
import shutil
import stat

import pytest

from aiguardctl import cli, edition

KEY = "nyxl_eyJ2IjoxLCJpZCI6Ik5ZWC0wMDAxIn0.c2lnbmF0dXJl"
NOW = __import__("datetime").datetime(2026, 9, 20, 10, 0, 0, tzinfo=__import__("datetime").timezone.utc)
SELECTOR = "app.kubernetes.io/instance=ai-guard,app.kubernetes.io/name in (ai-guard,ai-guard-portal)"


class Reporter:
    def __init__(self):
        self.steps, self.said = [], []

    def step(self, step, status, detail=""):
        self.steps.append((step, status, detail))

    def say(self, msg):
        self.said.append(msg)


def test_the_fingerprint_is_the_one_the_receiver_shows():
    digest = hashlib.sha256(KEY.encode()).hexdigest()
    assert edition.fingerprint(KEY) == "%s-%s-%s" % (digest[:4], digest[4:8], digest[8:12])


def test_only_the_key_stored_here_and_active_is_used():
    good = {"state": "active", "fingerprint": edition.fingerprint(KEY), "registry": "registry.nyxus.co.uk/nyxus-enterprise"}
    assert edition.check_key(KEY, good) == "registry.nyxus.co.uk"
    with pytest.raises(edition.EditionError, match="not the one stored"):
        edition.check_key(KEY, dict(good, fingerprint="0000-0000-0000"))
    for state in ("none", "expired", "invalid", None):
        with pytest.raises(edition.EditionError):
            edition.check_key(KEY, dict(good, state=state))
    with pytest.raises(edition.EditionError):
        edition.load_key(None, environ={})
    assert edition.load_key(None, environ={"NYXUS_KEY": " %s \n" % KEY}) == KEY


MANIFEST = """---
# Source: ai-guard/templates/secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: ai-guard
  labels:
    app.kubernetes.io/name: ai-guard
type: Opaque
data:
  authToken: "c2hhcmVk"
---
# Source: ai-guard/templates/managed-secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: ai-guard-admin
data:
  adminToken: "YWRtaW4="
---
# Source: ai-guard/templates/portal-secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: ai-guard-portal
data:
  password: "cGFzc3dvcmQ="
---
# Source: ai-guard/templates/managed-pvc.yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: ai-guard-state
  annotations:
    helm.sh/resource-policy: keep
spec:
  accessModes: [ReadWriteOnce]
---
# Source: ai-guard/templates/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ai-guard
  labels:
    app.kubernetes.io/name: ai-guard
---
# Source: ai-guard/templates/portal-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ai-guard-portal
  labels:
    app.kubernetes.io/name: ai-guard-portal
"""

MANIFEST_TAILSCALE = MANIFEST + """---
# Source: ai-guard/templates/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ai-guard
spec:
  ingressClassName: tailscale
---
# Source: ai-guard/templates/portal-ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ai-guard-portal
spec:
  ingressClassName: tailscale
"""

FOUND_HELM = {"route": "helm", "release": "ai-guard", "namespace": "ai-guard", "context": None, "helm": True,
              "deployments": [{"name": "ai-guard", "container": "receiver", "tag": "0.33.0", "label": "ai-guard",
                               "image": "ghcr.io/amansk5/shadow-ai-guard/receiver:0.33.0"},
                              {"name": "ai-guard-portal", "container": "portal", "tag": "0.33.0",
                               "label": "ai-guard-portal",
                               "image": "ghcr.io/amansk5/shadow-ai-guard/portal:0.33.0"}],
              "cronjobs": []}
LIVE = {"ai-guard": {"authToken": "c2hhcmVk"}, "ai-guard-admin": {"adminToken": "YWRtaW4="},
        "ai-guard-portal": {"password": "cGFzc3dvcmQ="}}


def _ingress(name, host, address="", finalizers=(edition.TAILSCALE_FINALIZER,), deleting=False):
    """An Ingress as the Tailscale operator leaves it, read from a live cluster."""
    md = {"name": name, "finalizers": list(finalizers)}
    if deleting:
        md["deletionTimestamp"] = "2026-09-20T10:01:00Z"
    return {"kind": "Ingress", "metadata": md,
            "spec": {"ingressClassName": "tailscale", "rules": [{"host": host}], "tls": [{"hosts": [host]}]},
            "status": {"loadBalancer": {"ingress": [{"hostname": address, "ports": [{"port": 443}]}]} if address else {}}}


def helm_runner(calls, files, manifest=MANIFEST, ingresses=(), left=lambda: [], released=None, after=(), state=None):
    def runner(argv, timeout=900, input=None):
        calls.append((argv, input))
        if argv[:3] == ["helm", "get", "values"]:
            return 0, json.dumps({"image": {"repository": "ghcr.io/amansk5/shadow-ai-guard/receiver"},
                                  "auth": {"value": ""}, "ingress": {"enabled": True, "host": "ai-guard.example.com"},
                                  "portal": {"enabled": True, "auth": {"password": ""}}}), ""
        if argv[:3] == ["helm", "get", "manifest"]:
            return 0, manifest, ""
        if argv[:3] == ["kubectl", "get", "secret"]:
            return 0, json.dumps({"data": LIVE[argv[3]]}), ""
        if argv[:3] == ["kubectl", "get", "ingress"] and "-l" in argv:
            return 0, json.dumps({"kind": "List", "items": list(after)}), ""
        if argv[:3] == ["kubectl", "get", "ingress"]:
            return 0, json.dumps({"kind": "List", "items": list(ingresses)}), ""
        if argv[:2] == ["kubectl", "get"] and "--ignore-not-found" in argv:
            items = left()
            return 0, (json.dumps({"kind": "List", "items": items}) if items else ""), ""
        if "patch" in argv and released is not None:
            released(argv[argv.index("patch") + 1].split("/", 1)[1])
        if "uninstall" in argv and state is not None:
            state["values_before_uninstall"] = os.path.exists(os.path.join(state["workdir"], "values.json"))
        if "-f" in argv:
            path = argv[argv.index("-f") + 1]
            files.append((argv, open(path).read(), stat.S_IMODE(os.stat(path).st_mode)))
        if argv[:2] == ["kubectl", "wait"]:
            return 1, "", "error: no matching resources found"
        return 0, "", ""
    return runner


@pytest.fixture
def clock(monkeypatch):
    """Ten minutes of waiting, in no time."""
    now = [0.0]
    monkeypatch.setattr(edition, "_clock", lambda: now[0])
    monkeypatch.setattr(edition, "_sleep", lambda s: now.__setitem__(0, now[0] + s))
    return now


def test_helm_keeps_storage_credentials_and_values_and_never_passes_the_key_as_an_argument():
    calls, files, state = [], [], {}
    runner = helm_runner(calls, files, state=state)
    p = edition.plan(FOUND_HELM, KEY, "registry.nyxus.co.uk", "0.1.0", runner=runner, now=NOW)
    state["workdir"] = p.workdir
    rep = Reporter()
    try:
        assert edition.apply(p, rep, runner=runner), rep.said
    finally:
        edition.cleanup(p)
    argvs = [" ".join(a) for a, _ in calls]
    assert all(KEY not in a for a in argvs)
    assert all(KEY not in d for _, _, d in rep.steps)
    # the order: back up, carry credentials, pull access, stop both, wait, remove, install
    order = [next(i for i, a in enumerate(argvs) if needle in a) for needle in (
        "exec deployment/ai-guard -- python -c", "get secret ai-guard ", "registry login registry.nyxus.co.uk",
        "scale deployment/ai-guard --replicas=0", "scale deployment/ai-guard-portal --replicas=0",
        "wait --for=delete pod", "uninstall ai-guard", "install nyxus oci://registry.nyxus.co.uk/nyxus-enterprise/charts/nyxus")]
    assert order == sorted(order)
    assert [i for a, i in calls if i] == [KEY]
    assert "state.db.before-nyxus-20260920T100000Z" in argvs[order[0]]
    # the wait is for the two Deployments' pods, not everything the release labels
    wait = next(a for a, _ in calls if a[:2] == ["kubectl", "wait"])
    assert wait[wait.index("-l") + 1] == SELECTOR
    # the values are written while the release still exists; removal does not block on its own
    assert state["values_before_uninstall"] is True
    uninstall = next(a for a, _ in calls if "uninstall" in a)
    assert "--wait" not in uninstall
    assert any("--ignore-not-found" in a and "persistentvolumeclaim/ai-guard-state" not in a for a in argvs)
    install = next(a for a, _ in calls if a[:2] == ["helm", "install"])
    assert install[install.index("--version") + 1] == "0.1.0"
    # every file handed over was readable by this user alone, and is gone afterwards
    assert files and all(mode == 0o600 for _, _, mode in files)
    carried = {json.loads(body)["metadata"]["name"]: json.loads(body)["data"] for _, body, _ in files if '"Opaque"' in body}
    assert carried == {"nyxus-carried-auth": LIVE["ai-guard"], "nyxus-carried-admin": LIVE["ai-guard-admin"],
                       "nyxus-carried-portal": LIVE["ai-guard-portal"]}
    pull = next(json.loads(body) for _, body, _ in files if "dockerconfigjson" in body)
    config = json.loads(base64.b64decode(pull["data"][".dockerconfigjson"]))
    assert config["auths"]["registry.nyxus.co.uk"]["password"] == KEY
    values = json.loads(next(body for a, body, _ in files if a[:2] == ["helm", "install"]))
    assert values["managed"]["persistence"]["existingClaim"] == "ai-guard-state"
    assert values["auth"] == {"existingSecret": "nyxus-carried-auth"}
    assert values["managed"]["adminToken"]["existingSecret"] == "nyxus-carried-admin"
    assert values["portal"]["auth"]["existingSecret"] == "nyxus-carried-portal" and "password" not in values["portal"]["auth"]
    assert values["imagePullSecrets"] == [{"name": "nyxus-registry"}]
    assert "image" not in values and values["ingress"]["host"] == "ai-guard.example.com"
    assert values["portal"]["shadowAiGuardFindingsBefore"].endswith("Z")
    assert not p.tailscale and not any("Tailscale" in line for line in edition.describe(FOUND_HELM, p, "0.1.0", "r", KEY))
    assert not os.path.exists(p.workdir)


def test_a_deployment_the_release_made_that_was_not_found_stops_the_plan():
    """What went wrong on a real move: detection found the receiver alone, the
    portal was never stopped, and the wait for its pod could only time out."""
    found = dict(FOUND_HELM, deployments=FOUND_HELM["deployments"][:1])
    calls = []
    with pytest.raises(edition.EditionError, match="ai-guard-portal"):
        edition.plan(found, KEY, "registry.nyxus.co.uk", "0.1.0", runner=helm_runner(calls, []), now=NOW)
    assert not any(a[:2] in (["kubectl", "scale"], ["helm", "uninstall"]) for a, _ in calls)


def test_a_failed_step_stops_the_move_before_anything_after_it():
    calls, files = [], []
    base = helm_runner(calls, files)

    def runner(argv, timeout=900, input=None):
        if argv[:2] == ["helm", "registry"]:
            calls.append((argv, input))
            return 1, "", "unauthorized"
        return base(argv, timeout, input)
    p = edition.plan(FOUND_HELM, KEY, "registry.nyxus.co.uk", "0.1.0", runner=runner, now=NOW)
    rep = Reporter()
    try:
        assert not edition.apply(p, rep, runner=runner)
    finally:
        edition.cleanup(p)
    assert not any(a[:1] == ["helm"] and "uninstall" in a for a, _ in calls)
    assert not any("scale" in a for a, _ in calls)
    # nothing was removed, so there is nothing to finish by hand and nothing kept
    assert not any("upgrade --install" in s for s in rep.said) and not os.path.exists(p.workdir)


def test_tailscale_machines_the_operator_cannot_delete_are_named_and_released_once_confirmed(clock):
    calls, files = [], []
    held = {"ai-guard": True, "ai-guard-portal": True}
    runner = helm_runner(
        calls, files, manifest=MANIFEST_TAILSCALE,
        ingresses=[_ingress("ai-guard", "ai-guard", "ai-guard.tail1234.ts.net"),
                   _ingress("ai-guard-portal", "ai-guard-portal", "ai-guard-portal.tail1234.ts.net")],
        left=lambda: [_ingress(n, n, deleting=True) for n, h in held.items() if h],
        released=lambda name: held.__setitem__(name, False),
        after=[_ingress("nyxus", "ai-guard", "ai-guard.tail1234.ts.net"),
               _ingress("nyxus-portal", "ai-guard-portal", "ai-guard-portal-1.tail1234.ts.net")])
    p = edition.plan(FOUND_HELM, KEY, "registry.nyxus.co.uk", "0.1.0", runner=runner, now=NOW)
    asked = []

    def ask(lines, question):
        asked.append((clock[0], "\n".join(lines), question))
        return True
    rep = Reporter()
    try:
        text = "\n".join(edition.describe(FOUND_HELM, p, "0.1.0", "registry.nyxus.co.uk", KEY))
        assert edition.apply(p, rep, runner=runner, ask=ask), rep.said
    finally:
        edition.cleanup(p)
    # said before anything ran
    assert "Tailscale:" in text and "ai-guard-portal (ai-guard-portal.tail1234.ts.net)" in text and "<name>-1" in text
    # asked once, only after the operator had had its chance, naming the machines to delete
    assert len(asked) == 1
    at, lines, question = asked[0]
    assert at >= edition.STALL_AFTER
    assert "admin console" in lines and "    ai-guard   (ai-guard.tail1234.ts.net)" in lines
    assert "    ai-guard-portal   (ai-guard-portal.tail1234.ts.net)" in lines and "[y/N]" in question
    # only the operator's finalizer, only on this release's Ingresses, and before Nyxus is installed
    patches = [a for a, _ in calls if "patch" in a]
    assert [a[a.index("patch") + 1] for a in patches] == ["ingress/ai-guard", "ingress/ai-guard-portal"]
    assert json.loads(patches[0][-1]) == [
        {"op": "test", "path": "/metadata/finalizers/0", "value": "tailscale.com/finalizer"},
        {"op": "remove", "path": "/metadata/finalizers/0"}]
    argvs = [" ".join(a) for a, _ in calls]
    assert max(i for i, a in enumerate(argvs) if " patch " in a) < next(i for i, a in enumerate(argvs) if "install nyxus" in a)
    # and a machine that came back under another name is caught, without failing a move that worked
    said = "\n".join(rep.said)
    assert "registered Nyxus as ai-guard-portal-1, not ai-guard-portal" in said
    assert "rename ai-guard-portal-1 to ai-guard-portal" in said and "as ai-guard," not in said
    assert rep.steps[-1] == ("check the Tailscale machine names", "done", "")


@pytest.mark.parametrize("ask", [None, lambda lines, question: False], ids=["unattended", "declined"])
def test_a_stalled_removal_stops_with_the_steps_and_keeps_what_finishing_needs(clock, ask):
    calls, files = [], []
    runner = helm_runner(
        calls, files, manifest=MANIFEST_TAILSCALE,
        ingresses=[_ingress("ai-guard", "ai-guard", "ai-guard.tail1234.ts.net"),
                   _ingress("ai-guard-portal", "ai-guard-portal", "ai-guard-portal.tail1234.ts.net")],
        left=lambda: [_ingress("ai-guard", "ai-guard", deleting=True),
                      _ingress("ai-guard-portal", "ai-guard-portal", deleting=True)])
    p = edition.plan(FOUND_HELM, KEY, "registry.nyxus.co.uk", "0.1.0", runner=runner, now=NOW)
    rep = Reporter()
    try:
        assert not edition.apply(p, rep, runner=runner, ask=ask)
        said = "\n".join(rep.said)
        assert not any("patch" in a for a, _ in calls) and not any(a[:2] == ["helm", "install"] for a, _ in calls)
        assert clock[0] < edition.GONE_TIMEOUT, "a stall that needs a person does not sit out the whole wait"
        # what the step reports - on System health too - is a whole sentence, not a line cut mid-way
        failed = next(detail for _, status, detail in rep.steps if status == "failed")
        assert failed == ("the Tailscale operator still holds Ingresses ai-guard and ai-guard-portal, "
                          "whose machines must be deleted in the admin console")
        assert "the move carries on" not in said
        if ask is None:
            assert "admin console" in said and "    ai-guard-portal   (ai-guard-portal.tail1234.ts.net)" in said
        assert "kubectl -n ai-guard patch ingress/ai-guard --type=json -p '[" in said
        assert ("helm upgrade --install nyxus oci://registry.nyxus.co.uk/nyxus-enterprise/charts/nyxus --version 0.1.0 "
                "-n ai-guard -f %s" % os.path.join(p.workdir, "values.json")) in said
        assert p.keep_workdir and os.path.exists(os.path.join(p.workdir, "values.json"))
        edition.cleanup(p)
        assert os.path.exists(p.workdir), "finishing by hand needs the values file"
    finally:
        shutil.rmtree(p.workdir, ignore_errors=True)


def test_an_object_held_by_anything_else_is_named_when_the_wait_gives_up(clock):
    calls, files = [], []
    lb = {"kind": "Service", "metadata": {"name": "ai-guard", "finalizers": ["service.kubernetes.io/load-balancer-cleanup"]}}
    runner = helm_runner(calls, files, left=lambda: [lb])
    p = edition.plan(FOUND_HELM, KEY, "registry.nyxus.co.uk", "0.1.0", runner=runner, now=NOW)
    asked = []
    rep = Reporter()
    try:
        assert not edition.apply(p, rep, runner=runner, ask=lambda lines, q: asked.append(q) or True)
        said = "\n".join(rep.said)
    finally:
        shutil.rmtree(p.workdir, ignore_errors=True)
    assert clock[0] >= edition.GONE_TIMEOUT and not asked
    assert "service/ai-guard (held by service.kubernetes.io/load-balancer-cleanup)" in said
    assert not any("patch" in a for a, _ in calls) and "helm upgrade --install nyxus" in said


def test_an_operator_that_can_delete_its_machines_is_never_asked_about(clock):
    calls, files = [], []
    runner = helm_runner(
        calls, files, manifest=MANIFEST_TAILSCALE,
        ingresses=[_ingress("ai-guard", "ai-guard", "ai-guard.tail1234.ts.net"),
                   _ingress("ai-guard-portal", "ai-guard-portal", "ai-guard-portal.tail1234.ts.net")],
        left=lambda: [],
        after=[_ingress("nyxus", "ai-guard", "ai-guard.tail1234.ts.net"),
               _ingress("nyxus-portal", "ai-guard-portal", "ai-guard-portal.tail1234.ts.net")])
    p = edition.plan(FOUND_HELM, KEY, "registry.nyxus.co.uk", "0.1.0", runner=runner, now=NOW)
    asked, rep = [], Reporter()
    try:
        assert edition.apply(p, rep, runner=runner, ask=lambda lines, q: asked.append(q) or True), rep.said
    finally:
        edition.cleanup(p)
    assert not asked and not any("patch" in a for a, _ in calls)
    assert clock[0] < edition.STALL_AFTER and not any("registered Nyxus as" in s for s in rep.said)


def compose_setup(tmp_path):
    old = tmp_path / "shadow-ai-guard"
    (old / "secrets").mkdir(parents=True)
    (old / "secrets" / "auth_token").write_text("shared-token\n")
    os.chmod(old / "secrets" / "auth_token", 0o640)
    (old / "secrets" / "portal_password").write_text("portal-pass\n")
    (old / ".env").write_text("AIGUARD_ADMIN_TOKEN=admin-token\nCORP_DOMAINS=example.com\nIMAGE_TAG=0.33.0\n")
    (old / "scanner.env").write_text("AIGUARD_ENTRA_TENANT_ID=tenant\nexport AIGUARD_JAMF_URL=https://jamf.example.com\n")
    new = tmp_path / "nyxus"
    new.mkdir()
    (new / "docker-compose.yml").write_text("services: {}\n")
    found = {"route": "compose", "project": "compose", "working_dir": str(old),
             "config_files": str(old / "docker-compose.yml"),
             "services": [{"service": "receiver", "image": "x", "tag": "0.33.0"},
                          {"service": "portal", "image": "x", "tag": "0.33.0"}]}
    return old, new, found


def test_compose_prepares_nyxus_from_the_running_project_and_starts_it_on_the_same_volumes(tmp_path):
    old, new, found = compose_setup(tmp_path)
    calls = []

    def runner(argv, timeout=900, input=None):
        calls.append((argv, input))
        return 0, "", ""
    p = edition.plan(found, KEY, "registry.nyxus.co.uk", "v0.1.0", compose_file=str(new / "docker-compose.yml"),
                     runner=runner, now=NOW)
    try:
        assert edition.apply(p, Reporter(), runner=runner)
    finally:
        edition.cleanup(p)
    assert all(KEY not in " ".join(a) for a, _ in calls)
    assert [i for a, i in calls if i] == [KEY]
    env = (new / ".env").read_text()
    assert "NYXUS_ADMIN_TOKEN=admin-token" in env and "AIGUARD_" not in env and "CORP_DOMAINS=example.com" in env
    assert "IMAGE_TAG=0.1.0" in env and "IMAGE_TAG=0.33.0" not in env
    assert "SHADOW_AI_GUARD_FINDINGS_BEFORE=" in env
    assert (new / "scanner.env").read_text() == "NYXUS_ENTRA_TENANT_ID=tenant\nexport NYXUS_JAMF_URL=https://jamf.example.com\n"
    assert (new / "secrets" / "auth_token").read_text() == "shared-token\n"
    for name in ("auth_token", "portal_password", "portal_token", "report_signing_key"):
        assert stat.S_IMODE(os.stat(new / "secrets" / name).st_mode) == 0o640, name
    assert len(base64.b64decode((new / "secrets" / "report_signing_key").read_text())) == 32
    argvs = [a for a, _ in calls]
    up = next(a for a in argvs if "up" in a)
    assert up[:4] == ["docker", "compose", "-p", "compose"] and up[-4:] == ["-d", "--no-deps", "portal", "receiver"]
    backup = next(a for a in argvs if "exec" in a)
    assert str(old) in backup and backup[backup.index("exec") + 1:backup.index("exec") + 3] == ["-T", "receiver"]
    order = [argvs.index(a) for a in (next(a for a in argvs if a[:2] == ["docker", "login"]),
                                      next(a for a in argvs if "pull" in a), backup,
                                      next(a for a in argvs if "stop" in a), up)]
    assert order == sorted(order)


def test_compose_overwrites_nothing_beside_nyxus_compose_file(tmp_path):
    old, new, found = compose_setup(tmp_path)
    (new / ".env").write_text("SOMETHING=kept\n")
    with pytest.raises(edition.EditionError, match="already exists"):
        edition.plan(found, KEY, "registry.nyxus.co.uk", "0.1.0", compose_file=str(new / "docker-compose.yml"))
    assert (new / ".env").read_text() == "SOMETHING=kept\n"


def test_the_command_refuses_what_it_cannot_move(monkeypatch, capsys):
    monkeypatch.setenv("NYXUS_KEY", KEY)
    monkeypatch.setattr(cli.detect, "kubernetes", lambda c, n: {"route": "kubernetes", "namespace": "x", "deployments": []})
    assert cli.main(["upgrade", "--portal", "https://p.example.com", "--edition", "nyxus",
                     "--nyxus-version", "0.1.0", "--dry-run"]) == 2
    assert "not installed with Helm" in capsys.readouterr().err
    assert cli.main(["upgrade", "--portal", "https://p.example.com", "--edition", "nyxus", "--dry-run"]) == 2


def test_compose_stops_before_anything_when_its_container_could_not_read_the_token(tmp_path, monkeypatch):
    old, new, found = compose_setup(tmp_path)
    calls = []

    def runner(argv, timeout=900, input=None):
        calls.append(argv)
        return 0, "", ""
    monkeypatch.setattr(edition.os, "chown", lambda *a: (_ for _ in ()).throw(PermissionError()))
    monkeypatch.setattr(edition, "_group_of", lambda path: -1)
    p = edition.plan(found, KEY, "registry.nyxus.co.uk", "0.1.0", compose_file=str(new / "docker-compose.yml"), runner=runner)
    rep = Reporter()
    try:
        assert not edition.apply(p, rep, runner=runner)
    finally:
        edition.cleanup(p)
    assert calls == [] and "sudo" in rep.said[-1]


def test_images_already_on_the_host_need_no_registry(tmp_path):
    old, new, found = compose_setup(tmp_path)
    p = edition.plan(found, KEY, "registry.nyxus.co.uk", "0.1.0", compose_file=str(new / "docker-compose.yml"),
                     runner=lambda *a, **k: (0, "", ""), pull=False)
    try:
        names = [s.name for s in p.steps]
    finally:
        edition.cleanup(p)
    assert "sign in to the registry" not in names and "pull Nyxus's images" not in names
    assert all(s.stdin is None for s in p.steps)


def test_once_shadow_ai_guard_has_stopped_progress_reports_do_not_hold_the_move_back(tmp_path):
    from aiguardctl import api, upgrade
    old, new, found = compose_setup(tmp_path)
    slept, posts = [], []

    def request(portal, method, path, body=None, token=""):
        posts.append(path)
        raise api.ApiError(0, "no answer")
    rep = upgrade.Reporter("http://p", "tok", "abcdef012345", lambda m: None, sleep=slept.append, request=request)
    p = edition.plan(found, KEY, "registry.nyxus.co.uk", "0.1.0", compose_file=str(new / "docker-compose.yml"),
                     runner=lambda *a, **k: (0, "", ""), pull=False)
    try:
        assert edition.apply(p, rep, runner=lambda *a, **k: (0, "", ""))
    finally:
        edition.cleanup(p)
    stop = [s.name for s in p.steps].index("stop Shadow AI Guard")
    before = 2 * stop + 1          # running and done for each earlier step, and running for the stop
    assert len(slept) == 6 * before   # a patient report waits after each of its six tries
    assert not rep.patient and len(posts) == 6 * before + (2 * len(p.steps) - before)


# ---- what the move could not see, and who is told about it -----------------
#
# Helm moves what it owns. A deployment that kept collector CronJobs, an
# Ingress or a credential Secret outside the chart keeps them exactly as they
# were, and nothing in the move says so - which on a real deployment was two
# days of every collector being refused at the door with the pods up, the
# console up, and no page disagreeing.


@pytest.mark.parametrize("version,named", [
    ("0.5.0", True),
    ("v0.5.0", True),
    ("0.5.1", True),
    ("0.10.0", True),
    ("1.0.0", True),
    # Before 0.5.0 there is no such command. Naming one that is not there is
    # the fault this line exists to stop, not a smaller version of it.
    ("0.4.0", False),
    ("0.3.0", False),
    # And a version that cannot be read is not a licence to guess.
    ("0.5", False),
    ("", False),
    ("latest", False),
])
def test_the_follow_up_command_is_named_only_where_it_exists(version, named):
    assert edition.has_move(version) is named


def test_the_closing_line_sends_a_helm_move_to_read_the_cluster(monkeypatch, capsys):
    """The move's last word is the only moment it has somebody's attention."""
    out = _finish(monkeypatch, capsys, route="helm", version="0.5.0")
    assert "nyxusctl move" in out
    assert "--apply" in out, "and says which form changes anything"
    assert "MDM" in out, "without losing the endpoints, which are still theirs to do"


def test_an_older_nyxus_is_not_sent_after_a_command_it_does_not_have(monkeypatch, capsys):
    out = _finish(monkeypatch, capsys, route="helm", version="0.4.0")
    assert "nyxusctl move" not in out
    assert "MDM" in out


def test_compose_is_not_sent_to_read_a_cluster_it_does_not_have(monkeypatch, capsys):
    """There are no CronJobs, no Ingress and no Secret to read, and the move
    writes Compose's env files itself with the names already renamed."""
    out = _finish(monkeypatch, capsys, route="compose", version="0.5.0")
    assert "nyxusctl move" not in out
    assert "MDM" in out


def _finish(monkeypatch, capsys, route, version):
    """Drive cmd_edition to its closing line with everything else stubbed."""
    class Args:
        nyxus_version = version
        nyxus_release = "nyxus"
        nyxus_compose_file = "compose.yml"
        key_file = None
        dry_run = False
        yes = True
        no_pull = False

    plan = type("P", (), {"objects": [], "backed_up": True, "backup": "/tmp/b",
                          "tailscale": [], "context": {}})()
    monkeypatch.setattr(edition, "load_key", lambda f: "nyxl_x")
    monkeypatch.setattr(edition, "check_key", lambda k, a: "registry.example")
    monkeypatch.setattr(edition, "plan", lambda *a, **k: plan)
    monkeypatch.setattr(edition, "describe", lambda *a, **k: [])
    monkeypatch.setattr(edition, "apply", lambda *a, **k: True)
    monkeypatch.setattr(edition, "cleanup", lambda p: None)
    monkeypatch.setattr(cli.auth, "authorize", lambda p, s: "tok")
    monkeypatch.setattr(cli.api, "request", lambda *a, **k: {"id": "r1", "portal_version": "0.3.0"})
    monkeypatch.setattr(cli.upgrade, "Reporter",
                        lambda *a, **k: type("R", (), {"finish": lambda s, *a: None,
                                                       "patient": False})())
    monkeypatch.setattr(cli.upgrade, "verify",
                        lambda *a, **k: {"portal_version": version.lstrip("v")})
    assert cli.cmd_edition(Args(), "http://portal", {"route": route, "namespace": "ns",
                                                     "release": "ai-guard"}) == 0
    return capsys.readouterr().err
