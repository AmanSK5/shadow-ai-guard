# Copyright 2026 Aman Karir
# SPDX-License-Identifier: Apache-2.0
# Part of Shadow AI Guard, https://github.com/AmanSK5/shadow-ai-guard

"""`aiguardctl upgrade --edition nyxus` without a cluster, a host or a portal.

The properties under test: the key is the one stored in this deployment or
nothing happens, and it never appears in a command's arguments; Helm keeps the
release's storage, credentials and values, backs the database up before
anything stops, and removes Shadow AI Guard only after its credentials are
copied; Compose prepares Nyxus's project from the running one without
overwriting anything, and starts Nyxus under the same project so its volumes
are the same volumes; and the findings Shadow AI Guard stored are marked for
Nyxus to read.
"""
import base64
import hashlib
import json
import os
import stat

import pytest

from aiguardctl import cli, edition

KEY = "nyxl_eyJ2IjoxLCJpZCI6Ik5ZWC0wMDAxIn0.c2lnbmF0dXJl"
NOW = __import__("datetime").datetime(2026, 9, 20, 10, 0, 0, tzinfo=__import__("datetime").timezone.utc)


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
"""

FOUND_HELM = {"route": "helm", "release": "ai-guard", "namespace": "ai-guard", "context": None, "helm": True,
              "deployments": [{"name": "ai-guard", "container": "receiver", "tag": "0.33.0",
                               "image": "ghcr.io/amansk5/shadow-ai-guard/receiver:0.33.0"},
                              {"name": "ai-guard-portal", "container": "portal", "tag": "0.33.0",
                               "image": "ghcr.io/amansk5/shadow-ai-guard/portal:0.33.0"}],
              "cronjobs": []}
LIVE = {"ai-guard": {"authToken": "c2hhcmVk"}, "ai-guard-admin": {"adminToken": "YWRtaW4="},
        "ai-guard-portal": {"password": "cGFzc3dvcmQ="}}


def helm_runner(calls, files):
    def runner(argv, timeout=900, input=None):
        calls.append((argv, input))
        if argv[:3] == ["helm", "get", "values"]:
            return 0, json.dumps({"image": {"repository": "ghcr.io/amansk5/shadow-ai-guard/receiver"},
                                  "auth": {"value": ""}, "ingress": {"enabled": True, "host": "ai-guard.example.com"},
                                  "portal": {"enabled": True, "auth": {"password": ""}}}), ""
        if argv[:3] == ["helm", "get", "manifest"]:
            return 0, MANIFEST, ""
        if argv[:3] == ["kubectl", "get", "secret"]:
            return 0, json.dumps({"data": LIVE[argv[3]]}), ""
        if "-f" in argv:
            path = argv[argv.index("-f") + 1]
            files.append((argv, open(path).read(), stat.S_IMODE(os.stat(path).st_mode)))
        if argv[:2] == ["kubectl", "wait"]:
            return 1, "", "error: no matching resources found"
        return 0, "", ""
    return runner


def test_helm_keeps_storage_credentials_and_values_and_never_passes_the_key_as_an_argument():
    calls, files = [], []
    runner = helm_runner(calls, files)
    p = edition.plan(FOUND_HELM, KEY, "registry.nyxus.co.uk", "0.1.0", runner=runner, now=NOW)
    rep = Reporter()
    try:
        assert edition.apply(p, rep, runner=runner), rep.said
    finally:
        edition.cleanup(p)
    argvs = [" ".join(a) for a, _ in calls]
    assert all(KEY not in a for a in argvs)
    assert all(KEY not in d for _, _, d in rep.steps)
    # the order: back up, carry credentials, pull access, stop, remove, install
    order = [next(i for i, a in enumerate(argvs) if needle in a) for needle in (
        "exec deployment/ai-guard -- python -c", "get secret ai-guard ", "registry login registry.nyxus.co.uk",
        "scale deployment/ai-guard --replicas=0", "uninstall ai-guard", "install nyxus oci://registry.nyxus.co.uk/nyxus-enterprise/charts/nyxus")]
    assert order == sorted(order)
    assert [i for a, i in calls if i] == [KEY]
    assert "state.db.before-nyxus-20260920T100000Z" in argvs[order[0]]
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
    assert not os.path.exists(p.workdir)


def test_a_failed_step_stops_the_move_before_anything_after_it():
    calls, files = [], []
    base = helm_runner(calls, files)

    def runner(argv, timeout=900, input=None):
        if argv[:2] == ["helm", "registry"]:
            calls.append((argv, input))
            return 1, "", "unauthorized"
        return base(argv, timeout, input)
    p = edition.plan(FOUND_HELM, KEY, "registry.nyxus.co.uk", "0.1.0", runner=runner, now=NOW)
    try:
        assert not edition.apply(p, Reporter(), runner=runner)
    finally:
        edition.cleanup(p)
    assert not any(a[:1] == ["helm"] and "uninstall" in a for a, _ in calls)
    assert not any("scale" in a for a, _ in calls)


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

