"""aiguardctl without a cluster, a host or a portal: every external command
and every HTTP call is replaced, so what is tested is what the command
would run and what it would send - which is what SECURITY.md promises."""
import json

import pytest

from aiguardctl import api, auth, detect, upgrade


def _kubectl(items, cronjobs=()):
    def runner(argv, timeout=120):
        if "deployments" in argv:
            return 0, json.dumps({"items": items}), ""
        if "cronjobs" in argv:
            return 0, json.dumps({"items": list(cronjobs)}), ""
        raise AssertionError(argv)
    return runner


def _dep(name, image, ns="ai-guard", rel="ai-guard", helm=True):
    labels = {"app.kubernetes.io/name": "ai-guard", "app.kubernetes.io/instance": rel}
    if helm:
        labels["app.kubernetes.io/managed-by"] = "Helm"
    return {"metadata": {"name": name, "namespace": ns, "labels": labels},
            "spec": {"template": {"spec": {"containers": [{"name": name.split("-")[-1], "image": image}]}}}}


def _cj(name, image):
    return {"metadata": {"name": name},
            "spec": {"jobTemplate": {"spec": {"template": {"spec": {"containers": [{"name": "job", "image": image}]}}}}}}


def test_kubernetes_detection_names_only_our_objects(monkeypatch):
    monkeypatch.setattr(detect, "have", lambda b: True)
    items = [_dep("ai-guard", "ghcr.io/amansk5/shadow-ai-guard/receiver:0.28.0"),
             _dep("ai-guard-portal", "ghcr.io/amansk5/shadow-ai-guard/portal:0.28.0"),
             _dep("someone-elses", "nginx:1.27", rel="ai-guard")]
    cjs = [_cj("nightly-scan", "ghcr.io/amansk5/shadow-ai-guard/scanner:0.28.0"),
           _cj("backup", "ghcr.io/other/backup:1")]
    found = detect.kubernetes(None, None, runner=_kubectl(items, cjs))
    assert found["route"] == "helm" and found["release"] == "ai-guard"
    assert [d["name"] for d in found["deployments"]] == ["ai-guard", "ai-guard-portal"]
    assert [c["name"] for c in found["cronjobs"]] == ["nightly-scan"]
    assert found["deployments"][0]["tag"] == "0.28.0"


def test_two_releases_need_a_namespace(monkeypatch):
    monkeypatch.setattr(detect, "have", lambda b: True)
    items = [_dep("ai-guard", "ghcr.io/amansk5/shadow-ai-guard/receiver:0.28.0", ns="a", rel="a"),
             _dep("ai-guard", "ghcr.io/amansk5/shadow-ai-guard/receiver:0.28.0", ns="b", rel="b")]
    with pytest.raises(detect.DetectError) as e:
        detect.kubernetes(None, None, runner=_kubectl(items))
    assert "--namespace" in str(e.value)


def test_a_helm_release_without_helm_on_path_is_refused(monkeypatch):
    monkeypatch.setattr(detect, "have", lambda b: b != "helm")
    items = [_dep("ai-guard", "ghcr.io/amansk5/shadow-ai-guard/receiver:0.28.0")]
    with pytest.raises(detect.DetectError):
        detect.kubernetes(None, None, runner=_kubectl(items))


def test_compose_detection_limits_itself_to_our_services(monkeypatch):
    monkeypatch.setattr(detect, "have", lambda b: True)
    ps = [{"ID": "1", "Image": "ghcr.io/amansk5/shadow-ai-guard/receiver:0.28.0"},
          {"ID": "2", "Image": "ghcr.io/amansk5/shadow-ai-guard/portal:0.28.0"},
          {"ID": "3", "Image": "grafana/grafana:11"}]
    def inspect(cid, image):
        return {"Config": {"Image": image, "Labels": {
            "com.docker.compose.project": "ai-guard", "com.docker.compose.service": image.split("/")[-1].split(":")[0],
            "com.docker.compose.project.working_dir": "/srv/ai-guard",
            "com.docker.compose.project.config_files": "/srv/ai-guard/docker-compose.yml"}}}
    def runner(argv, timeout=120):
        if argv[:2] == ["docker", "ps"]:
            return 0, "\n".join(json.dumps(r) for r in ps), ""
        if argv[:2] == ["docker", "inspect"]:
            assert argv[2:] == ["1", "2"], "only our containers are inspected"
            return 0, json.dumps([inspect("1", ps[0]["Image"]), inspect("2", ps[1]["Image"])]), ""
        raise AssertionError(argv)
    found = detect.compose(runner=runner)
    assert found["route"] == "compose" and found["project"] == "ai-guard"
    assert sorted(s["service"] for s in found["services"]) == ["portal", "receiver"]
    cmds = upgrade.commands(found, "v0.29.0")
    assert cmds[0] == ["docker", "compose", "--project-directory", "/srv/ai-guard",
                       "-f", "/srv/ai-guard/docker-compose.yml", "pull", "portal", "receiver"]
    assert cmds[1][-3:] == ["--no-deps", "portal", "receiver"] and "up" in cmds[1]


def test_an_image_of_ours_outside_compose_is_refused(monkeypatch):
    monkeypatch.setattr(detect, "have", lambda b: True)
    def runner(argv, timeout=120):
        if argv[:2] == ["docker", "ps"]:
            return 0, json.dumps({"ID": "1", "Image": "ghcr.io/amansk5/shadow-ai-guard/portal:0.28.0"}), ""
        return 0, json.dumps([{"Config": {"Image": "ghcr.io/amansk5/shadow-ai-guard/portal:0.28.0", "Labels": {}}}]), ""
    with pytest.raises(detect.DetectError):
        detect.compose(runner=runner)


def test_helm_commands_reuse_values_and_bump_the_cronjobs():
    found = {"route": "helm", "release": "ai-guard", "namespace": "sec", "context": "prod",
             "deployments": [{"name": "ai-guard", "container": "receiver",
                              "image": "ghcr.io/amansk5/shadow-ai-guard/receiver:0.28.0", "tag": "0.28.0"}],
             "cronjobs": [{"name": "nightly", "container": "job",
                           "image": "ghcr.io/amansk5/shadow-ai-guard/scanner:0.28.0", "tag": "0.28.0"}]}
    cmds = upgrade.commands(found, "v0.29.0")
    assert cmds[0] == ["helm", "--kube-context", "prod", "upgrade", "ai-guard", upgrade.CHART,
                       "--version", "0.29.0", "--namespace", "sec", "--reuse-values", "--wait", "--timeout", "10m"]
    assert cmds[1] == ["kubectl", "--context", "prod", "-n", "sec", "set", "image", "cronjob/nightly",
                       "job=ghcr.io/amansk5/shadow-ai-guard/scanner:0.29.0"]
    assert all(c[0] in ("helm", "kubectl") for c in cmds)
    text = "\n".join(upgrade.describe(found, {"portal_version": "0.28.0", "receiver_version": "0.28.0"}, "v0.29.0"))
    assert "$ helm --kube-context prod upgrade ai-guard" in text and "CronJob  nightly" in text


def test_bare_kubernetes_sets_images_on_labelled_objects_only():
    found = {"route": "kubernetes", "release": "", "namespace": "ai", "context": None,
             "deployments": [{"name": "ai-guard-portal", "container": "portal",
                              "image": "ghcr.io/amansk5/shadow-ai-guard/portal:0.28.0", "tag": "0.28.0"}],
             "cronjobs": []}
    cmds = upgrade.commands(found, "0.29.0")
    assert cmds[0] == ["kubectl", "-n", "ai", "set", "image", "deployment/ai-guard-portal",
                       "portal=ghcr.io/amansk5/shadow-ai-guard/portal:0.29.0"]
    assert cmds[1][:5] == ["kubectl", "-n", "ai", "rollout", "status"]


def test_apply_stops_at_the_first_failure_and_reports_steps_not_output():
    posted = []
    def request(portal, method, path, body=None, token=""):
        posted.append((path, body)); return {}
    said = []
    rep = upgrade.Reporter("http://p", "aigu_t", "abcdef012345", said.append, sleep=lambda s: None, request=request)
    found = {"route": "compose", "project": "x", "working_dir": "/w", "config_files": "",
             "services": [{"service": "portal", "image": "i", "tag": "0.28.0"}]}
    calls = []
    def runner(argv, timeout=900):
        calls.append(argv)
        return (1, "", "SECRET_VALUE=abc leaked in output") if len(calls) == 1 else (0, "", "")
    assert upgrade.apply(found, "0.29.0", rep, runner=runner) is False
    assert len(calls) == 1, "nothing runs after a failure"
    assert posted[-1][1]["status"] == "failed" and posted[-1][1]["detail"] == "exit 1"
    assert not any("SECRET_VALUE" in json.dumps(b) for _, b in posted), "output never leaves the terminal"
    assert any("SECRET_VALUE" in s for s in said), "but the operator sees it"


def test_a_missed_report_never_fails_the_upgrade():
    attempts = []
    def request(portal, method, path, body=None, token=""):
        attempts.append(path); raise api.ApiError(0, "portal restarting")
    rep = upgrade.Reporter("http://p", "aigu_t", "abcdef012345", lambda m: None, sleep=lambda s: None, request=request)
    rep.step("helm upgrade", "running")  # returns; does not raise
    assert len(attempts) == 6


def test_authorize_polls_until_approved_and_never_sees_a_password():
    calls = []
    def poll(portal, method, path, body=None, token=""):
        calls.append((path, body))
        if path == "/api/cli/authorize":
            assert set(body) == {"purpose", "verifier_hash", "client"}
            return {"device_code": "aigd_x", "user_code": "ABCD-EFGH", "approve_path": "/#cli-approve/ABCD-EFGH",
                    "interval": 0, "expires_in": 60}
        if len([c for c in calls if c[0] == "/api/cli/token"]) < 3:
            raise api.ApiError(428, "authorization_pending")
        assert body["device_code"] == "aigd_x" and len(body["verifier"]) > 16
        return {"token": "aigu_token"}
    opened = []
    said = []
    tok = auth.authorize("http://p", said.append, open_browser=opened.append, sleep=lambda s: None, poll=poll)
    assert tok == "aigu_token" and opened == ["http://p/#cli-approve/ABCD-EFGH"]
    assert any("ABCD-EFGH" in s for s in said)


def test_a_denial_is_final():
    def poll(portal, method, path, body=None, token=""):
        if path == "/api/cli/authorize":
            return {"device_code": "aigd_x", "user_code": "ABCD-EFGH", "approve_path": "/#cli-approve/ABCD-EFGH", "interval": 0, "expires_in": 60}
        raise api.ApiError(403, "denied by the owner")
    with pytest.raises(auth.Denied):
        auth.authorize("http://p", lambda m: None, open_browser=lambda u: None, sleep=lambda s: None, poll=poll)


def test_the_command_has_no_third_party_dependencies():
    import pathlib
    src = pathlib.Path(upgrade.__file__).parent
    for f in src.glob("*.py"):
        for line in f.read_text().splitlines():
            if line.startswith(("import ", "from ")) and not line.startswith("from ."):
                mod = line.split()[1].split(".")[0]
                assert mod in {"json", "urllib", "hashlib", "secrets", "time", "webbrowser", "shutil",
                               "subprocess", "argparse", "sys", "__future__"}, line
