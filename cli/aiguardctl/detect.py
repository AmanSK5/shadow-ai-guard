"""What is deployed, read with the operator's own tools. Only objects that
carry this project's labels or run this project's images are ever named;
everything else in the cluster or on the host is invisible to this command
on purpose. Every external command runs through `run`, which the tests
replace."""
from __future__ import annotations

import json
import shutil
import subprocess

IMAGE_REPO = "ghcr.io/amansk5/shadow-ai-guard"
NAME_LABEL = "app.kubernetes.io/name=ai-guard"


class DetectError(Exception):
    pass


def run(argv: list[str], timeout: int = 120) -> tuple[int, str, str]:
    p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def have(binary: str) -> bool:
    return shutil.which(binary) is not None


def _tag(image: str) -> str:
    # ghcr.io/x/y/receiver:0.28.0 -> 0.28.0 ; digests count as unknown
    if "@" in image:
        return "digest"
    last = image.rsplit("/", 1)[-1]
    return last.split(":", 1)[1] if ":" in last else "latest"


def _ours(image: str, component: str | None = None) -> bool:
    if not image.startswith(IMAGE_REPO + "/"):
        return False
    if component is None:
        return True
    return image.startswith("%s/%s:" % (IMAGE_REPO, component)) or \
        image.startswith("%s/%s@" % (IMAGE_REPO, component))


def kubernetes(context: str | None, namespace: str | None, runner=run) -> dict | None:
    """The chart's Deployments and any CronJobs running this project's
    scanner or discovery images. None when kubectl is absent or finds
    nothing labelled as ours."""
    if not have("kubectl"):
        return None
    base = ["kubectl"] + (["--context", context] if context else [])
    scope = ["-n", namespace] if namespace else ["-A"]
    code, out, err = runner(base + ["get", "deployments"] + scope
                            + ["-l", NAME_LABEL, "-o", "json"])
    if code != 0:
        raise DetectError("kubectl could not list deployments: %s" % err.strip()[:200])
    items = json.loads(out or "{}").get("items", [])
    if not items:
        return None
    releases = {}
    for d in items:
        md = d["metadata"]
        rel = md.get("labels", {}).get("app.kubernetes.io/instance", "")
        ns = md["namespace"]
        entry = releases.setdefault((rel, ns), {"release": rel, "namespace": ns,
                                                "deployments": [], "helm": False})
        for c in d["spec"]["template"]["spec"]["containers"]:
            if _ours(c["image"]):
                entry["deployments"].append({"name": md["name"], "container": c["name"],
                                             "image": c["image"], "tag": _tag(c["image"])})
        if md.get("labels", {}).get("app.kubernetes.io/managed-by") == "Helm":
            entry["helm"] = True
    if len(releases) > 1 and not namespace:
        raise DetectError("more than one release found (%s); say which with "
                          "--namespace" % ", ".join("%s in %s" % k for k in releases))
    found = next(iter(releases.values()))
    found["context"] = context
    # CronJobs: only those whose image is this project's own.
    code, out, err = runner(base + ["get", "cronjobs", "-n", found["namespace"], "-o", "json"])
    found["cronjobs"] = []
    if code == 0:
        for cj in json.loads(out or "{}").get("items", []):
            for c in cj["spec"]["jobTemplate"]["spec"]["template"]["spec"]["containers"]:
                if _ours(c["image"], "scanner") or _ours(c["image"], "discovery"):
                    found["cronjobs"].append({"name": cj["metadata"]["name"],
                                              "container": c["name"],
                                              "image": c["image"], "tag": _tag(c["image"])})
    if found["helm"] and not have("helm"):
        raise DetectError("this release is managed by Helm and `helm` is not on PATH")
    found["route"] = "helm" if found["helm"] else "kubernetes"
    return found


def compose(runner=run) -> dict | None:
    """The compose project whose running containers use this project's
    receiver and portal images. None when docker is absent or no such
    containers run."""
    if not have("docker"):
        return None
    code, out, err = runner(["docker", "ps", "--format", "{{json .}}", "--no-trunc"])
    if code != 0:
        raise DetectError("docker could not list containers: %s" % err.strip()[:200])
    rows = [json.loads(line) for line in out.splitlines() if line.strip()]
    ours = [r for r in rows if _ours(r.get("Image", ""))]
    if not ours:
        return None
    ids = [r["ID"] for r in ours]
    code, out, err = runner(["docker", "inspect"] + ids)
    if code != 0:
        raise DetectError("docker inspect failed: %s" % err.strip()[:200])
    services, projects, files, dirs = [], set(), set(), set()
    for c in json.loads(out or "[]"):
        labels = c.get("Config", {}).get("Labels", {}) or {}
        image = c.get("Config", {}).get("Image", "")
        if not labels.get("com.docker.compose.project"):
            raise DetectError("%s runs our image but is not a compose service; this "
                              "command only upgrades compose projects" % image)
        projects.add(labels["com.docker.compose.project"])
        files.add(labels.get("com.docker.compose.project.config_files", ""))
        dirs.add(labels.get("com.docker.compose.project.working_dir", ""))
        services.append({"service": labels["com.docker.compose.service"],
                         "image": image, "tag": _tag(image)})
    if len(projects) > 1:
        raise DetectError("our images run in more than one compose project (%s)"
                          % ", ".join(sorted(projects)))
    return {"route": "compose", "project": next(iter(projects)),
            "working_dir": next(iter(dirs)), "config_files": next(iter(files)),
            "services": services}
