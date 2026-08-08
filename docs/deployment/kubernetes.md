# Deploying on Kubernetes

Deploys the receiver: the one service every source reports to. The portal is
not in the chart yet and is available on the [Docker Compose
route](../../deploy/compose/README.md).

If you have no cluster, you do not need one: see [the routes](README.md).

## Prerequisites

- A cluster you can deploy to. Anything conformant; nothing here is cloud
  specific.
- A log pipeline that ingests container stdout. The dashboard assumes Loki,
  but the receiver's only output is JSON lines, so anything that scrapes
  stdout works.
- An ingress your endpoints can reach. Collectors report from off your
  network, so the receiver has to be reachable, with TLS and a real
  certificate.

## The short way

The chart does everything below in one command, with the compiled registry
already inside it:

```bash
helm install ai-guard charts/ai-guard \
  --namespace ai-guard --create-namespace \
  --set loki.pushUrl=http://loki.monitoring.svc.cluster.local:3100/loki/api/v1/push \
  --set ingress.enabled=true \
  --set ingress.host=ai-guard.example.com
```

Read the token it generated:

```bash
kubectl -n ai-guard get secret ai-guard \
  -o jsonpath='{.data.authToken}' | base64 -d; echo
```

[`charts/ai-guard/README.md`](../../charts/ai-guard/README.md) covers every
value, including bringing your own token or your own registry ConfigMap, and
which version number means what.

Then continue at [getting started](../getting-started.md).

## By hand

The same thing without Helm, if you would rather see the pieces.

### The images

Published to GHCR by CI, so nothing needs building:

```
ghcr.io/amansk5/shadow-ai-guard/receiver:0.4.0
```

Built for `linux/amd64` and `linux/arm64` under one tag, so it resolves on
Graviton, Apple Silicon and a Pi without anything extra:

```bash
docker buildx imagetools inspect ghcr.io/amansk5/shadow-ai-guard/receiver:0.4.0
```

Pin a version. `latest` moves when a release is tagged, which means a pod
rescheduling onto a node without the image cached can quietly pick up a
different build.

### 1. Namespace and token

Pick a namespace and use it consistently: the Secret, the ConfigMap and the
Deployment all have to land in the same one.

```bash
export NS=ai-guard
kubectl create namespace "$NS"

kubectl -n "$NS" create secret generic ai-guard-receiver \
  --from-literal=authToken="$(openssl rand -hex 32)"
```

Every source authenticates with this one token: collectors, scanners and the
browser extension.

### 2. The registry

The list of AI tools to detect. Collectors fetch it from the receiver at
runtime, so it lives in a ConfigMap the receiver serves.

`build.py` needs `pyyaml` and `jsonschema`. On current Homebrew or Debian
Python (PEP 668), use a venv:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install pyyaml jsonschema
python registry/build.py

kubectl -n "$NS" create configmap ai-guard-registry \
  --from-file=registry.json=registry/dist/registry.json \
  --from-file=collector.json=registry/dist/collector.json
```

The receiver reads the registry per request and the kubelet syncs ConfigMap
changes into the pod, so updating it later is a rebuild and a `kubectl apply`
with no restart.

### 3. The receiver

Deploy it with the Secret mounted as `AUTH_TOKEN` and the ConfigMap at
`/etc/ai-guard`. It listens on 8080.

[`receiver/deploy/receiver.yaml`](../../receiver/deploy/receiver.yaml) is a
working manifest to adapt, and
[`receiver/README.md`](../../receiver/README.md) documents every variable and
endpoint.

If you deploy before the ConfigMap exists, the pod sits in ContainerCreating
with a FailedMount event. That is normal: create the ConfigMap and the kubelet
mounts it within a minute, no restart needed.

Optional, all off by default:

- `LOKI_PUSH_URL` - the **full push endpoint**, `/loki/api/v1/push`, not the
  base URL. Unset means stdout only, for pipelines that scrape logs.
- `LOKI_USERNAME` and `LOKI_PASSWORD` - basic auth for a hosted log store.
- `ALERTMANAGER_URL` - unset means findings are logged and dashboarded but
  nothing pages.
- `DISPLAY_TZ` - timezone for the human-readable timestamp on alerts.

Confirm it is up:

```bash
curl -s https://your-receiver-host/healthz
```

And that it serves the registry:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  https://your-receiver-host/registry/collector | head
```

## When findings stop arriving

The receiver answers 200 to a reporting source even when the push to the log
store fails. That is deliberate - a log store being down should not lose a
collector's finding, which is on stdout regardless - but it means a
misconfigured push is invisible from the collector's side.

```bash
kubectl -n "$NS" logs deploy/ai-guard-receiver | grep '"kind": "error"'
```

Push failures log at error with the URL and, for the codes that account for
almost every misconfiguration, the likely cause. A 404 usually means
`LOKI_PUSH_URL` is the base URL rather than the push endpoint.

`aiguard_loki_push_last_success_timestamp` on `/metrics` is the one to alert
on: findings arrive irregularly, so a failure counter alone cannot tell
"nothing is happening" from "everything is failing".

## Then

[Getting started](../getting-started.md) picks up here: rolling out a
collector, seeing the first finding, the dashboard, and the portal.