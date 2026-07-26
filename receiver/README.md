# Receiver

The receiver is the one service in the platform. Every source POSTs findings
to it, it validates them, logs them as JSON lines on stdout, and optionally
pushes them straight to Loki and raises Alertmanager alerts. One container,
no database: the findings live in your log pipeline, not in the receiver.

It also serves the compiled registry, so collectors fetch their identifier
lists at runtime instead of carrying hardcoded copies.

## Endpoints

| method | path | auth | what |
|--------|------|------|------|
| GET  | `/healthz` | none | liveness and version |
| GET  | `/metrics` | none | Prometheus metrics |
| GET  | `/registry` | bearer | the full compiled registry |
| GET  | `/registry/collector` | bearer | the collector view of the registry |
| POST | `/report` | bearer | submit a finding |
| POST | `/flag` | bearer | same as `/report`, kept for older browser extension versions |

Auth is a single bearer token. It is a write-mostly credential: it can
submit findings and read the registry, nothing else.

## Configuration

Everything is environment variables. Only the token is required.

| variable | default | what it does |
|----------|---------|--------------|
| `AUTH_TOKEN` | required | the one bearer token every source authenticates with |
| `LOKI_PUSH_URL` | unset | if set, findings are POSTed straight to Loki as well; stdout logging happens regardless |
| `ALERTMANAGER_URL` | unset | if set, `warn` findings raise Alertmanager alerts; unset means findings are logged and dashboarded but nothing pages |
| `ALERT_TTL_MINUTES` | `120` | how long a warn finding counts as already alerted, so a device reporting the same thing repeatedly does not page repeatedly |
| `REGISTRY_PATH` | `/etc/ai-guard/registry.json` | where the compiled registry is mounted |
| `COLLECTOR_REGISTRY_PATH` | `/etc/ai-guard/collector.json` | where the collector view is mounted |
| `DISPLAY_TZ` | `UTC` | timezone for the human-readable timestamp on alerts only; machine timestamps are always UTC |

The registry is read per request, and the kubelet syncs ConfigMap changes
into the pod, so a registry update is a rebuild and a `kubectl apply` with
no receiver restart.

## Deploying

`deploy/receiver.yaml` is a working example: Deployment, Service and
Ingress, adapted from a real deployment. Change the Loki URL and the
ingress host, create the Secret and the registry ConfigMap, and apply it.

Two things worth knowing before the first apply:

- The pod mounts the registry ConfigMap. If you apply the Deployment before
  the ConfigMap exists, the pod sits in ContainerCreating with a
  FailedMount event until it does. It recovers on its own; nothing needs
  restarting.
- The ingress needs to be HTTPS and reachable from every endpoint that
  reports. The browser extension in particular will not POST to a plain
  HTTP endpoint.

The receiver listens on 8080 and runs as a non-root user.