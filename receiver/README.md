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
| GET  | `/healthz` | none | liveness, and the version the image was built from |
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
| `LOKI_PUSH_URL` | unset | if set, findings are POSTed straight to Loki as well; stdout logging happens regardless. The **full push endpoint**, `/loki/api/v1/push`, not the base URL |
| `LOKI_USERNAME` | unset | basic auth for the push, if your log store needs it. Hosted Loki usually does; a self-hosted one usually does not |
| `LOKI_PASSWORD` | unset | with the above. Sent only when a username is set, because an empty credential pair is not the same as sending none |
| `ALERTMANAGER_URL` | unset | if set, `warn` findings raise Alertmanager alerts; unset means findings are logged and dashboarded but nothing pages |
| `ALERT_TTL_MINUTES` | `120` | how long a warn finding counts as already alerted, so a device reporting the same thing repeatedly does not page repeatedly |
| `REGISTRY_PATH` | `/etc/ai-guard/registry.json` | where the compiled registry is mounted |
| `COLLECTOR_REGISTRY_PATH` | `/etc/ai-guard/collector.json` | where the collector view is mounted |
| `DISPLAY_TZ` | `UTC` | timezone for the human-readable timestamp on alerts only; machine timestamps are always UTC |

Any of these can be given as `NAME_FILE` pointing at a file instead:
`AUTH_TOKEN_FILE=/run/secrets/auth_token` rather than `AUTH_TOKEN`. That
exists because Docker Compose has no real secret story - an environment
variable is visible in `docker inspect`, in `/proc`, and in every child
process's environment, while a file is confined to the filesystem. **That is
better and it is not encryption:** it is still plaintext on the same disk.
Kubernetes has Secrets and does not need it.

The value is stripped, which matters: almost every way of writing a file
leaves a trailing newline, and a token differing by one fails authentication
with no indication why. A missing or unreadable file is fatal rather than a
silent fallback, because falling back would start the receiver with an empty
token.

`/healthz` reports the version the image was built from: the release on a tag
build, `main-<sha>` on a build off main, `dev` on a local one. It is set at
build time, so it cannot drift from what is running.

The registry is read per request, and the kubelet syncs ConfigMap changes
into the pod, so a registry update is a rebuild and a `kubectl apply` with
no receiver restart.

## When findings stop arriving

The receiver answers 200 to a reporting source even when the push to the log
store fails. That is deliberate - a log store being down should not lose a
collector's finding, which is on stdout regardless - but it means a
misconfigured push is invisible from the collector's side.

Push failures log at error with the URL and, for the codes that account for
almost every misconfiguration, the likely cause: a 404 usually means
`LOKI_PUSH_URL` is the base URL rather than the push endpoint; a 401 or 403
means the credentials are needed or wrong.

On `/metrics`:

- `aiguard_loki_push_failures_total` counts failures by reason
- `aiguard_loki_push_last_success_timestamp` is the one to alert on. Findings
  arrive irregularly, so a failure counter alone cannot tell "nothing is
  happening" from "everything is failing"; `time()` minus this answers it.

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