# ai-guard Helm chart

Deploys the receiver: the one service every source reports to. The compiled
registry ships with the chart, so an install gives you a working receiver
with nothing to build first.

## Install

```bash
helm install ai-guard charts/ai-guard \
  --set loki.pushUrl=http://loki.monitoring.svc.cluster.local:3100/loki/api/v1/push \
  --set ingress.enabled=true \
  --set ingress.host=ai-guard.example.com
```

Read the bearer token every source authenticates with:

```bash
kubectl get secret ai-guard -o jsonpath='{.data.authToken}' | base64 -d; echo
```

Then import `dashboards/ai-guard.json` into Grafana and roll out one
collector. See [../../docs/getting-started.md](../../docs/getting-started.md).

## Values

| key | default | what it does |
|-----|---------|--------------|
| `image.repository` | `ghcr.io/amansk5/shadow-ai-guard/receiver` | receiver image, multi-arch |
| `image.tag` | chart `appVersion` | override to pin a specific build |
| `replicaCount` | `1` | the receiver is stateless, so more than one is fine |
| `auth.value` | `""` | set the token explicitly; ends up in your helm values |
| `auth.existingSecret` | `""` | use a Secret you created yourself, key `authToken` |
| `loki.pushUrl` | `""` | unset means stdout only, for pipelines that scrape logs |
| `alertmanager.url` | `""` | unset means findings are logged and dashboarded but nothing pages |
| `alertmanager.ttlMinutes` | `120` | how long a warn finding counts as already alerted |
| `displayTz` | `UTC` | timezone for the readable timestamp on alerts only |
| `registry.create` | `true` | ship the compiled registry as a ConfigMap |
| `registry.existingConfigMap` | `""` | use your own, for example built by CI on every merge |
| `service.type` | `ClusterIP` | |
| `service.port` | `8080` | |
| `ingress.enabled` | `false` | endpoints report over HTTPS, so a real deployment needs this |
| `ingress.className` | `""` | |
| `ingress.host` | `ai-guard.example.com` | |
| `ingress.tls.enabled` | `true` | |
| `ingress.tls.secretName` | `ai-guard-tls` | set empty where the ingress issues its own cert |
| `resources` | 50m / 96Mi requests | |

## The token

With neither `auth.value` nor `auth.existingSecret` set, the chart generates
a random token on first install and reuses it on upgrade, so upgrading does
not silently break every deployed collector. A `helm template` or
`--dry-run` shows a different random token each time, because the lookup
that finds the existing one only works against a live cluster. That is
expected.

## Ingress

Endpoints report from the machines themselves, so the receiver needs to be
reachable over HTTPS from everywhere a collector or the browser extension
runs.

On a cluster running the Tailscale operator, the whole thing can be private
to your tailnet with a valid certificate and no cert-manager:

```bash
--set ingress.enabled=true \
--set ingress.className=tailscale \
--set ingress.host=ai-guard \
--set ingress.tls.secretName=""
```

which serves at `https://ai-guard.<tailnet>.ts.net`. Only useful if every
reporting machine is on the tailnet.

## Registry updates

The chart ships the registry compiled at release time. To update detection
without waiting for a chart release, compile your own and point the chart at
it:

```bash
python registry/build.py
kubectl create configmap ai-guard-registry \
  --from-file=registry.json=registry/dist/registry.json \
  --from-file=collector.json=registry/dist/collector.json \
  --dry-run=client -o yaml | kubectl apply -f -
helm upgrade ai-guard charts/ai-guard --set registry.existingConfigMap=ai-guard-registry
```

The receiver reads the registry per request and the kubelet syncs ConfigMap
changes into the mount, so later updates need no restart.

## Not in the chart

Collectors and the browser extension are delivered by your MDM or RMM, not
by Kubernetes. The scanners run as CronJobs against cloud APIs and are
deployed separately.