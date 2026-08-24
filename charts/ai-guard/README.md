# ai-guard Helm chart

Deploys the receiver: the one service every source reports to. The compiled
registry ships with the chart, so an install gives you a working receiver
with nothing to build first.

## Install

The chart is published as an OCI artifact on every release, beside the
images, so no clone is needed:

```bash
helm install ai-guard oci://ghcr.io/amansk5/shadow-ai-guard/charts/ai-guard \
  --set ingress.enabled=true \
  --set ingress.host=ai-guard.example.com \
  --set portal.ingress.enabled=true \
  --set portal.ingress.host=ai-guard-portal.example.com
```

Managed mode is the default, and that is the whole install: the receiver prints a
one-time setup code to its log, the portal turns it into the admin account,
and the first-run wizard configures everything else (log store, public
receiver URL, corporate domains, governance, deployment downloads) at
runtime. See
[../../docs/deployment/kubernetes.md](../../docs/deployment/kubernetes.md).

Classic mode (`managed.enabled=false`) instead configures by values, as
ever - file-driven, no server-side state, basic auth (from a checkout,
`charts/ai-guard` in place of the OCI reference works the same):

```bash
helm install ai-guard oci://ghcr.io/amansk5/shadow-ai-guard/charts/ai-guard \
  --set managed.enabled=false \
  --set loki.pushUrl=http://loki.monitoring.svc.cluster.local:3100/loki/api/v1/push \
  --set portal.lokiUrl=http://loki.monitoring.svc.cluster.local:3100 \
  --set ingress.enabled=true \
  --set ingress.host=ai-guard.example.com
```

Read the bearer token every source authenticates with:

```bash
kubectl get secret ai-guard -o jsonpath='{.data.authToken}' | base64 -d; echo
```

Then import `dashboards/ai-guard.json` into Grafana and roll out one
collector. See [../../docs/getting-started.md](../../docs/getting-started.md).

## Versions

Three numbers exist and they mean different things. They drifted once because
nothing said which was which, so:

| where | what it is |
|---|---|
| the git tag, e.g. `v0.4.0` | the release. What CI publishes images under. |
| `Chart.yaml` `appVersion` | the release this chart installs. `image.tag` defaults to it, so **this is what gets pulled**. CI fails a tag build if it disagrees with the tag. |
| `Chart.yaml` `version` | the chart's own version. Bump it whenever anything under `charts/` changes: a repo index compares it to decide whether an upgrade exists. |
| `/healthz` version | what the image was built from: the release on a tag build, `main-<sha>` on a build off main, `dev` on a local one. Set at build time, so it cannot drift from what is running. |

`appVersion` sat at `0.2.0` through the `0.3.0` release, so a default
`helm install` deployed a receiver a full release behind while reporting
success. That is why CI checks it now.

## The portal

Enabled by default. Deploying the receiver should give you somewhere to look at
what it collected, rather than a service with no face until you find a second
document.

It needs one thing set:

    --set portal.lokiUrl=http://loki.monitoring.svc.cluster.local:3100

That is the **base** URL, not the push endpoint - the portal appends its own
query path, unlike `loki.pushUrl` which the receiver POSTs to verbatim.

The portal refuses to start without authentication, because it names who runs
what on which machine. In managed mode - the default - that is the real
login backed by the receiver's accounts: the setup code creates the first
admin, and more accounts (admin or read-only viewer) are added under
Settings. The generated password below is the **classic-mode** path, kept
across upgrades the same way the chart handles the bearer token:

    kubectl get secret <release>-ai-guard-portal \
      -o jsonpath='{.data.password}' | base64 -d; echo

Basic auth is one shared credential with no per-user trail. If your ingress can
do OIDC or mTLS, do it there and set `portal.auth.mode=none` behind it - that
logs a warning on every start, so an unauthenticated deployment is never
something nobody noticed.

`portal.enabled=false` if you only want the receiver.

**Upgrading from a release before 0.4.0:** the portal appears as a new
Deployment with a generated password. It is additive - nothing about the
receiver changes - and its ingress is off by default, so nothing new is exposed
until you decide to expose it.

Use `--reset-then-reuse-values`, not `--reuse-values`:

    helm upgrade ai-guard charts/ai-guard --reset-then-reuse-values \
      --set portal.lokiUrl=http://loki.monitoring.svc.cluster.local:3100

`--reuse-values` keeps only the values you set previously and discards
everything underneath them, including defaults a newer chart added. So the
portal either silently does not appear - `portal.enabled` defaults to true, but
that default is one of the ones dropped - or the templates fail on the gaps.
The chart detects the second case and says this rather than failing on a nil
pointer.

### Adding Grafana panels later

You will not know the panel ids until Grafana is running with data in it, so
this is normally a second pass rather than something set at install:

    helm upgrade ai-guard charts/ai-guard --reset-then-reuse-values \
      --set portal.grafana.url=https://grafana.example.com \
      --set-string 'portal.grafana.panels=ai-guard:19:Devices reporting'

`--set-string` because the value contains colons and commas that `--set` would
try to parse as structure.

The uid is in the dashboard URL after `/d/`. The panel id is the
`viewPanel=<n>` at the end of a panel's Share link. `portal/README.md` covers
what Grafana itself needs before it will allow the frame - three settings, one
of which locks you out of Grafana if you miss it.

The portal uses its own `app.kubernetes.io/name` rather than a component label
on the shared one. A Deployment's selector is immutable, so adding a label to
the receiver's selector would fail every upgrade from a release that predates
the portal.

## Values

| key | default | what it does |
|-----|---------|--------------|
| `image.repository` | `ghcr.io/amansk5/shadow-ai-guard/receiver` | receiver image, multi-arch |
| `image.tag` | chart `appVersion` | override to pin a specific build |
| `replicaCount` | `1` | the receiver is stateless, so more than one is fine |
| `auth.value` | `""` | set the token explicitly; ends up in your helm values |
| `auth.existingSecret` | `""` | use a Secret you created yourself, key `authToken` |
| `loki.pushUrl` | `""` | unset means stdout only, for pipelines that scrape logs |
| `loki.username` | `""` | basic auth, used by BOTH containers: the receiver writes, the portal reads |
| `loki.existingSecret` | `""` | a Secret with a `lokiPassword` key. Not a value: `helm get values` would show it |
| `portal.loki.username` / `portal.loki.existingSecret` | `""` | optional read-only credentials for the portal, overriding the shared pair - where your store can mint separate tokens, the portal then never holds a write credential |
| `alertmanager.url` | `""` | unset means findings are logged and dashboarded but nothing pages |
| `alertmanager.ttlMinutes` | `120` | how long a warn finding counts as already alerted |
| `displayTz` | `UTC` | timezone for the readable timestamp on alerts only |
| `corpDomains` | `[]` | corporate domains served to the collectors via `/registry/collector`; collectors prefer this to their local list, so a change here reaches the fleet on its next check-in with no MDM re-push |
| `managed.enabled` | `true` | the default since 0.9.9: device enrollment, accounts, central settings and a fleet inventory, backed by SQLite on a PVC. Requires `replicaCount: 1` (the chart refuses otherwise) and switches the Deployment to `Recreate`. Set `false` for classic mode |
| `managed.adminToken.value` | `""` | the optional API credential for `/admin/*`: automation, break-glass recovery, and the portal's own service reads (viewer accounts reading a wizard-saved log store, and the digest task). Set it if you use viewer accounts or the digest; leaving both unset means no admin secret exists at all |
| `managed.adminToken.existingSecret` | `""` | a Secret you created yourself, key `adminToken` |
| `managed.persistence.size` | `1Gi` | the state PVC. Annotated `helm.sh/resource-policy: keep`: uninstalling the chart does not unenroll the fleet |
| `managed.persistence.existingClaim` | `""` | use a PVC you created yourself |
| `managed.requireDeviceCredentials` | `false` | the shared token's off-switch, once every surface has enrolled: ingest accepts device credentials only and refuses the shared token with a 401 that says "enroll". Flip it back and unenrolled machines report again |
| `portal.digest.webhookUrl` | `""` | a Slack-compatible webhook for the portal's weekly digest. When set alongside `managed.adminToken`, the chart mounts the credential for the portal's background reads |
| `portal.digest.day` / `portal.digest.hour` | `""` | when the digest sends; defaults to Monday 08:00 UTC |
| `portal.receiverUrl` | receiver service | managed mode: where the portal proxies admin actions; defaults to the chart's own receiver service |
| `portal.receiverPublicUrl` | ingress host | managed mode: the ingest URL baked into downloaded deployment artifacts; defaults to the receiver ingress host when one is enabled |
| `registry.create` | `true` | ship the compiled registry as a ConfigMap |
| `registry.existingConfigMap` | `""` | use your own, for example built by CI on every merge |
| `service.type` | `ClusterIP` | |
| `service.port` | `8080` | |
| `ingress.enabled` | `false` | endpoints report over HTTPS, so a real deployment needs this |
| `ingress.exposeAdminApi` | `false` | the public ingress carries only the reporting surfaces; `/admin` and `/metrics` stay cluster-internal. `true` restores expose-everything for automation that drives `/admin` from outside |
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

## A log store that needs credentials

Grafana Cloud and most hosted Loki want basic auth, and both containers need
it: the receiver to write and the portal to read.

```bash
kubectl create secret generic my-loki-creds \
  --from-literal=lokiPassword='<token>'

helm upgrade --install ai-guard charts/ai-guard \
  --set loki.username=123456 \
  --set loki.existingSecret=my-loki-creds
```

Setting them for one and not the other gives you a deployment where findings
are stored and cannot be read back, and neither container reports an error you
would attribute to the right cause: the receiver is healthy, its push counter
climbs, and the portal returns something a deployer reads as their own
misconfiguration.

On Grafana Cloud the username is a numeric instance id rather than an email,
and the access policy needs `logs:write` AND `logs:read`. A read-only token
produces a 401 on every push that the receiver counts and logs while still
answering 200 to the collector, so findings look accepted and are not stored.
`aiguard_loki_push_total` staying at zero while findings arrive is that
failure.

## Not in the chart

Collectors and the browser extension are delivered by your MDM or RMM, not
by Kubernetes. The scanners run as CronJobs against cloud APIs and are
deployed separately.