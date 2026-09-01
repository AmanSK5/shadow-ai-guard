# Deploying on Kubernetes

Deploys the receiver, which every source reports to, and the portal, which
reads the findings back. Both are in the chart and the portal is enabled by
default; set `portal.enabled=false` if you want the receiver alone.

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

## The short way: managed mode (the default)

One command, no clone - the chart is published as an OCI artifact beside the
images, and managed mode is the default since 0.9.9. Only what creates
cluster objects goes on the command line (the ingresses); everything else is
configured in the portal afterwards:

```bash
helm install ai-guard oci://ghcr.io/amansk5/shadow-ai-guard/charts/ai-guard \
  --namespace ai-guard --create-namespace \
  --set ingress.enabled=true \
  --set ingress.host=ai-guard.example.com \
  --set portal.ingress.enabled=true \
  --set portal.ingress.host=ai-guard-portal.example.com
```

(On a Tailscale-operator cluster: `ingress.className=tailscale` and
`portal.ingress.className=tailscale` with short hostnames like `ai-guard` -
the operator serves them at `https://<host>.<tailnet>.ts.net`.)

Then read the one-time setup code the receiver printed:

```bash
kubectl -n ai-guard logs deploy/ai-guard | grep setup_code
```

Open the portal, enter the code, create the admin account, and the first-run
wizard takes it from there: the public receiver URL (with a probe that warns
about names other machines cannot resolve - on Tailscale it must be the full
`.ts.net` address, not the short ingress name), the log store (self-hosted or
Grafana Cloud, with connection tests both ways), corporate domains, a
governance baseline, the extension ID, and pre-configured deployment
downloads for every surface. Nothing after `helm install` touches a values
file, and everything the wizard sets is editable later under Settings.

## Making the hostnames resolve

The chart creates the routing rules inside the cluster; it cannot make
`ai-guard.example.com` resolve from the internet. That part is DNS you own:

1. Your ingress controller sits behind one entry point - a load balancer IP,
   or a hostname on a cloud provider. `kubectl get ingress -n ai-guard`
   shows it under ADDRESS once the chart is installed.
2. Point both names at it: an A record to the IP, or an ALIAS/CNAME to the
   hostname (in Route 53, an alias to the ELB). Both hosts go to the same
   place - the ingress controller routes by the Host header, which is how
   two names share one entry point. A wildcard record (`*.example.com`) does
   the same job once for every service you will ever add.
3. TLS comes after DNS, not before: cert-manager with Let's Encrypt can only
   issue a certificate for a name that already resolves. Set
   `ingress.tls.secretName` to what it issues.

Teams that automate step 2 run external-dns, which watches Ingress resources
and writes the records itself.

Two audiences, one nuance: the receiver's name must resolve from **every
machine that reports** - a laptop on hotel wifi included - so it needs real
public DNS. The portal's name only has to resolve for the people who open
it, so internal DNS or VPN-only is a legitimate choice there.

The Tailscale route above skips all of this: the operator registers the
names in your tailnet's own DNS and issues the certificates itself, with
nothing exposed publicly. The wizard's probe button is the check either
way - it tells you when a saved name does not resolve or the certificate
does not match.

## The short way: classic mode

The file-and-environment deployment, for teams that want configuration in a
repo rather than a portal: no server-side state, governance and the registry
as reviewable files, basic auth (or your ingress's SSO). Set
`managed.enabled=false` and configure by values, as it always worked:

```bash
helm install ai-guard oci://ghcr.io/amansk5/shadow-ai-guard/charts/ai-guard \
  --namespace ai-guard --create-namespace \
  --set managed.enabled=false \
  --set loki.pushUrl=http://loki.monitoring.svc.cluster.local:3100/loki/api/v1/push \
  --set portal.lokiUrl=http://loki.monitoring.svc.cluster.local:3100 \
  --set ingress.enabled=true \
  --set ingress.host=ai-guard.example.com
```

(A checked-out repo installs the same chart from `charts/ai-guard` instead of
the OCI reference.)

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
ghcr.io/amansk5/shadow-ai-guard/receiver:0.21.2
```

Built for `linux/amd64` and `linux/arm64` under one tag, so it resolves on
Graviton, Apple Silicon and a Pi without anything extra:

```bash
docker buildx imagetools inspect ghcr.io/amansk5/shadow-ai-guard/receiver:0.21.2
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
browser extension. (With `managed.enabled`, each of those can carry an
enrollment token instead and hold a credential of its own - see below.)

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
- `CORP_DOMAINS` (chart value `corpDomains`) - corporate domains, served to
  the endpoint collectors inside `/registry/collector`. Collectors prefer
  this list to their locally configured one, so a change here reaches the
  fleet on its next check-in with no MDM re-push per platform.
- `managed.enabled` - device enrollment, per-device credentials and
  revocation, backed by SQLite on a PVC. The portal gets a real login in
  this mode: on first boot the receiver prints a one-time setup code to its
  log (`kubectl logs deploy/<release>-ai-guard | grep setup_code` - NOTES
  prints the exact command), and the portal's first screen turns it into
  the admin account. From there the Managed section shows the fleet, mints
  and revokes enrollment tokens, and downloads pre-configured collector
  scripts from the Setup view. No admin secret is provisioned by default;
  set `managed.adminToken.value` if you use viewer accounts or the weekly
  digest (the portal reads with it server-side), if automation drives the `/admin` API
  with curl, or as break-glass when the portal password is lost. Enrollment
  tokens go wherever the shared token goes today - collector parameters,
  the extension's managed policy, the scanner Secret - one surface at a
  time; each enrolls and holds its own credential. Once every surface has,
  `managed.requireDeviceCredentials: true` turns the shared token off for
  ingest. See the receiver and portal READMEs for the details.

Confirm it is up:

```bash
curl -s https://your-receiver-host/healthz
```

And that it serves the registry:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  https://your-receiver-host/registry/collector | head
```

## The portal

Enabled by default and deployed alongside the receiver. It reads findings back
out of the log store, so it needs to be told where that is:

    --set portal.lokiUrl=http://loki.monitoring.svc.cluster.local:3100

That is the BASE url, not the push endpoint: the portal appends its own query
path, while `loki.pushUrl` is POSTed to verbatim by the receiver. Two values,
same host, and getting them crossed produces a receiver that stores findings
and a portal that finds none.

### A log store that needs credentials

Grafana Cloud and most hosted Loki want basic auth, and **both containers need
it**: the receiver to write, the portal to read.

    kubectl create secret generic my-loki-creds \
      --from-literal=lokiPassword='<token>'

    --set loki.username=123456 \
    --set loki.existingSecret=my-loki-creds

The username is a value; the password comes from a Secret, because a password
passed as a value ends up in `helm get values` and in whatever holds your
values file.

Setting them for one container and not the other produces a deployment where
findings are stored and cannot be read back, and neither container reports an
error you would attribute to the right cause. On Grafana Cloud the username is
a numeric instance id rather than an email, and the access policy needs both
`logs:write` and `logs:read`: a read-only token produces a 401 the receiver
counts, logs, and answers to the collector as a 503 - so findings retry
and are not stored. `aiguard_loki_push_total` staying at zero while findings
arrive is that failure.

### Authentication

The portal names who runs what on which machine, so it refuses to start
without credentials. What those are depends on the mode.

**Managed mode** replaces all of this with a real login: the admin account
created from the boot-printed setup code (see the short way above). No portal
password Secret exists, and `portal.auth.*` is moot unless set to `none`.

**Classic mode** is basic auth. The chart generates a password on first
install and keeps it across upgrades:

    kubectl -n "$NS" get secret ai-guard-portal \
      -o jsonpath='{.data.password}' | base64 -d; echo

Either way, if your ingress can do OIDC or mTLS, do it there and set
`portal.auth.mode=none` behind it - one shared credential with no per-user
trail is a floor, not a ceiling.

Managed mode can also federate sign-in to **Microsoft Entra**, configured
from the portal rather than from values: there is nothing to set here, and
the wizard checks each step against the tenant as you go. Once an owner has
signed in that way you can require it, which puts your conditional access
in front of the portal. The account the setup code created keeps its
password as the break-glass path, so make sure that password is stored
somewhere reachable without this portal before you turn enforcement on.

### Outbound mail

Optional, and worth setting here rather than in the portal when the relay
credential is already a Secret in this cluster - which it usually is,
because whatever else you run that sends mail is reading one already:

    --set managed.smtp.host=postfix.mail.svc.cluster.local \
      --set managed.smtp.port=25 \
      --set managed.smtp.security=none \
      --set managed.smtp.from=ai-guard@example.com

An in-cluster relay normally wants exactly that shape: no username, no
password, security `none`, because it decides what to accept by the sending
pod rather than by a credential. For a relay that does want one, point at
the Secret you already have rather than pasting the password anywhere:

    --set managed.smtp.password.existingSecret=mail-credentials \
      --set managed.smtp.password.key=password

Every field is also settable from the portal, and a value saved there wins -
the same precedence every other setting in this chart follows. It is used to
tell somebody an account has been made for them, and nothing else; with none
of it set, accounts are created exactly as before.

### Governance and identity

Both optional, both ConfigMaps:

    --set portal.governance.existingConfigMap=ai-guard-governance
    --set portal.identityMap.existingConfigMap=ai-guard-identity

The first records approvals, owners and review dates
([governance](../governance.md)). The second maps device keys to people, so
reports carry a name rather than a serial. Without either, the register falls
back to the registry's own `approved` flag and devices show as serials.

## When findings stop arriving

With a push target configured, a failed push is a 503 and collectors
retry; the failure is also visible where the receiver writes to the log
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

For failures outside the log pipeline, including chart installs that stop on
existing resources, `ImagePullBackOff`, and sources the portal lists as silent
while they are sending, see [Troubleshooting](../../TROUBLESHOOTING.md).

## Then

[Getting started](../getting-started.md) picks up here: rolling out a
collector, seeing the first finding, the dashboard, and the portal.