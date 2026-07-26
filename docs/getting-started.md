# Getting started

This guide takes you from a clone to your first finding on a dashboard. It
deploys the minimum viable platform: the receiver, plus one endpoint
collector. Once that thread works end to end, adding the other surfaces is
repetition rather than new concepts.

If you just want to see what the dashboard looks like without deploying
anything, skip to the demo at the end.

## What you are building

```
one collector ──► receiver ──► logs (Loki) ──► Grafana dashboard
                     │
              registry (served to the collector at runtime)
```

Everything else in the project is more sources feeding the same receiver.
Get one source working first.

## Prerequisites

- A Kubernetes cluster you can deploy to. Anything conformant works; nothing
  in the core is cloud specific.
- A log pipeline that ingests container stdout. The provided dashboard
  assumes Loki, but the receiver's only output is JSON lines, so any pipeline
  that scrapes stdout works.
- Grafana, to import the dashboard.
- One macOS, Windows, or Linux machine you can run a script on as
  root/admin, to be your first endpoint.

You do not need Alertmanager, the cloud scanners, or the browser extension
to get started. Add those once the basic thread works. When you do add the
browser surface, [../extension/README.md](../extension/README.md) covers
packing, hosting and MDM deployment, including the paste guard.

## 1. Deploy the receiver

The receiver is a single container. Prebuilt images are published to GHCR by
CI, so you do not need to build anything:

```
ghcr.io/amansk5/shadow-ai-guard/receiver:latest
```

Create its bearer token as a Kubernetes Secret. Every source authenticates
to the receiver with this one token:

```bash
kubectl create secret generic ai-guard-receiver \
  --from-literal=authToken="$(openssl rand -hex 32)"
```

Deploy the receiver with that Secret mounted as the `AUTH_TOKEN` environment
variable, and expose it on an ingress your endpoints can reach. The receiver
listens on port 8080 and needs, at minimum:

- `AUTH_TOKEN` from the Secret above
- the registry ConfigMap mounted at `/etc/ai-guard` (next step)

If you deploy before the ConfigMap from step 2 exists, the pod sits in
ContainerCreating with a FailedMount event. That is normal: create the
ConfigMap and the kubelet mounts it within a minute, no restart needed.

Optional environment variables, all off by default:
- `ALERTMANAGER_URL`, set to enable alerting; unset means findings are
  logged and dashboarded but nothing pages
- `DISPLAY_TZ`, timezone for the human-readable timestamp on alerts
  (default UTC)

Confirm it is up:

```bash
curl -s https://your-receiver-host/healthz
# {"ok": true, "version": "..."}
```

## 2. Publish the registry

The registry is the list of AI tools to detect. Collectors fetch it from the
receiver at runtime, so it lives in a ConfigMap the receiver serves.

`build.py` needs `pyyaml` and `jsonschema`. On current Homebrew or Debian
Python (PEP 668), install them in a venv:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install pyyaml jsonschema
python registry/build.py
kubectl create configmap ai-guard-registry \
  --from-file=registry.json=registry/dist/registry.json \
  --from-file=collector.json=registry/dist/collector.json
```

The receiver reads the registry per request, and the kubelet syncs ConfigMap
changes into the pod, so updating the registry later is a rebuild and a
`kubectl apply` with no receiver restart.

Confirm the receiver serves it:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  https://your-receiver-host/registry/collector | head
```

## 3. Roll out one collector

Pick the OS of your test machine and follow its collector README:

- macOS: `endpoint/macos/README.md` (Jamf, or run the script directly)
- Windows: `endpoint/windows/README.md` (Intune)
- Linux: `endpoint/linux/README.md` (any RMM, cron, or config management)

For a first test you can run the script directly on the machine as
root/admin, without any MDM, by setting the three configuration values (the
READMEs show how per platform):

- receiver base URL
- the bearer token from step 1
- your corporate domains, comma separated (accounts on these are "work";
  everything else is a personal-account finding)

Run it once. The collector reads the AI tool config files in the user's home
directory and POSTs findings to the receiver.

## 4. See the finding

Check the receiver logs:

```bash
kubectl logs deploy/ai-guard-receiver -c receiver --since=5m
```

You should see a JSON finding line with the tool, surface, account domain,
device, and user. That is the whole pipeline working: a config file on a
machine became a structured finding in your log store.

## 5. Import the dashboard

In Grafana, import `dashboards/ai-guard.json`. Set the datasource variables
to your Loki (and Prometheus, if used), and set the corporate domains
variable to your domains. The finding from step 4 should appear in the "who
is running what" table, coloured by whether the account is personal or work.

## Where to go next

- Add more collectors (the other two OSes) by repeating step 3.
- Add cloud and network detection: `scanner/README.md` covers the Entra,
  Exchange, Intune, Jamf, and SentinelOne scanners, each optional.
- Turn on alerting: set `ALERTMANAGER_URL` on the receiver so personal
  account findings page you.
- Understand the design before extending it: `docs/architecture.md`.
- Before deploying for real, read `docs/deployment-privacy.md`: this is
  workplace monitoring and usually warrants a DPIA.

## Just want to see the dashboard?

The demo in `demo/` needs no cluster and no real data: `docker compose up`
brings up the receiver, Loki, Grafana and a seeder, with the dashboard
populated in about five minutes. `demo/README.md` covers it, including the
paste guard demo page.
