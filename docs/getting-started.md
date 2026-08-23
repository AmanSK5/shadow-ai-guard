# Getting started

From a running receiver to your first finding on a dashboard. Once that thread
works end to end, adding the other surfaces is repetition rather than new
concepts.

If you just want to see what any of this looks like without deploying
anything, skip to the demo at the end.

## What you are building

```
one collector ──► receiver ──► logs (Loki) ──► Grafana dashboard
                     │                            or the portal
              registry (served to the collector at runtime)
```

Everything else in the project is more sources feeding the same receiver. Get
one source working first.

## Prerequisites

- **A running receiver.** Two routes, both producing the same thing:
  [Docker Compose](../deploy/compose/README.md) on a host, or
  [Kubernetes](deployment/kubernetes.md). See
  [the routes](deployment/README.md) if you are not sure which.
- **A log pipeline that ingests container stdout.** The dashboard assumes
  Loki, but the receiver's only output is JSON lines, so anything that scrapes
  stdout works.
- **Grafana**, to import the dashboard. Optional if you only want the portal.
- **One macOS, Windows or Linux machine** you can run a script on as
  root or admin, to be your first endpoint.

You do not need Alertmanager, the cloud scanners or the browser extension to
get started. Add those once the basic thread works.

You also need the **bearer token** your receiver was deployed with. Every
source authenticates with it. The route you followed says where to find it.

**Managed mode shortcut (the default deployment):** the
portal's first-run wizard replaces most of this page - it configures the log
store and corporate domains centrally, and its deployment downloads are the
collector scripts below with the receiver URL and a fresh enrollment token
already baked in, so there is no token to find and nothing to edit. Download,
run as root/admin (or push through your MDM), and skip to step 2.

## 1. Roll out one collector

Pick the OS of your test machine and follow its README:

- macOS: [`endpoint/macos/README.md`](../endpoint/macos/README.md) (Jamf, or
  run the script directly)
- Windows: [`endpoint/windows/README.md`](../endpoint/windows/README.md)
  (Intune)
- Linux: [`endpoint/linux/README.md`](../endpoint/linux/README.md) (any RMM,
  cron, or config management)

Each needs the same three values:

- the receiver base URL
- the bearer token
- your corporate domains, comma separated. Accounts on these are "work";
  everything else is a personal-account finding.

**How you pass them differs per platform**, because each matches its delivery
mechanism, and this is the thing most likely to stop a first run:

- **macOS** takes them as positional parameters, because that is how Jamf
  passes script parameters. Environment variables are ignored. Running it by
  hand means passing three empty strings first, since `$1`-`$3` are Jamf's own:

      sudo ./ai-guard-collector.sh "" "" "" \
        https://receiver.example.com <token> example.com

- **Linux** takes environment variables: `AIGUARD_RECEIVER_BASE`,
  `AIGUARD_TOKEN`, `AIGUARD_CORP_DOMAINS`.
- **Windows** takes them at the top of the script or as Intune script
  parameters.

You can run any of them directly as root or admin with no MDM at all, which is
the fastest way to see a finding.

Run it once. The collector reads the AI tool config files in the user's home
directory and POSTs findings to the receiver.

## 2. See the finding

Check the receiver's logs. Every finding it accepts is a JSON line on stdout,
whether or not it also pushes to a log store:

```bash
# Docker Compose
docker compose logs receiver --since 5m

# Kubernetes
kubectl -n ai-guard logs deploy/ai-guard-receiver --since=5m
```

You should see a line carrying the tool, surface, account domain, device and
user. That is the whole pipeline working: a config file on a machine became a
structured finding in your log store.

**If the collector reported success and you see nothing**, the collector never
reached the receiver: check the URL and token it was given. **If you see the
finding here but not in Grafana or the portal**, the push to the log store is
failing rather than the collector - look for `"kind": "error"` in the same
logs, which names the URL and the likely cause.

Nothing there? [Troubleshooting](../TROUBLESHOOTING.md) covers the usual
reasons: a collector that printed nothing because the throttle suppressed a
repeat, a receiver that accepted the finding but could not write it to Loki,
and the parameters the macOS and Windows collectors need when you run them by
hand rather than through Jamf or Intune.

## 3. Import the dashboard

In Grafana, import `dashboards/ai-guard.json`. Set the datasource variables to
your Loki (and Prometheus, if used), and set the corporate domains variable to
your domains.

The finding from step 2 should appear in the "who is running what" table,
coloured by whether the account is personal or work.

## 4. Optional: the portal

Grafana answers how much and when. The portal answers what belongs to what:
which tools a device has, which devices a person uses, and which of your
sources are reporting versus silent. It reads the same logs, writes nothing,
and is not in the ingest path, so it can be added or removed without touching
anything above.

On the compose route it is already there, on port 8091. Otherwise:

```bash
docker run --rm -p 8091:8091 \
  -e LOKI_URL=http://your-loki:3100 \
  -e PORTAL_USER=admin -e PORTAL_PASSWORD=... \
  ghcr.io/amansk5/shadow-ai-guard/portal:0.9.8
```

It refuses to start without authentication, because it names who runs what on
which machine.

It opens on a setup view showing which sources are reporting and what each
silent one needs, derived from findings rather than from configuration being
present. Straight after step 2 that view is mostly empty, which is the honest
picture rather than a broken one: one collector reporting and everything else
not yet configured.

[`portal/README.md`](../portal/README.md) covers attaching people to devices,
embedding Grafana panels, and why basic auth is a floor rather than a ceiling.

## Where to go next

- Add the other two collectors by repeating step 1.
- Add cloud and network detection:
  [`scanner/README.md`](../scanner/README.md) covers the Entra, Exchange,
  Intune, Jamf and SentinelOne scanners, each optional.
- Add the browser surface:
  [`extension/README.md`](../extension/README.md) covers packing, hosting and
  MDM deployment, including the paste guard.
- Turn on alerting: set `ALERTMANAGER_URL` on the receiver so personal-account
  findings page you.
- Understand the design before extending it:
  [`docs/architecture.md`](architecture.md).
- Before deploying for real, read
  [`docs/deployment-privacy.md`](deployment-privacy.md). This is workplace
  monitoring and usually warrants a DPIA.

## Just want to see it?

The demo in [`demo/`](../demo/README.md) needs no cluster, no real data and no
credentials. `docker compose up` brings up the receiver, Loki, Grafana, the
portal and a seeder, with both populated in a few minutes. Grafana is on 3000
and the portal on 8091.