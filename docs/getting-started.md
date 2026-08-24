# Getting started

This page takes you from nothing to your first finding in the portal. Once one
machine is reporting, every other surface is the same pattern: turn it on,
watch it show up.

If you just want to see what the project looks like before deploying anything,
run the [demo](../demo/README.md) instead: `docker compose up` in `demo/`, no
cluster, no credentials, fake data.

## The short version

1. Install the receiver and portal (one command).
2. Get the one-time setup code from the receiver's log and create your admin
   account.
3. Follow the first-run wizard in the portal.
4. Download a pre-configured collector from the wizard and run it on one
   machine.
5. Watch the finding appear.

That's the whole thing. The rest of this page is those five steps in detail.

## 1. Install

**Kubernetes:**

```bash
helm install ai-guard oci://ghcr.io/amansk5/shadow-ai-guard/charts/ai-guard \
  --namespace ai-guard --create-namespace \
  --set ingress.enabled=true --set ingress.host=ai-guard.your.domain \
  --set portal.ingress.enabled=true --set portal.ingress.host=ai-guard-portal.your.domain
```

The two hosts are the URLs your machines will reach the receiver on and you
will reach the portal on. Anything that gives those two services a hostname
works: an ingress controller, Tailscale, a reverse proxy.

**Docker Compose:**

```bash
git clone https://github.com/AmanSK5/shadow-ai-guard.git
cd shadow-ai-guard/deploy/compose
docker compose up -d
```

Both routes need a log store for findings. If you already run Loki, you will
connect it in step 3 and nothing needs configuring up front. If you don't, the
compose file includes one.

## 2. Create your admin account

The receiver prints a one-time setup code when it starts with no admin
account:

```bash
# Kubernetes
kubectl logs deploy/ai-guard -n ai-guard | grep -i setup

# Compose
docker compose logs receiver | grep -i setup
```

Open the portal, enter the code, pick a username and password. The code works
exactly once and only for creating the first account.

## 3. Follow the wizard

The portal opens on a first-run wizard. Work through it top to bottom:

1. **Public receiver URL** - the URL your laptops and servers can reach the
   receiver on from outside the cluster. This gets baked into every download,
   so the "save" button probes it and tells you if it's wrong.
2. **Log store** - where findings are stored and read from. For an in-cluster
   Loki this is one URL. For Grafana Cloud it's the URL, your numeric instance
   ID as the username, and an access token with logs read *and* write. There
   are test buttons for both directions; use them.
3. **Corporate domains** - your work email domains. An AI tool signed into one
   of these is a work account; anything else is flagged as personal.
4. **Governance baseline** - which tools your organisation has approved or
   banned. Only set the ones you have a position on; the rest stay undecided.
5. **Browser extension and paste guard** - fine to skip on a first pass. When
   you come back, the portal has a guided setup that walks the whole thing:
   pre-configured source download, packing, hosting, signing for Firefox, and
   the paste guard behaviour. Every value it saves is also editable flat
   under Settings.
6. **Alerting and Grafana** - optional, also fine to skip for now.
7. **Deployment downloads** - this is the step that matters today. Download
   the collector for whatever OS your test machine runs.

## 4. Run a collector on one machine

The download from step 7 is ready to run: the receiver URL and an enrollment
token are already inside it. Nothing to edit.

```bash
# macOS / Linux, on the test machine
sudo ./ai-guard-collector.sh
```

On Windows, run the `.ps1` as administrator.

The script reads the AI tool config files on that machine (which CLIs are
installed, which accounts they're signed into, which IDE extensions and MCP
servers exist) and reports what it finds. It also enrolls the machine, so it
shows up under Fleet in the portal with its own credential you can revoke.

For a real rollout you push the same file through your MDM or RMM - Jamf,
Intune, anything that can run a script as root/admin on a schedule. Each OS
README ([macOS](../endpoint/macos/README.md),
[Windows](../endpoint/windows/README.md),
[Linux](../endpoint/linux/README.md)) has the exact steps for that. Pilot on
one machine first.

## 5. See the finding

Open the portal. The overview should now show the tools found on your test
machine, and Setup shows the collector as reporting.

If nothing appears within a minute:

- **The collector printed an error about the receiver URL or token** - it
  never reached the receiver. Re-download the script (each download carries a
  fresh token) and check the URL is reachable from that machine.
- **The collector said it reported, but the portal is empty** - the receiver
  got the finding but couldn't push it to the log store. Check the receiver's
  logs for lines with `"kind": "error"`; they name the URL it tried and the
  likely fix. The Diagnostics view in the portal shows the same thing.
- Anything else: [Troubleshooting](../TROUBLESHOOTING.md).

## Where to go next

Everything below is optional and independent. Add them in any order.

- **More machines**: push the collector through your MDM/RMM.
- **The browser extension and paste guard**: shows which accounts are signed
  into AI sites, and warns or blocks when marked documents are pasted into
  them. The portal's guided setup covers packing and hosting; the deployment
  files come pre-configured. [extension/README.md](../extension/README.md)
  has the same material for reading offline.
- **Cloud and network scanners**: Entra sign-ins, OAuth grants, Exchange
  signup evidence, Intune/Jamf inventory, SentinelOne DNS.
  [scanner/README.md](../scanner/README.md). The portal generates the CronJob.
- **Discovery**: a scheduled job that spots AI domains in your fleet's DNS
  that the registry doesn't know yet, and queues them in the portal's review
  queue for you to define or dismiss. The portal generates this CronJob too.
- **More eyes**: add accounts under Settings. Admins run the platform;
  viewers read every page and can change nothing, which is the right shape
  for an auditor or an exec. Every change anyone makes lands in the audit
  trail under Diagnostics.
- **Notifications**: set a webhook URL in Settings and the receiver posts to
  Slack (or anything webhook-compatible) the moment discovery finds a new
  tool. The portal can also send a weekly digest of the estate; see the
  [portal README](../portal/README.md) for the one credential it needs.
- **Working the findings**: personal-account findings carry a lifecycle.
  Acknowledge one to mark it spoken-to, or accept it with a reason and it
  drops out of the open count. Who decided what, and when, is recorded.
- **Grafana**: import `dashboards/ai-guard.json` for trends and history. The
  portal can embed the panels, and they follow the portal's light or dark
  theme.
- **Alerting**: set the Alertmanager URL in Settings and personal-account
  findings will page you.

Before deploying to real users' machines, read
[deployment-privacy.md](deployment-privacy.md). This is workplace monitoring
in most jurisdictions and usually needs a DPIA.

## Running it classic (files instead of the portal)

If you'd rather manage everything as files and environment variables in your
own repo, with no server-side state, deploy with `managed.enabled=false` (or
the compose classic overlay). You then edit `governance.yaml` and
`registry/registry.yaml` by hand, set config through environment variables,
and pass the receiver URL and shared token to collectors yourself - each OS
README documents the values it needs. The
[deployment docs](deployment/README.md) compare the two modes.
