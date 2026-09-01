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
works: an ingress controller, Tailscale, a reverse proxy. With an ingress
controller, both names need a DNS record pointing at its load balancer -
[the deployment docs](deployment/kubernetes.md) walk that through; Tailscale
handles names and certificates itself.

**Docker Compose:**

```bash
git clone https://github.com/AmanSK5/shadow-ai-guard.git
cd shadow-ai-guard/deploy/compose
docker compose up -d
```

Both routes need a log store for findings. If you already run Loki, you will
connect it in step 3 and nothing needs configuring up front. If you don't, the
compose file includes one.

## 2. Create the owner account

The receiver prints a one-time setup code when it starts with no account:

```bash
# Kubernetes
kubectl logs deploy/ai-guard -n ai-guard | grep -i setup

# Compose
docker compose logs receiver | grep -i setup
```

On Windows, swap `grep -i` for `findstr /i` - it is built into both
PowerShell and cmd.

Open the portal, enter the code, pick a username and password. The code works
exactly once and only for creating the first account, and that account is the
deployment's **owner** - the role that cannot be locked out, because an admin
cannot create another one. Every account after it is added from inside the
portal.

This account is also the deployment's break-glass one. If you later require
single sign-on, every other account has to come through the identity
provider and this one keeps its password, so it is what gets you back in
when Entra is unreachable. Store that password where you can reach it
without this portal.

## 3. Follow the wizard

The portal opens on a first-run wizard: seven steps, one screen at a time,
with a rail down the side marking each one required, recommended or
optional. Only two are required - the receiver URL and corporate domains -
because a deployment missing either runs wrong rather than not running. Once
both are in it will tell you the deployment can go out. You can leave at any
point and pick it up again under Settings > Getting started.

Finishing or skipping only stops the wizard opening; it does not mean the
deployment is configured. The bell in the header keeps a live list of what
is still outstanding and what each gap makes the platform get wrong, so
skipping the required steps is visible rather than silent.

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
- **The collector reported a POST failure** - the receiver refused the
  finding because it couldn't deliver it to the log store (the collector
  keeps it and retries). Check the receiver's logs for lines with
  `"kind": "error"`; they name the URL it tried and the likely fix. The
  Diagnostics view in the portal shows the same thing.
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
- **More eyes**: add accounts under Settings > Account. The setup code made
  you the owner; from there you can add admins, who run the platform, and
  viewers, who read every page and can change nothing - the right shape for
  an auditor or an exec. Nobody can act on an account that outranks them or
  grant a role above their own, and the last owner cannot be removed. Every
  change anyone makes lands in the audit trail under Diagnostics.
- **Telling people about it**: with a mail relay configured, creating an
  account emails the person to say it exists. Settings > Account has a
  wizard for the relay that knows the common providers and fills in the
  host, port and encryption for the one you pick, plus a test send that
  reports what the relay actually said. Configure it whenever - one button
  sends the invites that were missed before you got round to it. Nothing
  about account creation depends on it working.
- **Single sign-on** (beta): the same tab federates sign-in to Microsoft
  Entra, in six steps that each check something against the provider rather
  than trusting what was typed. It authenticates rather than provisions -
  create the account first with the person's work address, and their first
  Entra sign-in binds it to that identity for good. It has been run end to
  end against one real app registration, which is not the same as proven,
  so pilot it on one account before moving anybody across.

  Once an owner has signed in that way, you can **require** it, which puts
  your tenant's MFA and conditional access in front of the portal. One
  account stays exempt: the one the setup code created, which keeps its
  password as the way back in if the identity provider is unreachable. Put
  that password somewhere you can reach without this portal. You can also
  set how recently somebody must have signed in at Entra before the portal
  accepts it - twelve hours by default, and checked rather than merely
  asked for, so a browser already signed into the tenant does not let
  whoever is sitting at it straight in.
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
