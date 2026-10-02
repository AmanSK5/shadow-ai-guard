# Moving a deployment to Nyxus

Nyxus is the commercial edition of this system: the same collectors and the
same evidence, from private images under a subscription with support. A
Shadow AI Guard deployment moves to it in place, with one command, and keeps
what it has.

## What moves, and what it keeps

Nyxus opens this receiver's own database, so the move keeps the file rather
than exporting and importing it:

- **Accounts and sign-in.** People sign in with the passwords they have, and
  anyone signed in stays signed in. Owners stay owners.
- **Enrolled devices.** Each machine keeps its identity, and an enrollment
  token not yet used still enrolls.
- **What you decided.** Governance decisions, the identity map, budget
  subscriptions, your additions to the registry, candidates, finding
  statuses, settings and preferences.
- **The activation key**, which Nyxus checks again for itself.
- **Findings already in your log store.** Nyxus reads the ones Shadow AI
  Guard stored for as far back as its reporting window reaches, and no
  further: they are not copied or rewritten.

The database is backed up beside itself before anything stops.

## Before you start

- The deployment runs in managed mode (the default).
- An owner has stored the activation key on System health, and it shows as
  activated.
- You have the Nyxus release to install. It comes with your subscription.
- You have `aiguardctl` from this release, with your own `helm` and `kubectl`,
  or `docker`, on your PATH:

      pipx install --force -q "git+https://github.com/AmanSK5/shadow-ai-guard@v0.37.0#subdirectory=cli"

Move the receiver and portal first. The endpoints follow, below.

## Run it

Put the key in your shell. The command reads it from `NYXUS_KEY` (or a file
named with `--key-file`) and never from its own arguments, because a command
line is visible to every user on the machine:

    export NYXUS_KEY='<your activation key>'

See the plan. Nothing runs and nothing is approved:

    aiguardctl upgrade --edition nyxus --portal https://ai-guard-portal.example.com \
      --nyxus-version <version> --dry-run

Then run it. An owner approves in the portal, as for an upgrade, and the
command checks the key in your shell is the one stored in the deployment
before it changes anything:

    aiguardctl upgrade --edition nyxus --portal https://ai-guard-portal.example.com \
      --nyxus-version <version>

It waits for the portal to answer as Nyxus and records the outcome, which
System health shows once Nyxus is running.

### On Kubernetes, with Helm

In order:

1. Back up the receiver database, as `state.db.before-nyxus-<time>` on the
   same volume.
2. Copy the Secrets the release made - the shared token, and the admin token
   and portal password if there are any - into `nyxus-carried-auth`,
   `nyxus-carried-admin` and `nyxus-carried-portal`. Uninstalling a release
   removes its Secrets; these copies belong to neither release.
3. Sign in to the registry with the key, and create the pull secret
   `nyxus-registry` in the namespace.
4. Scale every Deployment the release made - the receiver and the portal - to
   zero, and wait for their pods to stop. A finished scanner or discovery Job
   is not waited on; it goes with the release.
5. Write Nyxus's values: this release's own, pointed at that storage claim and
   the carried Secrets, pulling with `nyxus-registry`.
6. Uninstall the release, and wait until what it made is gone. Its storage
   claim stays: the chart marks it to be kept.
7. Install Nyxus with those values.

If the release made a Deployment the command cannot find running this
project's images, it stops before changing anything and names it.

`--nyxus-release` names the new release, `nyxus` by default. `--context` and
`--namespace` pick the cluster and release, as for an upgrade.

### With the Tailscale operator

When the release's Ingresses use the `tailscale` class, the plan says so and
names the machines they are on the tailnet. Removing the release asks the
operator to delete those machines, and Nyxus's Ingresses ask for the same
names, so the old machines have to be gone before Nyxus starts: while one
exists, Nyxus's is registered as `<name>-1` and its address changes.

The operator can only delete a machine if its OAuth client is allowed to
delete devices. When it is not, the operator holds the Ingress with its
finalizer, `tailscale.com/finalizer`, and removal cannot finish. The command
gives it a minute, then:

1. names the machines to delete in the Tailscale admin console, under
   Machines, and asks whether you have deleted them;
2. once you answer yes, removes that finalizer - only that one, and only from
   this release's Ingresses - and carries on.

With `--yes`, or with no terminal to ask in, it stops there instead and prints
the machines, the `kubectl patch` commands that release the Ingresses, and the
command that finishes the move (below).

Once Nyxus is installed the command reads its Ingresses back. If a machine
still came up as `<name>-1`, it says so: delete the old machine in the admin
console, then rename the new one (Edit machine name). A new machine can take a
minute or two to resolve on the computer running the command, so the wait for
the portal can take that much longer.

Afterwards, allow the operator's OAuth client to delete devices, or removing
any Tailscale Ingress in that cluster will stall the same way.

### On Docker Compose

Put the compose file that comes with your subscription in a directory of its
own, and name it with `--nyxus-compose-file`. The command writes into that
directory and refuses to start if anything it would write is already there.
In order:

1. Prepare Nyxus's project: copy `secrets/auth_token` and
   `secrets/portal_password` with the same group and mode the running
   deployment uses, make `secrets/portal_token` and
   `secrets/report_signing_key`, and write `.env`, `scanner.env` and
   `discovery.env` from yours, with `AIGUARD_` names renamed to `NYXUS_`.
2. Sign in to the registry with the key, and pull Nyxus's images.
3. Back up the receiver database.
4. Stop Shadow AI Guard's services. Loki, Grafana and anything else in the
   project keep running.
5. Start Nyxus's services under the same project name, so its volumes are the
   same volumes and its network the same network.

For an air-gapped host, load Nyxus's images first (`docker load`) and add
`--no-pull`: the command then neither signs in to the registry nor pulls.

### On Kubernetes, without Helm

Not automated. By hand, the same steps: back up the database, copy the shared
token and admin token Secrets, create the pull secret, stop Shadow AI Guard,
and run Nyxus's receiver and portal on the same storage and Secrets, with the
portal's `SHADOW_AI_GUARD_FINDINGS_BEFORE` set to the moment Shadow AI Guard
stopped.

## Then the endpoints

Replace the collector script in each MDM policy, RMM job or Intune script
with Nyxus's, in the same policy. Adding a second policy leaves both
collectors reporting. On its first run each Nyxus collector takes over the
credential and the record of what it has reported that Shadow AI Guard's
left on the machine, so nothing enrolls again and an unchanged machine is not
reported afresh.

The browser extension is a different extension. Deploy Nyxus's by policy and
remove Shadow AI Guard's; each browser profile enrolls again on its own.

## After the move

### First, what the move could not see

Helm moves what it owns. Anything set up around the release by hand is
invisible to it, so the move cannot have touched it:

- collector CronJobs applied outside the chart, still on Shadow AI Guard's
  image and its `AIGUARD_` environment;
- credentials in your own Secret, under names Nyxus's collectors do not read
  — the scanner reads Entra, Jamf and SentinelOne credentials by a `NYXUS_`
  prefix now, and nothing rewrites the keys inside a Secret you made. This
  one is quiet: the collector runs, finds nothing, and reports nothing;
- an Ingress made by hand naming the release's Service, which the uninstall
  took with it. Requests to it are refused before they reach anything.

From Nyxus 0.5.0, `nyxusctl move` reads the cluster and says which of these
are present, and `nyxusctl move --apply` puts right what it can in place:
it repoints the Ingress, adds each credential under the name the collector
reads while keeping the old name, and offers to hand hand-maintained
CronJobs to the chart so they stop drifting. It changes nothing until you
ask it to.

On Docker Compose none of this applies: the move writes `scanner.env` and
`discovery.env` itself, with the names already renamed.

### Then, what is outside the deployment

Nyxus keeps the addresses this deployment is reached on, so collectors, the
extension and people signing in carry on as they were. What the move cannot
change is outside the deployment, and the first time an owner or admin signs
in to Nyxus it opens on **Finish moving to Nyxus**, which lists it with this
deployment's own values:

- **Its names.** To serve Nyxus under new names, change the DNS record
  (Route 53, Cloudflare or your own DNS), the certificate and the ingress host
  or reverse proxy first, then the portal address and the single sign-on
  redirect URI, and the receiver last, together with the collectors: its
  address is built into every collector download.
- **Anything set up by hand around this release.** On Kubernetes the
  Services and Ingresses take the Nyxus release's name (`nyxus` and
  `nyxus-portal` by default, where they were `ai-guard` and `ai-guard-portal`).
  The chart's own Ingresses move with their hosts; anything else that names
  the old Services needs the new names.
- **Monitoring.** The receiver's metrics are `nyxus_*` where they were
  `aiguard_*`, and findings carry `app="nyxus-receiver"` where they carried
  `app="ai-guard-receiver"`, so alert rules and dashboards written for these
  names stop matching.
- **The command line.** `aiguardctl` becomes `nyxusctl`.

The page stays under Settings › Getting started in Nyxus.

## If it stops part way

Nothing after a failed step runs, and the terminal says which step and where
the backup is.

- **Before Shadow AI Guard stopped**, nothing has changed except files the
  command wrote: carried Secrets and the pull secret on Kubernetes, the new
  project directory on Compose. Run it again once the cause is fixed.
- **After Shadow AI Guard's release was removed, before Nyxus was running**
  (Helm), the terminal prints the command that finishes the move - a
  `helm upgrade --install` of Nyxus with the values file the move wrote - and
  keeps that file for it. Run that command once the cause is dealt with, then
  delete the directory it names: the file holds the release's settings.
- **After Nyxus started**, to go back: stop Nyxus, copy the backup over
  `state.db` on the same volume and remove `state.db-wal` and `state.db-shm`
  beside it, then start Shadow AI Guard again - on Kubernetes by installing
  its chart with `managed.persistence.existingClaim` and the carried Secrets
  as `auth.existingSecret` and `managed.adminToken.existingSecret`, on
  Compose from its own directory.

## What it will not do

Put the key on a command line or print it. Touch anything outside the release
or the compose project it detected. Remove a finalizer you have not confirmed,
or any finalizer but the Tailscale operator's. Overwrite a file beside Nyxus's
compose file. Remove the storage or the database. Move a deployment whose key
is not the one stored in it, or is not active. Change your MDM.
