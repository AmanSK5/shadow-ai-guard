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

      pipx install -q "git+https://github.com/AmanSK5/shadow-ai-guard@v0.34.0#subdirectory=cli"

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
   if there is one - into `nyxus-carried-auth` and `nyxus-carried-admin`.
   Uninstalling a release removes its Secrets; these copies belong to neither
   release.
3. Sign in to the registry with the key, and create the pull secret
   `nyxus-registry` in the namespace.
4. Scale Shadow AI Guard's Deployments to zero and wait for its pods to stop.
5. Uninstall the release. Its storage claim stays: the chart marks it to be
   kept.
6. Install Nyxus with this release's own values, pointed at that storage
   claim and the carried Secrets, pulling with `nyxus-registry`.

`--nyxus-release` names the new release, `nyxus` by default. `--context` and
`--namespace` pick the cluster and release, as for an upgrade.

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

## If it stops part way

Nothing after a failed step runs, and the terminal says which step and where
the backup is.

- **Before Shadow AI Guard stopped**, nothing has changed except files the
  command wrote: carried Secrets and the pull secret on Kubernetes, the new
  project directory on Compose. Run it again once the cause is fixed.
- **After Nyxus started**, to go back: stop Nyxus, copy the backup over
  `state.db` on the same volume and remove `state.db-wal` and `state.db-shm`
  beside it, then start Shadow AI Guard again - on Kubernetes by installing
  its chart with `managed.persistence.existingClaim` and the carried Secrets
  as `auth.existingSecret` and `managed.adminToken.existingSecret`, on
  Compose from its own directory.

## What it will not do

Put the key on a command line or print it. Touch anything outside the release
or the compose project it detected. Overwrite a file beside Nyxus's compose
file. Remove the storage or the database. Move a deployment whose key is not
the one stored in it, or is not active. Change your MDM.
