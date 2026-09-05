# aiguardctl

Upgrade a Shadow AI Guard deployment from your own machine, with your own
credentials, while the portal shows the progress.

The portal tells you a newer release exists. It never applies one: nothing in
the cluster or on the compose host holds a right it did not have, and the
portal has no code path that runs `helm`, `kubectl` or `docker`. This command
does, on your machine, with the kubeconfig context or Docker context you
already use to administer the deployment. The platform's part is to check
that an owner asked for the upgrade, to describe what is running, and to
hold the progress so System health can show it live - including while the
portal itself restarts. The design and its threat model are in
[SECURITY.md](../SECURITY.md), under *Upgrading*.

## Install

From a tagged release of this repository, once:

    pipx install "git+https://github.com/AmanSK5/shadow-ai-guard@v0.29.0#subdirectory=cli"

No third-party dependencies, so what runs is what the tag contains. It
shells out to your own `helm`, `kubectl` and `docker`, found on your PATH.

## Upgrade

    aiguardctl upgrade --portal https://ai-guard-portal.example.com

1. It reads what is deployed with your tools: the chart's Deployments and any
   CronJobs running this project's scanner or discovery images on
   Kubernetes, or the compose services running this project's images.
2. Your browser opens the portal's approval page. Sign in as you always do -
   password, or Microsoft Entra with your tenant's MFA. An **owner** compares
   the code on the page with the one in your terminal and approves. The
   command never sees a password and never learns which sign-in you use.
3. It shows the plan - every object it will touch and every command it will
   run - and waits for `y`.
4. It runs them: `helm upgrade --reuse-values` on a Helm release, image bumps
   on a bare Kubernetes install, `pull` and `up -d` for the named services on
   compose. Each step is reported to the portal; command output stays in
   your terminal.
5. It waits for the portal to answer as the new version, checks the receiver
   did too and that detection sources are reporting, and records the
   outcome.

Options: `--dry-run` prints the plan and runs and approves nothing;
`--yes` skips the confirmation for automation; `--context` and
`--namespace` pick a cluster and a release when you have more than one;
`--version` targets a release other than the latest; `--kubernetes` or
`--compose` stops it looking at the other.

## What it will not do

Touch an object without the chart's labels or this project's image. Run a
command it did not show you. Send command output to the portal. Keep the
token: it lives in memory for one run and is retired when the run finishes.
Upgrade a compose project whose images were built locally rather than
pulled from the registry - it says so and stops.
