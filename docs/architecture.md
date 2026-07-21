# Architecture

This document is the mental model. Read it before extending the platform or
reviewing a change: it explains not just what the pieces are but why they are
shaped this way, which is the part that is hard to reconstruct from the code.

## The one idea

Every detection surface, however different its mechanism, produces the same
thing: a **finding**. A finding is a small JSON object saying "this AI tool,
on this surface, on this device, is signed into an account on this domain."
The receiver accepts findings and does not care where they came from. That
single shape is the contract the whole system is built around.

Because the finding is the contract, adding a new source (a new scanner, a
new OS collector, a new RMM) is never a change to the receiver or the
dashboard. It is a new thing that emits the finding shape. This is the
property that makes the platform extensible, and it is worth protecting: a
change that makes the receiver care about a specific source is a change
moving in the wrong direction.

## The finding schema

```json
{
  "tool": "claude-code",
  "surface": "cli",
  "os": "linux",
  "account_domain": "gmail.com",
  "device": "SERIAL123",
  "user": "jane.doe",
  "evidence": "~/.claude.json",
  "severity": "warn",
  "reported_at": "2026-01-01T09:00:00Z",
  "source": "collector-linux"
}
```

- **tool**, which AI tool, from the registry.
- **surface**, one of browser, cli, ide, desktop, network, cloud.
- **os**, macos, windows, linux, or unknown (cloud and network findings
  have no single device OS).
- **account_domain**, the domain of the signed-in account, never the
  mailbox local part. This is the whole point: the platform answers "is a
  managed device using an unmanaged account" with the minimum identifying
  data.
- **severity**, `warn` if the account domain is not one of the deployer's
  corporate domains, `info` otherwise. Personal accounts warn; work accounts
  are informational presence.
- **evidence**, where the finding came from, with a literal `~` for the
  user's home so a username never lands in the evidence string.
- **source**, which collector or scanner produced it, for provenance.

If you are writing a new source, emit exactly this. Everything downstream
already understands it.

## Components

**receiver**, a FastAPI service, the only component every finding passes
through. It authenticates the sender with a shared bearer token, writes each
finding as a structured JSON line to stdout (which the log pipeline scrapes),
optionally fires an Alertmanager alert for personal-account findings, and
serves the registry to collectors. It is deliberately thin: it does not
store findings itself, does not deduplicate at rest, and does not know about
any specific tool. State it does keep is in memory only (active-session and
device gauges), so a restart loses gauges but no findings, because findings
live in the log store.

**registry**, a YAML file, schema-validated, that is the source of truth
for what counts as an AI tool: domains, extension IDs, config file paths per
OS, account file locations, approval status. `build.py` compiles it into two
views: one for the receiver and one for collectors. Collectors fetch their
view from the receiver at runtime, which is why adding a tool is a registry
merge request rather than a script change pushed to every endpoint.

**collectors**, per-OS scripts (macOS/bash, Windows/PowerShell,
Linux/bash) delivered by whatever runs scripts as root on that fleet: Jamf,
Intune, an RMM, cron. They read AI tool config files in the user's home and
report which account each tool is signed into. This is the data no
API-level product has, because the account identity lives in a local file,
not in any cloud log.

**scanners**, cloud and network detection: Entra sign-ins, Exchange signup
evidence, Intune and Jamf software inventory, SentinelOne DNS telemetry.
Each is an independent module; a deployer runs the ones their estate
supports. They run as a scheduled job and post findings to the receiver like
any other source.

**discovery**, a scheduled job that classifies unrecognised AI-looking
domains from DNS telemetry and proposes registry additions for human review.
It never adds to the registry itself; a person approves every change.

**dashboard**, Grafana over the log store. It reads findings, not a
database, and computes personal-vs-work from the corporate domain variable
the deployer sets. Most panels count distinct devices or users, not events,
so they are stable across receiver restarts.

## Why these choices

**Why collectors fetch the registry at runtime.** The alternative is baking
tool identifiers into each collector, which means every new tool is a script
edit re-pushed through MDM to the whole fleet. Fetching at runtime makes a
new tool a one-line registry change that every collector picks up on its
next run. The registry is the thing that changes often; the collectors are
the thing that is painful to redeploy. Decoupling them puts the churn where
it is cheap.

**Why the receiver is the only thing touching Loki and Alertmanager.**
Sources should not need credentials for the log store or the alerting
system. They need one thing: the receiver's bearer token. Centralising the
outbound integrations in the receiver keeps the trust surface small and lets
a deployer swap Loki for another pipeline by changing one component.

**Why domain, never mailbox.** The question the platform answers is whether
a managed device uses a personal account, which the domain answers
completely. The local part (who specifically) adds identifying data without
adding signal for that question. Collecting less is both a privacy stance
and a smaller thing to secure.

**Why severity is computed from the corporate domain, not stored.** What
counts as a "work" account is the deployer's configuration, not a property
of the finding. The same finding is a warn at one org and info at another.
Computing it at query time from a dashboard variable means one place to
configure it and no re-processing when the domain list changes.

**Why RBAC is applied by hand, not by CI.** The deploy pipeline's service
account cannot grant itself permissions it does not have; that is the
control working, not a limitation. RBAC is applied once by an admin, out of
band from the automated deploy.

## The trust model in one paragraph

One shared bearer token authenticates all sources to the receiver. Findings
carry usernames and device identifiers, so the log store is sensitive and
should be access-scoped. Collectors run as root and are delivered through
your MDM, so they are as trusted as anything else you push that way. The
platform is a visibility tool, not a control: a user with local admin can
remove a collector, and the platform's value is making the common case
visible, not defeating a determined insider. `SECURITY.md` states this in
full.

## Extending it

The extension point is always the finding. A new detection source emits the
schema and posts to the receiver; nothing else changes. See
`docs/writing-a-scanner.md` for the concrete steps.
