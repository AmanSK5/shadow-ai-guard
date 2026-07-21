# Architecture

This document is the mental model. Read it before extending the platform or
reviewing a change: it explains not just what the pieces are but why they are
shaped this way, which is the part that is hard to reconstruct from the code.

## How it fits together

Every detection surface, however different its mechanism, produces the same
thing: a **finding**. A finding is a small JSON object saying "this AI tool,
on this surface, on this device, is signed into an account on this domain."
The receiver accepts findings and does not care where they came from. That
single shape is the contract the whole system is built around.

Because every source uses the same finding shape, adding a new one (a new
scanner, a new OS collector, a new RMM) is never a change to the receiver
or the dashboard. It is a new thing that emits the finding shape. This is
worth keeping: if a change makes the receiver need to know about a specific
source, something has gone wrong.

## What a deployment actually looks like

The receiver, the logs and the dashboard stay the same everywhere. The part that
changes from one company to the next is what feeds them: whatever you already run
that can spot AI tools and send in a finding.

It's set up this way on purpose. The receiver takes findings the same way no
matter which source they came from, so adding a new source doesn't mean changing
the receiver, the logs or the dashboard. You point one more thing at it and it
fits in with the rest.

```
  WHAT FEEDS IT                                   WHERE IT ENDS UP
  (use what you already run)                      (your existing stack)

  browser extension ──────┐
  (managed browser policy)│
                          │
  endpoint collectors ────┤                        ┌─► logs ──► Grafana
  macOS / Windows / Linux │                        │   (Loki, or       dashboard
  (pushed by MDM or RMM)  ├──►  receiver  ──────────┤    anything that
                          │                         │    takes JSON lines)
  cloud scanners ─────────┤                         │
  sign-in logs,           │                         └─► alerts ──► your channel
  signup emails,          │                             (Alertmanager)
  software inventory      │
                          │        ▲
  network / DNS scanner ──┘        │
  anything that sees             registry (a YAML file, reviewed in a PR)
  which domains devices          domains, extension IDs, config paths,
  talk to: EDR, DNS              whether a tool's approved - collectors
  firewall, web gateway          pull this at runtime
```

Left to right: anything on the left sends the same kind of finding into the
receiver, the receiver writes it to the logs and fires alerts, and Grafana reads
the logs. The registry is the one shared thing everything leans on. Collectors
pull their list of what-to-look-for from it at runtime, which is why adding a new
AI tool is a one-line edit to a YAML file instead of a change you have to push to
every machine.

The left column is the part you have freedom over. None of those four are
required, and none are tied to a particular vendor. You run the ones you can, and where you're
missing one you can usually swap in something you already have (see *Swapping
collectors* below).

## Swapping collectors

The receiver only cares about the finding, not where it came from. So the
left-hand side is really a set of jobs, not a fixed list of products. Each job
can be done by whatever you've got that can see that surface and either run a
script or give you an inventory. If you don't have the obvious tool for a job,
there's usually something you already own that'll stand in.

| The job | Usually done by | Can also be done by | What the stand-in has to do |
| --- | --- | --- | --- |
| macOS machines | An Apple MDM | Any MDM or RMM that can push and run a shell script on Macs | Run the collector script on a schedule and capture the output |
| Windows machines | A Windows MDM | Any MDM or RMM that can push and run PowerShell | Run the collector script on a schedule and capture the output |
| Linux / unmanaged machines | (often nothing) | An RMM that can run scripts on a schedule | Just run the collector script. It doesn't need to fully "manage" the box, only run scripts on it |
| Software inventory | Your device-management tool's inventory | Anything that lists installed apps and extensions per machine | Give you app or extension IDs the registry can match |
| Network / DNS | A DNS-telemetry source | Anything that already sees which domains your machines reach: EDR, a DNS firewall, a web gateway, resolver logs | Give you (machine, domain) pairs to match against the registry |
| Cloud sign-ins | Your identity provider's sign-in logs | Any IdP that shows per-app sign-in events | Show which users signed into which AI apps |
| Cloud signups | A mail or records search | Anything that can surface signup / verification emails from AI vendors | Show the sender domains of self-service signups |

Two things worth pulling out of that table:

An **RMM that can run scripts can stand in for an MDM here**, even if it
doesn't otherwise manage the machine. That's how Linux and any other unmanaged
boxes get covered - you don't need a "real" MDM for them, you just need something
that can run a script on a schedule.

The **network side doesn't need a dedicated DNS product**. Anything that already
sees the domains your machines talk to will feed it, so most places can use an
EDR or web filter they already pay for rather than buying something new.

## Where people usually start

You don't turn everything on at once. Pick the jobs you can already cover and
grow from there. A few common shapes:

- **Mostly Microsoft.** Windows machines and inventory come from your Windows
  MDM, sign-ins and signups from your Microsoft identity and mail side, and the
  network side from whatever EDR or web filter already logs domain traffic. Add
  the browser extension through managed browser policy.

- **Apple-heavy or a mix.** macOS machines and inventory from your Apple MDM,
  Windows from a Windows MDM, and any Linux or contractor machines covered by an
  RMM that can run scripts. Cloud and network as above.

- **Just trying it out.** Start with only the endpoint collectors on the few
  machines that matter, plus the browser extension. That alone answers the
  question worth the most - which AI CLIs and IDE tools are signed into personal
  accounts - with no cloud setup at all. Add the rest later if you need it.

Either way the receiver, the logs, the dashboard and the registry don't change.
Only the left-hand side does.

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
