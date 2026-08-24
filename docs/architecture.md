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
  endpoint collectors ────┤                        ┌─► logs ─┬─► Grafana
  macOS / Windows / Linux │                        │  (Loki,  │   dashboard
  (pushed by MDM or RMM)  ├──►  receiver  ─────────┤   or     │
                          │                        │  anything └─► portal
  cloud scanners ─────────┤                        │  that         (optional)
  sign-in logs,           │                        │  takes
  signup emails,          │                        │  JSON lines)
                          │                        └─► alerts ──► your channel
                          │                              (Alertmanager)
  software inventory      │
                          │        ▲
  network / DNS scanner ──┘        │
  anything that sees             registry (shipped + your own entries,
  which domains devices          added in the portal or as YAML)
  talk to: EDR, DNS              domains, extension IDs, config paths -
  firewall, web gateway          collectors pull this at runtime
```

Left to right: anything on the left sends the same kind of finding into the
receiver, the receiver writes it to the logs and fires alerts, and Grafana reads
the logs. The portal is optional and reads the same logs; it answers what
belongs to what where the dashboard answers how much and when. The registry is the one shared thing everything leans on. Collectors
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

The browser surface reports under two sources, because it answers two
questions. `browser_extension` says which account is signed into an AI tool.
`paste_guard` says what was stopped or flagged on the way into one, plus a
daily heartbeat proving the chain works on that device. Both come from the same
extension; keeping the sources separate is what lets you tell "nobody pasted
anything risky" apart from "the extension isn't deployed".

The paste guard is also the one place the platform prevents rather than
observes: it scans pastes into AI tools on-device and warns or blocks before
content reaches the page, reporting detector ids and never the matched text.
Everything else in this document describes detection; that one control is
enforcement, and it rides the same pipeline.

## The finding schema

```json
{
  "tool": "claude-code",
  "surface": "cli",
  "os": "linux",
  "account_domain": "gmail.com",
  "device": "SERIAL123",
  "device_name": "ASK-SERIAL123",
  "user": "jane.doe",
  "evidence": "~/.claude.json",
  "severity": "warn",
  "reported_at": "2026-01-01T09:00:00Z",
  "source": "collector-linux"
}
```

- **tool**, which AI tool, from the registry.
- **surface**, one of browser, cli, ide, desktop, mcp, network, cloud.
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
through. It authenticates the sender (a per-device credential, or the shared
bearer token), writes each finding as a structured JSON line to stdout
(which the log pipeline scrapes), optionally fires an Alertmanager alert for
personal-account findings, and serves the registry to collectors. It is
deliberately thin: it does not store findings itself, does not deduplicate
at rest, and does not know about any specific tool.

In managed mode - the default - the receiver also holds the platform's one
piece of durable state: a single SQLite file with the device registry,
accounts and sessions, central settings, governance decisions,
portal-defined registry entries, the discovery queue and the audit trail.
Everything in it is a decision or a credential hash, never a finding;
findings always live in the log store. Classic mode never creates the file,
so a classic deployment keeps the property that losing any component loses
nothing.

**registry**, the source of truth for what counts as an AI tool: domains,
extension IDs, config file paths per OS, account file locations. The shipped
registry is a schema-validated YAML file compiled at release time; in
managed mode the portal's own entries are merged on top at serve time,
validated to the same rules, so defining a tool in the review queue reaches
every collector on its next check-in. Either way, collectors fetch their
view from the receiver at runtime, which is why adding a tool never means a
script change pushed to every endpoint.

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
domains from DNS telemetry and posts candidates to the receiver, where they
wait in the portal's review queue. It never adds to the registry itself; a
person turns each candidate into a registry entry or dismisses it. (With
GitLab configured it proposes merge requests against the registry source
instead.)

**dashboard**, Grafana over the log store. It reads findings, not a
database, and computes personal-vs-work from the corporate domain variable
the deployer sets. Most panels count distinct devices or users, not events,
so they are stable across receiver restarts.

**portal**, the operating surface. Where the dashboard answers how much and
when, the portal answers what belongs to what - findings arrive as a flat
stream of isolated rows, and a log store cannot say that forty rows are the
same twelve machines. The portal derives those relationships on request and
holds no database of its own, so it is a view rather than a store and it is
never in the ingest path: losing it loses nothing.

In managed mode it is also where the platform is run: the wizard, central
settings, accounts (admin and read-only viewer), the review queue, the
fleet, notifications, and pre-configured deployment downloads. Every one of
those writes is proxied to the receiver and authorized there with the
operator's own session - the portal stores no credentials, so a compromised
portal yields readable findings, which it always did, and nothing that can
mint or revoke.

The AI register is that view pointed at governance: the tools actually in
use, joined to what your organisation has decided about each. Tools the
registry watches for but nobody uses show as a count, not a row - padding the
register with unused tools would put vendor defaults in front of a management
review as if someone had taken a position on them. A tool in use that the
registry doesn't know does get a row, flagged, because that's the one worth
acting on. Decisions (status, owner, review date) come from what you record
in the portal or an optional governance file, described in
[governance.md](governance.md).

Governance is kept separate from the registry on purpose. The registry
answers "what is this tool and how do we detect it", and ships with the
project. Governance answers "what did our organisation decide", which nobody
else can ship for you.

Approval records a position and does not change severity. Severity is decided
at the point of detection and depends on the account domain, so an approved
tool signed into a personal account is still a warn, and an unapproved tool on
a corporate account is still info. Those are independent dimensions and the
portal keeps them that way: approval must never come to mean safe.

An approval past its review date shows as "reviewing" with the old decision
alongside; the stored record is never rewritten. An approval nobody has
revisited isn't evidence the tool is safe - it's evidence nobody looked.

The evidence snapshot is the same data packaged for an auditor: what was
observed in a stated window, with the registry and governance files
identified by hash, and a checksum over the whole document. Two limits are
stated in the document itself because they matter for anything offered as
evidence: it can't be regenerated identically later (log retention), and the
checksum catches corruption and careless edits, not deliberate alteration
(anyone changing a count can recompute it). Every count comes with its
denominator - "8 sources reporting" always sits next to "of 12 known" -
so a half-blind estate can't look complete on paper. See
[evidence.md](evidence.md).

Identity works in two halves. Endpoint findings know the machine (the
serial is reliable - every fleet tool keys on it) but only a local username,
which varies by how the machine was set up. Cloud findings know the person
but not the machine. Joining them needs a lookup only the deployer has: an
MDM, an RMM, a CMDB, a spreadsheet. The portal proposes a mapping from
string matches but never applies one itself - a wrong guess acted on is how
the wrong name ends up on a report. Devices with no mapping show as
unattributed, which is fine: a small team with no MDM still learns that
three machines are running Ollama on personal accounts.

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

**What the account fields carry.** The `account_domain` field holds the
domain only, which is what answers the core question: is a managed device
using a personal account. The finding also carries a `user` field so it can
be followed up with the right person. On cloud scanners this is the corporate
email's local part, kept only for approved corporate domains; on endpoint
collectors it is the device's console username. Both are already known to IT.
See [privacy](deployment-privacy.md) for exactly when the username is populated.

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

Sources authenticate to the receiver with their own enrolled credential, or
the shared bearer token during migration and in classic mode. Findings
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