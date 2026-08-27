# Portal

A governance view over the findings the receiver already collects. Devices,
identities, tools, and the relationships between them.

It reads findings from Loki when you open a page. It writes nothing and holds
no database, and it sits outside the collection path, so if the portal goes
down, collection keeps working.

## Why it exists

Findings arrive as a flat stream of rows. Loki can filter and count them, but
it can't tell you that forty rows are really twelve machines. The questions
you actually ask are about relationships: which tools does this device have,
which devices does this person use, who is signed into what. That's what the
portal answers.

Grafana is better at graphs and history. The portal is better at
relationships and current state. Run either or both.

## Deployment

Three are equally valid:

- **Grafana only.** Nothing changes; the portal is not deployed.
- **Portal only.** For a deployer who wants governance and does not care
  about time series.
- **Both**, with Grafana panels embedded in the portal dashboard.

The receiver stays one stateless container in all three.

## Authentication

**Required.** The portal refuses to start without it.

The portal shows who runs what on which machine - the most sensitive thing
this platform produces - so it will not start unauthenticated by accident. If
no auth is configured, it stops and tells you.

In **managed mode** (`RECEIVER_URL` set) none of the below applies: the
portal has a real login backed by the receiver's admin account, and the
basic-auth pair is ignored with a warning. See "Managed mode" further down.
Classic mode:

    PORTAL_USER=admin
    PORTAL_PASSWORD=...

Basic auth is the minimum, not a recommendation: it's one shared credential,
no per-user trail, and plaintext unless TLS sits in front. **If you already
run a reverse proxy, authenticate there instead** (OIDC, mTLS, an allowlist -
whatever you already have) and run the portal behind it with:

    PORTAL_AUTH=none

That setting logs a warning on every start so an unauthenticated deployment
is never an accident. Use it for localhost and behind an authenticating
proxy; don't use it for anything directly reachable.

The portal doesn't do OIDC itself - a reverse proxy does it better with less
configuration.

`/healthz` is unauthenticated on purpose: liveness probes shouldn't need
credentials, and it reveals nothing about your estate.

## Configuration

| Variable | Required | Meaning |
|---|---|---|
| `PORTAL_USER` | yes* | basic auth username (classic mode; ignored in managed mode) |
| `PORTAL_PASSWORD` | yes* | basic auth password (classic mode; ignored in managed mode) |
| `PORTAL_AUTH` | yes* | `none` to run without auth, deliberately |
| `LOKI_URL` | yes | Loki base URL, the same one the receiver writes to |
| `LOKI_TOKEN` | no | bearer token, if your Loki needs one |
| `LOKI_USERNAME` | no | basic auth user. Grafana Cloud and most hosted Loki want this rather than a token, and the receiver needs the same pair to write |
| `LOKI_PASSWORD` | no | basic auth password, `_FILE` supported |
| `LOOKBACK_HOURS` | no | default window, default 168 |
| `REGISTRY_PATH` | no | registry.yaml, for resolving domains to tool ids |
| `IDENTITY_MAP` | no | CSV of `key,identity` attaching people to devices |
| `GOVERNANCE_PATH` | no | YAML of approval decisions, owners and review dates. See [docs/governance.md](../docs/governance.md) |
| `GRAFANA_URL` | no | a Grafana that permits embedding; unset shows a note |
| `GRAFANA_PANELS` | no | `dashboardUid:panelId:Title`, semicolon separated |
| `GRAFANA_DASHBOARD_UID` | no | embed a whole dashboard instead of panels |
| `CACHE_TTL_SECONDS` | no | how long a derived graph is reused, default 30 |
| `OVERVIEW_WIDGETS` | no | which widgets the overview shows, comma separated |
| `DEPLOY_CHART_VERSION` | no | shown on the settings page, clearly unverified |
| `DEPLOY_RELEASE` | no | as above |
| `DEPLOY_NAMESPACE` | no | as above |
| `DIGEST_WEBHOOK_URL` | no | Slack-compatible webhook for the weekly digest; `DIGEST_DAY` (mon..sun) and `DIGEST_HOUR` (UTC) tune when it sends |
| `RECEIVER_ADMIN_TOKEN` | no | the receiver's `ADMIN_TOKEN`, `_FILE` supported. The portal's own service credential for the server-side log-store secrets read - needed for viewer sessions and the digest task when the log store was saved through the wizard (viewers are refused that read by design; the credential is typically write-capable). The chart mounts it automatically when `managed.adminToken` is set |
| `RECEIVER_URL` | no | the receiver's admin API, reachable from the portal. Unset means the Managed views say so and nothing else changes |
| `RECEIVER_PUBLIC_URL` | no | the ingest URL agents can reach, baked into downloaded deployment artifacts. Different from `RECEIVER_URL` on purpose: a cluster-internal service name baked into a Jamf script would enroll nothing |
| `COLLECTOR_SCRIPTS_DIR` | no | verified copies of the endpoint collector scripts, shipped in the image; override for development |

## Managed mode: the login, and the one write path

With `RECEIVER_URL` set (and `MANAGED_MODE=true` on the receiver), the
portal is in **login mode**: basic auth is replaced by a real sign-in
against the admin account that lives in the receiver's state DB.
`PORTAL_USER`/`PORTAL_PASSWORD` are ignored, with a warning. On a fresh
deployment no account exists yet - the receiver prints a one-time setup
code to its log at every boot until one does (`kubectl logs ... | grep
setup_code`, or `docker compose logs receiver`), and the portal's first
screen turns it into the admin account. The session is an HttpOnly,
SameSite=Strict cookie that page script can never read; the portal
validates it against the receiver per request (with a 60-second positive
cache, which bounds revocation latency) and stores nothing. `PORTAL_AUTH=none`
still means what it always did - reads are open for a reverse proxy that
authenticates - but admin actions still require the login, because the
receiver demands a credential either way.

The portal also gains a Managed section: a fleet view of enrolled devices,
an enrollment-token view that mints and revokes, and per-source Download
buttons on the Setup view that generate a pre-configured collector script
with a fresh enrollment token baked in as the script's own fallback default
(MDM-supplied values still win; corporate domains are never baked - the
receiver serves those at runtime).

On a fresh managed install the portal opens on a **first-run wizard**:
corporate domains, a governance baseline over the registry's watchlist, the
extension ID, and pre-configured deployment downloads for all five surfaces
(three collectors, the extension's managed-storage policy plist, a scanner
CronJob manifest with its token in a Secret). Every step is skippable and
everything it sets is editable later; Finish records `onboarding_done` so
the portal stops opening there. The extension policy is the one artifact
that bakes corporate domains - the extension reads no central config, so a
domain change means regenerating that file (its header says so).

The Settings view grows a **Central settings** card: corporate domains and
the extension ID are saved into the receiver's state DB and served to the
fleet at runtime, with the source of each value named - a saved list shows
what environment value it is shadowing, and clearing it falls back. The AI
register's cards gain an **edit** control for governance decisions (status,
owner, review date, reason), stored the same way and merged per tool with
the governance file - the recorded decision wins, the file fills the gaps,
and the card says "set in the portal" so the two are never mistaken for one
another. Exceptions stay file-only
([docs/governance.md](../docs/governance.md)).

**Accounts and roles.** The first account (the one the setup code creates)
is an admin. Admins can add more under Settings, as admin or as viewer. A
viewer reads every page and can change nothing - every write comes back as
a 403 that says so - which is the right shape for an auditor or an exec.
Roles are fixed at creation; changing someone's trust level is delete and
recreate, which leaves a cleaner trail than an edit would. The last admin
cannot be deleted, password resets revoke the sessions the old password
minted, and everything lands in the audit trail.

**The audit trail.** Every change made through the portal - settings,
decisions, accounts, enrollments, revocations - is recorded by the receiver
as it happens, with who did it. Settings, Diagnostics shows the recent
trail; `/api/audit` serves it.

**The finding lifecycle.** A personal-account finding can be acknowledged
(spoken to - stays visible, stops being new) or accepted with a reason
(drops out of the open count), and reopened. The receiver stores only the
answer; the finding itself stays derived from the log store, so the record
and the evidence can never disagree.

**Notifications.** A `webhook_url` saved in Settings makes the receiver
post to Slack (or anything webhook-compatible) the moment discovery puts a
new tool or MCP server in the review queue - once per discovery, never per
finding. Separately, the portal can send a weekly digest of the estate:
set `DIGEST_WEBHOOK_URL` on the portal, and give it `RECEIVER_ADMIN_TOKEN`
if your log store was configured through the wizard rather than by env
(a background task has no operator session to read the saved settings
with).

Every one of those actions is authorized by the **receiver**, not the
portal: the operator's own session token is forwarded per request and never
stored anywhere in the portal. The portal holds no database and no
credentials of its own - a compromised portal yields readable findings,
which it always did, and nothing that can mint or revoke.

### Reading from a hosted log store

`LOKI_USERNAME` and `LOKI_PASSWORD` are the same credentials the receiver
writes with, and both containers need them. Setting them on one and not the
other produces a deployment where findings are stored and cannot be read back,
and nothing reports an error you would attribute to the right cause: the
receiver is healthy, its push counter climbs, and this portal returns something
a deployer reads as their own misconfiguration.

Basic auth takes precedence over `LOKI_TOKEN` when both are set, because only
one `Authorization` header can be sent and the log store is the thing that has
to accept it.

On Grafana Cloud the username is a numeric instance id rather than an email,
and `LOKI_URL` is the base URL without the query path, while the receiver's
`LOKI_PUSH_URL` ends `/loki/api/v1/push`. Same host, two values, and crossing
them is the commonest way to get a receiver that stores findings and a portal
that finds none.

## Identity

The portal does not resolve identity. It carries enough for you to resolve it
against whatever you run.

One machine is one device even when its sources disagree about the key. An
endpoint collector reports an asset-tagged serial and a browser extension
reports the bare one, so the same laptop used to arrive as two devices with
its tools split across both. Keys that differ only by a prefix are merged,
the other spellings are listed on the device's detail, and a personal-account
row whose source reported no account name takes the person the identity map
attaches to that machine - labelled "via device", because it was inferred
from the hardware rather than read from the source. An ambiguous key (the
tail of two prefixed keys) or one too short to be an identifier is left
alone: merging the wrong two machines is worse than showing two cards.

Endpoint findings carry a device and a local username. The username is a hint,
not a key: it is `firstname.lastname` on a Jamf Connect Mac, a local account on
a Mac enrolled before that, the work account on Autopilot Windows, and whatever
the person chose on unmanaged Linux. The device is reliable, because Jamf,
Intune, SentinelOne and most RMMs all key on it.

Cloud findings carry an identity and no device, because Entra and Exchange know
people rather than machines.

So the two halves meet at the person, and joining them is a lookup you own.
Supply `IDENTITY_MAP` as a CSV of `key,identity` where the key is a device or a
local username, from your MDM, your RMM, a CMDB, or a spreadsheet.

**A device with no mapping just shows as unattributed, and that's fine.** A
small team with no MDM still gets "these three machines are running Ollama on
personal accounts", which is useful without a name attached.

To start a map, `GET /api/suggest-identities?fmt=csv` returns proposals built
by comparing normalised local usernames against the identities cloud sources
report.

The portal never applies those proposals automatically. They're string
matches, and you should check every line - a wrong match puts the wrong
person's name on a report.

### Where the file goes

**Not in this repository.** The map associates named people with the machines
they use. It is personal data, it is specific to one deployment, and committing
it would publish your colleagues' names. Add it to `.gitignore` and keep it
wherever you keep deployment configuration.

The format is one `key,identity` per line. The key is a device identifier or a
local username; lines starting with `#` are ignored, so the commented proposals
in the generated file can be uncommented as you confirm them.

    C02XK1AB,alex.morgan@example.com
    NIX-BUILD-02,sam.reid@example.com
    jordan.lee,jordan.lee@example.com

**Local:**

    curl -o ~/.config/ai-guard/identity-map.csv \
      http://localhost:8091/api/suggest-identities?fmt=csv
    # edit it, then
    IDENTITY_MAP=~/.config/ai-guard/identity-map.csv uvicorn app.main:app

**Docker:** mount it read-only.

    docker run --rm -p 8091:8091 \
      -e LOKI_URL=http://loki:3100 \
      -e IDENTITY_MAP=/etc/ai-guard/identity-map.csv \
      -v /path/to/identity-map.csv:/etc/ai-guard/identity-map.csv:ro \
      ai-guard-portal

**Kubernetes:** a ConfigMap mounted as a file, or a Secret if your privacy
assessment calls for it. The portal only reads it.

    kubectl create configmap ai-guard-identity-map \
      --from-file=identity-map.csv=./identity-map.csv

The file is re-read whenever the derived graph is rebuilt, so an edit takes
effect within `CACHE_TTL_SECONDS` (default 30) without a restart.

## Sections

The sidebar is seven sections; each holds its pages as tabs. Details open in
an inspector beside the list rather than a separate page, and the theme
toggle (light or dark) is remembered per browser.

| Section | Pages | What it answers |
|---|---|---|
| Overview | Overview, Grafana | how the estate looks and which way the week went, in widgets you choose |
| Inventory | Tools, People, Devices, Personal accounts, MCP servers | what is in use, by whom, on what, signed into which account |
| Governance | AI register, Tool registry, Paste guard, ISO 42001 evidence | what each tool is, what was decided, what the guard stopped |
| Budget | Budget | what each AI tool costs, and whether the seats paid for match the people observed using them |
| Health | Sources, Uncovered devices | which detection sources are reporting, which are silent, and which machines nothing covers |
| Fleet | Devices, Enrollment tokens | who is enrolled with their own credential, and the invitations that enroll them |
| Settings | Settings tabs, Diagnostics | central settings, accounts, the audit trail, and what the portal verified about itself |

Tools that need a look sort first, with the reasons spelled out as named
factors (personal accounts, wide spread, multiple surfaces, new this week)
rather than a score. Personal-account rows carry their lifecycle controls.

## AI register

The tools actually in use, from findings in the lookback window, joined to what
the registry knows and what your organisation has decided.

Tools the registry watches for but nobody uses show as a count, not a row -
padding the register with unused tools would make it a worse record, not a
more complete one. A tool in use that the registry doesn't know does get a
row, flagged, because something in use that nobody has considered is the
thing worth acting on.

Status, owner and review date come from your recorded decisions (in the
portal, or an optional governance file). Without any, everything shows as
undecided - every tool ships `approved: false`, and showing that as "banned"
would claim a decision nobody made. See
[docs/governance.md](../docs/governance.md).

An approval past its review date shows as "reviewing", says how long ago it
expired, and keeps the previous decision visible. The record itself isn't
rewritten - a date passing is not a decision.

`GET /api/register?fmt=csv` exports the same rows the page shows, with the
timestamp and lookback window in the filename. It is a convenience export
rather than an evidence artifact: no manifest, no checksum.

## Paste guard

What the guard stopped, on which tool, and how often. Metadata only: it inspects
clipboard content on the device and reports detector identifiers, so what was
nearly pasted is not here and is not stored anywhere.

Overrides sort first: someone who was shown a warning and pasted anyway is
the row worth following up.

The page also shows how many devices the guard is running on, and which
versions and modes. That's what makes "0 pastes stopped" trustworthy - without
it, zero could just mean the extension was never deployed. Multiple versions
means a rollout stalled somewhere; a device in warn mode when your policy says
block means the policy isn't in force there.

Daily heartbeats are excluded from the event counts, so a check-in never
counts as a paste.

## ISO 42001 evidence

An index of what the platform can currently say and where each record lives, with
review inputs below it. No compliance score, no clause numbers, no assessment.
See [docs/evidence.md](../docs/evidence.md).

The evidence snapshot is generated from the same derivations these pages use, so
a snapshot and the page it summarises cannot disagree.

## Overview widgets

In managed mode these are toggles under Settings, one per widget with its
description, and a widget added in a release appears there as an unticked
option. Classic deployments set the same list as `OVERVIEW_WIDGETS`, a comma
separated list drawn in order:

```
OVERVIEW_WIDGETS=stat_row,top_tools,recent_personal_accounts,detection_coverage
```

| Widget | Shows |
|---|---|
| `stat_row` | headline counts across the estate |
| `top_tools` | tools by number of devices |
| `recent_personal_accounts` | most recently seen personal accounts |
| `detection_coverage` | how much of each surface is reporting |
| `source_health` | sources listed as silent |
| `review_queue` | observed tools awaiting a governance decision |
| `budget_spend` | tracked AI spend, tools linked, paid seats never observed and the next renewal (managed mode) |
| `paste_guard` | pastes warned, overridden and blocked - and what block mode would have stopped |
| `grafana:<panel title>` | a panel named in `GRAFANA_PANELS` |

Prefer a native widget over a `grafana:` one where both exist - embedded
panels arrive in Grafana's styling and look out of place next to the cards.

Leaving it unset gives you a sensible default. A typo in a widget name shows
an error card listing the valid names, so you find out immediately instead of
wondering where your widget went.

## Budget

Link a tool to the licence you pay for - plan, seat tiers, per-seat price,
renewal date - and give it the list of people that licence covers. The card
then joins that list against the findings the portal already holds: paid
seats never observed, observed users no seat covers, and personal-account
use running alongside the paid plan.

User lists come from a vendor's admin API where one exists (Anthropic's
Claude Enterprise and Console organisations, Fireflies), and from the member
export the vendor's admin page produces where one does not (ChatGPT
Business, Claude Team). Imports and syncs enrich rather than erase, so seat
tiers assigned by import survive a sync that cannot report them.

A subscription is a licence, not a tool: it records every tool the licence
entitles, so one Claude seat is counted once across Claude and Claude Code
and a person seen on either counts as observed. Per-tier coverage carries
the seat economics - which tier buys which tool - and the two findings that
follow it: a tier's exclusive tool its holders are never seen on, and a
person seen on a tool their tier does not cover.

**Share / export** opens the same numbers as a report meant to leave the
browser: everything expanded, its own provenance and a plain-language note
on how to read it, printable to PDF (the print stylesheet drops the
furniture and forces a light palette), downloadable as one flat CSV, and
with a single control that withholds every name in both the page and the
file for wider circulation.

Admins link, edit and import; viewers read - including the report, which is
what an auditor or a finance owner usually needs. Vendor API keys are held
by the receiver, spent server-side and never returned to any page.
[Budget](../docs/budget.md) covers the whole feature.

## Personal accounts

Personal accounts get their own page because even an approved tool on a
personal account is unmanaged data flow and an offboarding gap.

"Personal" is decided at the point of detection: the collector and extension
know your corporate domains and judge each account against them. Each row is
one person + account + tool + device combination, so the same person on two
tools is two rows - two things to follow up.

## MCP servers

Counted by server, not by tool. An MCP server is an integration with its own
credentials - it can reach whatever it was pointed at even when the tool that
configured it isn't open, which makes the server the interesting unit.

What a server can actually do depends on the credentials it holds, which
aren't visible from here. The device count tells you reach, not risk.

## Settings and diagnostics

Read only, and split in two on purpose.

Everything under Application, Loki, Registry and Access is something the
portal actually checked: it reached Loki or it didn't, loaded the registry or
it didn't. Values it was merely told (like a chart version) are grouped
separately and labelled "Provided by deployment configuration", so nothing
unverified reads as a fact.

Credential values are never shown - only whether one is configured.

## Setup view

The view the portal opens on. It shows which sources are reporting and which
are silent, derived from findings rather than from configuration being present.

A source that has never reported might not be set up, or might genuinely have
nothing to say - a dashboard can't tell those apart, so this page lists each
one and what it needs. It turns "I deployed this and the screen is empty"
into "the Entra scanner has never reported". Afterwards it stays useful as an
is-it-still-working view.

## Embedding Grafana

The Grafana tab embeds Grafana panels, so the portal can be the one place
someone looks. It is optional, and everything else works without it.

Grafana refuses to be embedded in another page by default (that's a
clickjacking protection). Allowing it is your call to make on the Grafana
side:

    GF_SECURITY_ALLOW_EMBEDDING=true
    GF_SECURITY_COOKIE_SAMESITE=none
    GF_SECURITY_COOKIE_SECURE=true      # if your Grafana has a login

The second is easy to miss. A framed page is cross-site as far as the browser
is concerned, so the default `Lax` cookie is not sent and the frame renders a
login screen that no amount of `allow_embedding` will fix.

**The third locks you out of Grafana if you skip it.** `SameSite=None` is only
valid on a cookie that also has `Secure`, so a browser silently discards the
session cookie: you log in, it succeeds, and you land back on the login screen
with nothing to explain why. Setting `cookie_secure` requires Grafana to be
behind HTTPS, which it should be anyway.

You only need it if your Grafana authenticates. An anonymous, read-only
Grafana issues no session cookie, so the first two settings are enough - which
is why the demo works without it and a real instance does not.

Then decide how the frame authenticates: anonymous access on a Grafana that is
locked down and read-only, or an auth proxy. The demo takes the first route
because its Grafana is anonymous, viewer-only and bound to loopback.

On the portal side, either name the panels:

    GRAFANA_PANELS="ai-guard:2:Devices reporting (24h);ai-guard:6:Top tools (devices, 7d)"

Semicolons, not commas. Panel titles routinely contain commas, and a comma
separator splits "Top tools (devices, 7d)" into two malformed entries.

or embed a whole dashboard in one frame, which needs no panel ids and survives
someone rearranging them:

    GRAFANA_DASHBOARD_UID=ai-guard

The title is the frame's accessible name rather than a visible caption:
Grafana renders the panel title inside the frame already, and showing it twice
reads as a mistake.

`GRAFANA_URL` is the URL a browser reaches Grafana on, not the one the portal
container would use: the frames are loaded by the browser, not by the portal.

### Finding the ids

You will not know these until Grafana is running with data in it, so this is
normally something you come back and do rather than set up front.

Open the dashboard. The address bar gives you the uid:

    https://grafana.example.com/d/ai-guard/ai-guard-shadow-ai-visibility
                                   ^^^^^^^^ uid

Then any panel's menu, Share, Link. That URL ends with `viewPanel=<n>`, and
that number is the panel id:

    ...?orgId=1&from=now-7d&to=now&viewPanel=19
                                              ^^ panel id

So that panel is `ai-guard:19:Whatever you want to call it`.

### Applying them afterwards

**Docker Compose:** edit `.env`, then recreate the container. A restart does
not reread the file.

    docker compose up -d portal

**Helm:**

    helm upgrade ai-guard charts/ai-guard --reset-then-reuse-values \
      --set portal.grafana.url=https://grafana.example.com \
      --set-string 'portal.grafana.panels=ai-guard:19:Devices reporting'

Two things there matter. `--reset-then-reuse-values`, not `--reuse-values`:
the latter keeps only the values you previously set, so any chart default you
have not overridden goes missing, and the templates fail on the gaps. And
`--set-string`, because the value contains colons and commas that `--set`
would try to parse as structure.

If a frame stays blank, Grafana is refusing to be framed rather than the panel
being wrong. Check the two settings above before the panel id.

## Running it

    make lock                 # first time, or after editing requirements.in
    docker build -t ai-guard-portal .
    docker run --rm -p 8091:8091 \
      -e LOKI_URL=http://loki:3100 \
      -e PORTAL_USER=admin -e PORTAL_PASSWORD=... \
      ai-guard-portal

Then open http://localhost:8091.