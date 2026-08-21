# Portal

A governance view over the findings the receiver already collects. Devices,
identities, tools, and the relationships between them.

It reads Loki on request and derives entities. It writes nothing, holds no
database, and is not in the path of anything that already works: if the portal
falls over, collection carries on.

## Why it exists

Findings are a flat stream. Each one is an isolated row, and Loki can filter
and count them but cannot say that these forty rows are the same twelve
machines. Every governance question is a relationship: which tools a device
has, which devices a person uses, who is signed into what.

Grafana is better at graphs. This is better at relationships. Both are
optional and neither replaces the other.

## Deployment

Three are equally valid:

- **Grafana only.** Nothing changes; the portal is not deployed.
- **Portal only.** For a deployer who wants governance and does not care
  about time series.
- **Both**, with Grafana panels embedded in the portal dashboard.

The receiver stays one stateless container in all three.

## Authentication

**Required.** The portal refuses to start without it.

This page names who runs what on which machine, which is the most sensitive
thing the platform produces. Coming up open because a variable was missed is
the failure that matters: the portal is reachable, it looks like it works, and
nothing says the door is off. So it fails closed and says why.

    PORTAL_USER=admin
    PORTAL_PASSWORD=...

Basic auth is a floor rather than a ceiling: one shared credential, no
per-user trail, and plaintext without TLS in front of it. **If you already run
a reverse proxy, authenticate there instead** - it can do OIDC, mTLS or an
allowlist against whatever you already have - and run the portal behind it
with:

    PORTAL_AUTH=none

That opt-out logs a warning on every start, because an unauthenticated
deployment should never be something nobody noticed. It is the right setting
for localhost and for a proxy that authenticates for you, and the wrong one for
anything reachable.

OIDC in the portal itself is deliberately out of scope: correct, but heavy, and
a lot of configuration surface for something that reads a log store.

`/healthz` is unauthenticated on purpose. A liveness probe that needs a
credential is a probe that fails for the wrong reason, and it returns nothing
about the estate.

## Configuration

| Variable | Required | Meaning |
|---|---|---|
| `PORTAL_USER` | yes* | basic auth username |
| `PORTAL_PASSWORD` | yes* | basic auth password |
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
| `RECEIVER_URL` | no | the receiver's admin API, reachable from the portal. Unset means the Managed views say so and nothing else changes |
| `RECEIVER_PUBLIC_URL` | no | the ingest URL agents can reach, baked into downloaded deployment artifacts. Different from `RECEIVER_URL` on purpose: a cluster-internal service name baked into a Jamf script would enroll nothing |
| `COLLECTOR_SCRIPTS_DIR` | no | verified copies of the endpoint collector scripts, shipped in the image; override for development |

## Managed mode: the one write path

With `RECEIVER_URL` set (and `MANAGED_MODE=true` on the receiver), the
portal gains a Managed section: a fleet view of enrolled devices, an
enrollment-token view that mints and revokes, and per-source Download
buttons on the Setup view that generate a pre-configured collector script
with a fresh enrollment token baked in as the script's own fallback default
(MDM-supplied values still win; corporate domains are never baked - the
receiver serves those at runtime).

Every one of those actions is authorized by the **receiver**, not the
portal: the operator enters the receiver's admin token in the UI, it is
held in the tab's memory only, forwarded per request in an `X-Admin-Token`
header, and never stored anywhere in the portal. The portal still holds no
database and no credentials - a compromised portal yields readable
findings, which it always did, and nothing that can mint or revoke.
Governance decisions remain in the file ([docs/governance.md](../docs/governance.md));
these routes manage operational credentials, which is a different kind of
thing.

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

**A device with no mapping stays unattributed, and that is a legitimate answer
rather than a failure.** A small team with no MDM still gets "these three
machines are running Ollama on personal accounts", which is useful without a
name attached.

To start a map, `GET /api/suggest-identities?fmt=csv` returns proposals built
by comparing normalised local usernames against the identities cloud sources
report.

The portal will not apply those proposals itself. They are string matches, and
a mapping this platform invented and then acted on is how the wrong name ends
up on a report.

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

| Section | What it answers |
|---|---|
| Overview | how the estate looks right now, in widgets you choose |
| Tools | which AI tools appear, on how many devices, on which surfaces |
| People | identities from cloud sources, and the devices an identity map attaches |
| Devices | one row per machine, with each tool paired to the account it uses |
| Personal accounts | every personal account seen, with first and last seen |
| MCP servers | which MCP servers are configured, on which machines, by which tool |
| AI register | the tools actually in use, joined to what has been decided about each |
| Paste guard | what the guard stopped, on which tool, and how often |
| ISO 42001 evidence | an index of what the platform can say and where each record lives |
| Setup | which detection sources are reporting and which are silent |
| Uncovered devices | machines a scanner knows about that no collector reports from |
| Grafana | Grafana, embedded, with a link to the real thing |
| Settings | what the portal can say about itself, for a support conversation |

## AI register

The tools actually in use, from findings in the lookback window, joined to what
the registry knows and what your organisation has decided.

The registry is a watchlist rather than an inventory, so a tool it knows about
and nothing has reported is a count rather than a row. A register padded with
tools nobody here uses is a worse record of what an organisation does, not a
more complete one. A tool observed and absent from the registry does get a row,
flagged, because something in use that governance has never considered is the
anomaly worth acting on.

Status, owner and review date come from an optional governance file. Without
one, everything reads as undecided, which is honest: every tool ships
`approved: false` and presenting that as a refusal would assert a decision
nobody made. See [docs/governance.md](../docs/governance.md).

An approval past its review date reports as reviewing, says how long ago it
expired, and shows the previous decision. The record is not rewritten: a clock
ticking over is not a decision.

`GET /api/register?fmt=csv` exports the same rows the page shows, with the
timestamp and lookback window in the filename. It is a convenience export
rather than an evidence artifact: no manifest, no checksum.

## Paste guard

What the guard stopped, on which tool, and how often. Metadata only: it inspects
clipboard content on the device and reports detector identifiers, so what was
nearly pasted is not here and is not stored anywhere.

Overrides sort first. Somebody shown the detector by name who pasted anyway is
the row to follow up, and sorting by event count would bury one override under
twenty warnings that worked.

The page also reports how many devices the guard checked in from, and which
versions and modes they are running. Without that, "0 pastes stopped" means both
an estate where nobody pasted a secret and one where the extension was never
deployed. More than one version is a rollout that stalled; a device in warn mode
where policy says block is a policy not in force.

Heartbeats are excluded from the event counts. They share the same source, and
counting them would report every device's daily check-in as a paste somebody
tried to make.

## ISO 42001 evidence

An index of what the platform can currently say and where each record lives, with
review inputs below it. No compliance score, no clause numbers, no assessment.
See [docs/evidence.md](../docs/evidence.md).

The evidence snapshot is generated from the same derivations these pages use, so
a snapshot and the page it summarises cannot disagree.

## Overview widgets

`OVERVIEW_WIDGETS` is a comma separated list, drawn in order:

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
| `paste_guard` | pastes warned, overridden and blocked |
| `grafana:<panel title>` | a panel named in `GRAFANA_PANELS` |

Prefer a native widget to a `grafana:` one where both exist. An embedded panel
renders cross-origin, so it arrives in Grafana's typography with a title the
portal cannot restyle, and it sits visibly apart from the cards beside it.
`paste_guard` used to be a panel for this reason and no longer needs to be: the
portal derives those counts itself.

Unset gives a sensible default rather than an empty page. An unknown name
renders an error card naming what is valid, because a widget that silently does
not appear looks identical to one that appeared with nothing to show, and that
sends someone off debugging their data instead of their config.

This is a deployment decision rather than a per-user one. The portal holds no
state and has no users to hold it against, so an organisation shapes its landing
page here and the portal stays something that can be deleted and reinstalled
with nothing lost.

## Personal accounts

Its own section rather than a number on a summary page, because an approved
tool signed into a personal account is still unmanaged data flow and an
offboarding gap.

"Personal" is the reporting source's judgement, not the portal's: the collector
and the extension are told the corporate domains and decide at the point of
detection. The portal does not re-derive it, because it may not hold the same
list, and two definitions that disagree is worse than one that is occasionally
coarse.

Rows are keyed on the full tuple of person, account, tool and device. The same
person signing into two tools is two things to follow up, not one account with
a longer attribute list.

## MCP servers

Counted by server rather than by tool. An MCP server is a standing integration
rather than an application someone opens: it holds its own credentials and can
reach whatever it was pointed at whether or not the tool that configured it is
in use.

Server names come from the finding evidence. Two formats are read, because a
Loki window holds both for a while: the current `mcpServers: figma,context7`,
and the older form that folded the list into the tool name. That older form is
why this exists at all, since every distinct combination of servers became a
separate tool, and a machine with two servers looked unrelated to a machine
with one of them.

What a server can actually do wherever it points depends on the credentials it
holds, which are not visible from here. The device count is reach, not risk.

## Settings and diagnostics

Read only, and split in two on purpose.

Everything under Application, Loki, Registry and Access is something the portal
verified about itself: it either reached Loki or it did not, loaded the registry
or it did not. Anything it was merely told is grouped separately and labelled
"Provided by deployment configuration", so a chart version nobody updated is
never presented as a fact something checked. A Compose deployment leaves those
fields empty rather than guessing.

Credential values are never shown. Whether one is configured is useful; what it
is, is not.

## Setup view

The view the portal opens on. It shows which sources are reporting and which
are silent, derived from findings rather than from configuration being present.

A source that has never reported is either not set up or genuinely has nothing
to say, and from a dashboard those are identical. Listing them turns "I
deployed this and see an empty screen" into "the Entra scanner has never
reported". It stays useful afterwards as an is-it-still-working view.

## Embedding Grafana

The Grafana tab embeds Grafana panels, so the portal can be the one place
someone looks. It is optional, and everything else works without it.

Grafana refuses to be framed by default, deliberately: framing a session
someone is logged into is how clickjacking works. Turning that off is a
decision for the deployer, not something this portal can do on their behalf.
It needs, on the Grafana side:

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