# portal

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

## Configuration

| Variable | Required | Meaning |
|---|---|---|
| `LOKI_URL` | yes | Loki base URL, the same one the receiver writes to |
| `LOKI_TOKEN` | no | bearer token, if your Loki needs one |
| `LOOKBACK_HOURS` | no | default window, default 168 |
| `REGISTRY_PATH` | no | registry.yaml, for resolving domains to tool ids |
| `IDENTITY_MAP` | no | CSV of `key,identity` attaching people to devices |
| `GRAFANA_URL` | no | a Grafana that permits embedding; unset shows a note |
| `GRAFANA_PANELS` | no | `dashboardUid:panelId:Title`, semicolon separated |
| `GRAFANA_DASHBOARD_UID` | no | embed a whole dashboard instead of panels |
| `CACHE_TTL_SECONDS` | no | how long a derived graph is reused, default 300 |

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
effect within `CACHE_TTL_SECONDS` (default 300) without a restart.

## Setup view

The view the portal opens on. It shows which sources are reporting and which
are silent, derived from findings rather than from configuration being present.

A source that has never reported is either not set up or genuinely has nothing
to say, and from a dashboard those are identical. Listing them turns "I
deployed this and see an empty screen" into "the Entra scanner has never
reported". It stays useful afterwards as an is-it-still-working view.

## Embedding Grafana

The Dashboard tab embeds Grafana panels, so the portal can be the one place
someone looks. It is optional, and everything else works without it.

Grafana refuses to be framed by default, deliberately: framing a session
someone is logged into is how clickjacking works. Turning that off is a
decision for the deployer, not something this portal can do on their behalf.
It needs, on the Grafana side:

    GF_SECURITY_ALLOW_EMBEDDING=true
    GF_SECURITY_COOKIE_SAMESITE=none

The second is easy to miss. A framed page is cross-site as far as the browser
is concerned, so the default `Lax` cookie is not sent and the frame renders a
login screen that no amount of `allow_embedding` will fix.

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

Panel ids come from the dashboard JSON. `GRAFANA_URL` is the URL a browser
reaches Grafana on, not the one the portal container would use: the frames are
loaded by the browser, not by the portal.

If a frame stays blank, Grafana is refusing to be framed rather than the panel
being wrong. Check the two settings above before the panel id.

## Running it

    make lock                 # first time, or after editing requirements.in
    docker build -t ai-guard-portal .
    docker run --rm -p 8091:8091 -e LOKI_URL=http://loki:3100 ai-guard-portal

Then open http://localhost:8091.