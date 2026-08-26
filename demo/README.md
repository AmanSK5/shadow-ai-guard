# Local demo

See the platform work with synthetic data in about five minutes. No cluster,
no real estate touched. Everything here is fake: demo users are named after
Pokemon, findings are seeded locally. The only credential involved is the
one the demo itself mints: the portal runs managed mode like a real
deployment, so the first visit walks the real first-boot path.

The demo shows both halves of the platform: the detection pipeline landing
in a Grafana dashboard, and the browser paste guard intercepting secrets
before they reach an AI tool.

## Run it

Requires Docker with Compose v2 (`docker compose`, not the legacy
`docker-compose`), and ports 3000, 8080, 3100 and 8090 free.

From the repository root:

```bash
cd demo
docker compose up
```

Stop and wipe everything:

```bash
docker compose down -v
```

## The portal

Open http://localhost:8091. It asks you to create the admin account - the
receiver printed a one-time setup code to its log when it started:

```bash
docker compose logs receiver | grep setup_code
```

On Windows, swap `grep` for `findstr` - it is built into both PowerShell
and cmd.

Paste the code, pick a username and password, and you are in - the same
first-boot flow as a real deployment, which is why the demo does not skip
it. Being signed in unlocks the managed half of the platform: the setup
wizard (the portal offers it, or go to `#wizard`), central settings, the
fleet view and enrollment tokens.

After login it lands on a sources view showing which detection sources are
reporting and what each silent one would need. In the demo most are not
reporting - that's what a partly-configured deployment looks like, and the
page exists so you can always tell "not set up" apart from "nothing to
report".

The other tabs are the part Grafana cannot do. Findings are a flat stream of
isolated rows; the portal derives the relationships between them, so a device
page shows every tool seen on that machine across every surface, and a tool
page shows how many devices have it in a browser versus a desktop app versus
a CLI. Those are different exposures and are deliberately not merged.

Nobody is attached to a device until you supply an identity map, and the
portal explains how on the setup page. It proposes one and will not apply it:
the proposals are string matches against local usernames, and a mapping this
platform invented and then acted on is how the wrong name ends up on a report.

The portal is never in the ingest path. Stop that one service and
collection carries on, which is a property worth seeing for yourself.

## The dashboard

Open http://localhost:3000 and look at the "Shadow AI" dashboard. It opens
with no login (anonymous access is on for the demo only).

Personal-versus-work colouring works out of the box: the dashboard's
corporate domains variable ships with the demo's domains
(`example[.]com|example[.]co[.]uk`) as its default, so example.com accounts
show as corporate and gmail.com / outlook.com as personal with no steps.
In a real deployment that same variable is what you point at your own
domains.

## The paste guard

Open http://localhost:8090/demo/ for a stand-in AI prompt box running the
extension's real, unmodified `guard.js`. Paste the test vectors on the page
(all fake or documentation values) and watch it warn or block; the panel
underneath shows the exact report the extension would send, which never
contains what you pasted. Deploying the real extension is covered in
[../extension/README.md](../extension/README.md).

## What is running

Six containers:

- **loki** - the log store, where findings land
- **receiver** - the real receiver, built from `../receiver`, running
  managed mode and pushing every finding straight to Loki (no scraping
  sidecar needed)
- **portal** - the real portal, built from `../portal`, proxying admin
  actions to the receiver exactly as a deployment does
- **grafana** - pre-provisioned with the Loki datasource and the project
  dashboard, so it is populated on load with nothing to import
- **seeder** - posts a spread of synthetic findings once the receiver is
  healthy, then exits
- **extension-demo** - serves the paste-guard demo page and the real
  `guard.js` it loads

The seed data covers all six surfaces and all three endpoint OSes, with a
mix of personal accounts (which show as warnings) and corporate accounts, so
every panel has something to show.

## Re-seed

The seeder runs once at startup. To post the findings again (for example
after `docker compose down -v`), bring the stack back up, or run just the
seeder against a running stack:

```bash
docker compose run --rm seeder
```

## This is a demo, not a deployment

The demo uses a fixed token (`demo-token`), anonymous Grafana, and no TLS.
None of that is suitable for real use. For an actual deployment see
[../docs/getting-started.md](../docs/getting-started.md).