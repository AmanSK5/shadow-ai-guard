# Local demo

See the platform work with synthetic data in about five minutes. No cluster,
no credentials, no real estate touched. Everything here is fake: demo users
are named after Pokemon, findings are seeded locally.

## Run it

From the repository root:

```bash
cd demo
docker compose up
```

Then open http://localhost:3000 and look at the "Shadow AI" dashboard. It
opens with no login (anonymous access is on for the demo only).

Personal-versus-work colouring works out of the box: the dashboard's
corporate domains variable ships with the demo's domains
(`example\.com|example\.co\.uk`) as its default, so example.com accounts
show as corporate and gmail.com / outlook.com as personal with no steps.
In a real deployment that same variable is what you point at your own
domains.

Stop and wipe everything:

```bash
docker compose down -v
```

## What is running

Four containers:

- **loki** - the log store, where findings land
- **receiver** - the real receiver, built from `../receiver`, pushing every
  finding straight to Loki (no scraping sidecar needed)
- **grafana** - pre-provisioned with the Loki datasource and the project
  dashboard, so it is populated on load with nothing to import
- **seeder** - posts a spread of synthetic findings once the receiver is
  healthy, then exits

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
