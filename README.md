# shadow-ai-guard

> [!NOTE]
> **Alpha release.** Early-stage and under active development. It works, but
> has known limitations tracked in [Issues](../../issues).

Shadow AI detection across every surface it actually appears on: browser, CLI,
IDE, desktop, network and cloud. Built to run on infrastructure you already
have, for roughly the cost of nothing.

## Why this exists

No single commercial tool sees all of the places AI tools turn up. CASB and
DLP products see the browser. Endpoint tools see installed applications. Cloud
access tools see OAuth grants. None of them read `~/.claude.json` to tell you
which account your developers' AI CLIs are signed into, and the account is the
part that matters: an approved tool on a personal account is unmanaged data
flow, invisible spend, and an offboarding gap.

This project unifies detection across six surfaces with one finding schema,
one registry of known AI tools, and one dashboard. Adding a new AI tool to
detection is a merge request to a YAML file, not a script change on every
endpoint.

## Try it in five minutes

https://github.com/user-attachments/assets/f114e781-7053-4000-ba82-2b2d0fcc3e85

You don't need a Kubernetes cluster, an MDM, or any cloud logins to see what
this does. There's a demo that runs the real receiver and a real Grafana
dashboard against fake data, all in Docker:

```bash
git clone https://github.com/AmanSK5/shadow-ai-guard.git
cd shadow-ai-guard/demo
docker compose up
```

Then open **http://localhost:3000** and look at the **AI Guard - Shadow AI
Visibility** dashboard. It brings up Loki, the receiver (built from the real
Dockerfile in this repo), and a small seeder that posts example findings across
every surface and OS. That's so you land on a dashboard that's already full
instead of an empty one: who's running what, personal versus work accounts, a
breakdown per tool, and the MCP integrations people have wired up.

The demo uses `example.com` / `example.co.uk` as the work domains, plus made-up
device and user names. It only runs Loki, so a few of the Prometheus tiles are
left out. This isn't the full picture a real deployment gives you, but it's
enough to see how the thing works without setting anything up. The dashboard's
own header spells out what's different, and there's more detail in
[`demo/README.md`](demo/README.md).

Alongside the dashboard, the demo serves the browser paste guard at
http://localhost:8090/demo/: a stand-in AI prompt box running the
extension's real, unmodified `guard.js`, with copyable test vectors on the
page. Paste a fake AWS key or a payment card number and watch it get
stopped before it reaches the page; the panel underneath shows the exact
report that would be sent, which never contains what you pasted.

https://github.com/user-attachments/assets/16dd7857-935b-40c8-ad73-524b30271ec7

When you want to run it for real, start with
[docs/getting-started.md](docs/getting-started.md).

## Documentation

Everything is under `docs/` and the component folders. Start here rather than
digging through subfolders.

**Getting it running**
- [Getting started](docs/getting-started.md) - clone to your first finding on
  a dashboard, the minimum viable deployment
- [Architecture](docs/architecture.md) - the mental model: the finding schema,
  and why the pieces are shaped this way
- [Receiver](receiver/README.md) - the one service everything reports to: every variable and endpoint, plus an example deployment to adapt

**Deploying each surface**
- [macOS endpoint collector](endpoint/macos/README.md) - via Jamf
- [Windows endpoint collector](endpoint/windows/README.md) - via Intune
- [Linux endpoint collector](endpoint/linux/README.md) - via any RMM, cron,
  or config management
- [Browser extension](extension/README.md) - the browser surface
- [Cloud and network scanners](scanner/README.md) - Entra, Exchange, Intune,
  Jamf, SentinelOne, and the MCP security scanner

**Extending and operating**
- [Writing a scanner](docs/writing-a-scanner.md) - add a new detection source
  by emitting the finding schema
- [Security model](SECURITY.md) - the trust model, stated plainly
- [Privacy and DPIA guidance](docs/deployment-privacy.md) - read before
  deploying; this is workplace monitoring and usually warrants a DPIA

---

## How it works

```
browser extension ─┐
macOS collector  ──┤
Windows collector ─┼──► receiver ──► logs (Loki) ──► Grafana dashboard
Linux collector  ──┤       │
cloud scanners  ───┤       └──────► Alertmanager ──► alerts (personal accounts)
network scanner ───┘       ▲
        registry (YAML, MR-reviewed) ── served to collectors at runtime
```

- **receiver** - FastAPI service. Accepts findings, logs them as structured
  JSON, fires alerts for personal accounts, serves the registry to collectors.
- **registry** - the source of truth for what counts as an AI tool: domains,
  extension IDs, config file paths, approval status. Schema-validated in CI.
  Collectors fetch their identifier lists from the receiver at runtime, so a
  new tool needs no endpoint changes.
- **scanner** - cloud and fleet scanners: Entra ID sign-ins, Exchange signup
  email evidence, Intune and Jamf software inventory, SentinelOne DNS
  telemetry for network-level detection including local process bridges.
  Each module is optional; run the ones your estate supports.
- **endpoint** - collectors for macOS (Jamf, bash), Windows (Intune,
  PowerShell), and Linux (any RMM, cron, or config management). These read AI
  tool config files to report which account each tool is signed into. This is
  the data no API-level product has.
- **discovery** - weekly job that classifies unrecognised AI-looking domains
  from DNS telemetry and proposes registry additions as merge requests. A
  human approves every change.
- **dashboards** - Grafana dashboard over Loki. Set your corporate domains in
  the dashboard variable and personal accounts light up red.

The discovery job currently opens GitLab merge requests; a GitHub backend is
on the roadmap.

## Finding schema

Every source uses this same shape. Any new scanner or collector that emits
it works with everything downstream:

```json
{
  "tool": "claude-code",
  "surface": "cli",
  "os": "macos",
  "account_domain": "gmail.com",
  "device": "SERIAL123",
  "user": "aman.test",
  "evidence": "~/.claude.json",
  "severity": "warn",
  "reported_at": "2026-01-01T09:00:00Z",
  "source": "collector-macos"
}
```

`severity` is `warn` when the account domain is not one of your corporate
domains, `info` otherwise. The `user` field carries an account name so a
finding can be followed up with the right person; see
[privacy](docs/deployment-privacy.md) for exactly when it is populated.

## What you need

- A Kubernetes cluster for the receiver and scanner CronJobs. Anything
  conformant works; nothing in the core is cloud-specific.
- A log pipeline that ingests container stdout. The provided dashboard
  assumes Loki, but the receiver's only output is JSON lines.
- Grafana for the dashboard, Alertmanager for alerting (optional).
- At least one detection source per surface you care about. Currently
  supported: Microsoft Graph (Entra, Exchange, Intune), Jamf Pro,
  SentinelOne, Chrome/Edge managed extension policy, and endpoint collectors
  for macOS, Windows and Linux.
- Secrets for whichever sources you enable. Local development uses a
  `.env` (see `scanner/README.md`); deployed scanners read from Kubernetes
  Secrets or your secret store.

Prebuilt images are published to GHCR by CI. A Helm chart is in progress;
until then, the receiver is a Deployment with the registry ConfigMap mounted
at `/etc/ai-guard`, and the scanners are CronJobs. See each component's
README for specifics.

## Deployment order

1. Deploy the receiver, create its bearer token Secret, expose it on an
   ingress endpoints can reach.
2. Publish the registry: `python registry/build.py`, then load
   `registry/dist/registry.json` and `registry/dist/collector.json` into the
   ConfigMap the receiver mounts.
3. Enable the scanners your estate supports and schedule them.
4. Roll out the endpoint collectors through your MDM or RMM. Pilot on one
   machine first; the deployment notes in `endpoint/*/README.md` are written
   from doing exactly that.
5. Import the dashboard, set the corporate domains variable.

New here? [docs/getting-started.md](docs/getting-started.md) walks this
through end to end for a minimum deployment.

## Status and known limitations

This is an alpha, released early on purpose. It runs in production in one
environment, and the rough edges are labelled rather than hidden. The list
has changed since the first release: the registry fallback drift and the
Entra scanner counting failed sign-ins as usage are fixed and tested. The
current ones:

- **Browser extensions as a detection target.** The registry carries Chrome
  and Edge extension IDs for tools like Grammarly and Perplexity, and the
  matching code exists, but no collector reads browser profiles yet, so
  nothing produces those findings. An AI extension reads every page without
  anyone pasting a thing, and today only DNS traffic hints at one. This is
  the biggest known coverage gap.
- **Non-interactive sign-ins.** The Entra scanner sees interactive sign-ins
  only. Silent token refreshes, which are most of the volume, are invisible
  to it ([#23](https://github.com/AmanSK5/shadow-ai-guard/issues/23)).
  Sign-in findings are a floor, not a count.
- **The Windows delivery path.** The Linux collector is driven end to end in
  CI and the macOS path has been run on a fresh cluster; the Windows
  collector has had the least real-world running. Pilot on one machine
  first.

Treat findings as leads to follow up, not verdicts. If you hit something
wrong or missing, an issue with the finding JSON and what you expected is
genuinely useful.

## Governance notes

The registry ships with every tool set to `approved: false`. Approval is your
organisation's decision, not this project's default. The discovery job
proposes additions; it never merges them. If you operate under ISO 42001 or
similar, the registry doubles as your maintained inventory of AI systems in
use, and the dashboard as its evidence.

Before deploying, read docs/deployment-privacy.md: this is workplace
monitoring in most jurisdictions and usually warrants a DPIA.

## Security model

See SECURITY.md. Short version: one bearer token shared by reporting sources,
rate-limited public ingest, findings carry usernames and device identifiers
so treat your log store as sensitive, and endpoint collectors run as
root/SYSTEM via your MDM or RMM, so review them like anything else you push
that way.

## License

Apache-2.0.