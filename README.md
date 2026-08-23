<a id="top"></a>

<p align="center">
  <img
    src="assets/shadow-ai-guard-title.png"
    alt="Shadow AI Guard"
    width="650"
  />
</p>

<hr>
<p align="center">
  <strong>See the AI your organisation is actually using.</strong><br>
  Browser. CLI. IDE. Desktop. Network. Cloud. MCP.
</p>

<p align="center">
  <a href="docs/getting-started.md"><strong>Get started</strong></a> ·
  <a href="#try-it-in-five-minutes"><strong>Run the demo</strong></a> ·
  <a href="#documentation"><strong>Read the docs</strong></a>
</p>

> [!NOTE]
> **Alpha release.** Early-stage and under active development. It works, but
> has known limitations tracked in [Issues](../../issues).

---

<p align="center">
  <img
    src="assets/Shadow-AI-Guard-Portal.png"
    alt="Shadow AI Guard Setup"
    width="100%"
  />
</p>

> **Know what you can see, and what you can't.** Shadow AI Guard shows which detection sources are reporting, which are silent, and where your current visibility gaps are.

Shadow AI Guard detects AI usage across the places it actually appears, then
correlates the findings so you can see the tools, accounts, users, devices and
sources behind it.

It is self-hosted and free. If you already run Docker or Kubernetes and a log
stack, you have everything it needs. There is no SaaS platform behind it and
nothing leaves your infrastructure.

## Contents

<p align="center">
  <a href="#why-this-exists">Why this exists</a> ·
  <a href="#what-it-sees">What it sees</a> ·
  <a href="#know-your-coverage">Coverage</a> ·
  <a href="#try-it-in-five-minutes">Try it</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#documentation">Documentation</a>
  <br>
  <a href="#what-you-need">Requirements</a> ·
  <a href="#deployment-order">Deployment</a> ·
  <a href="#finding-schema">Finding schema</a> ·
  <a href="#governance">Governance</a> ·
  <a href="#status-and-known-limitations">Limitations</a> ·
  <a href="#security-model">Security</a>
</p>

## Why this exists

No single commercial tool sees all of the places AI tools turn up. CASB and
DLP products see the browser. Endpoint tools see installed applications. Cloud
access tools see OAuth grants.

None of them read `~/.claude.json` to tell you which account your developers'
AI CLIs are signed into.

The account is the part that matters: an approved tool on a personal account is
still unmanaged data flow, invisible spend and an offboarding gap.

Shadow AI Guard brings those signals together across seven detection surfaces with
one finding schema and one registry of known AI tools.

The same findings can then be explored in two different ways:

- **Portal**: people, devices, tools, identity relationships and source health.
- **Grafana**: telemetry, trends, counts and time-series analysis.

Adding a new AI tool to detection is a merge request to a YAML file, not a
script change on every endpoint.

## What it sees

| Surface | What Shadow AI Guard can observe |
|---|---|
| **Browser** | AI websites, managed extensions, account domains and Paste Guard events |
| **CLI** | Local AI tooling and the account it is signed into |
| **IDE** | AI coding extensions and integrations |
| **Desktop** | Installed AI applications and local configuration |
| **Network** | AI domains and local process attribution through SentinelOne |
| **Cloud** | Entra sign-ins, delegated access, OAuth grants, Exchange evidence, Intune and Jamf |
| **MCP** | MCP servers and security findings |

Every source emits the same finding shape, so new scanners and collectors plug
into the same downstream pipeline.

## Know your coverage

A source that reports nothing might be clean, or it might be broken. Those look
identical on a dashboard, so the portal tells you the difference: which
detection sources are reporting, which are set up but silent, and which you
have not enabled yet.

From the same findings, the portal also answers questions that are hard to get
out of a flat log stream:

- which tools a device has
- which devices a person uses
- which accounts are personal or corporate
- which sources observed a tool
- which expected sources are not reporting

The portal does not replace Grafana. Grafana is better at graphs and historical
analysis; the portal is better at relationships and current state.

## Try it in five minutes

You do not need a Kubernetes cluster, an MDM, or any cloud credentials to see
what the project does.

The demo runs the real receiver, portal, Loki and Grafana against synthetic
data:

```bash
git clone https://github.com/AmanSK5/shadow-ai-guard.git
cd shadow-ai-guard/demo
docker compose up
```

Then open:

- **Shadow AI Guard Portal:** http://localhost:8091
- **Grafana:** http://localhost:3000
- **Paste Guard demo:** http://localhost:8090/demo/

The seeder posts fake findings across every surface and OS so you do not land
on an empty install. It uses `example.com` / `example.co.uk`, made-up users and
made-up devices.

### Portal

Use the portal to explore people, devices, tools, source health and the
relationships between them.

https://github.com/user-attachments/assets/a50191d2-c6c3-48d4-a383-59ab22d39afa

### Grafana

Grafana is the deeper telemetry view: usage over time, personal versus work
accounts, per-tool breakdowns and MCP findings.

https://github.com/user-attachments/assets/f114e781-7053-4000-ba82-2b2d0fcc3e85

### Paste Guard

The demo also serves a stand-in AI prompt box running the browser extension's
real, unmodified `guard.js`.

Paste a fake AWS key or payment card number and watch it get stopped before it
reaches the page. The panel underneath shows the report that would have been
sent, which never contains what you pasted.

https://github.com/user-attachments/assets/16dd7857-935b-40c8-ad73-524b30271ec7

When you want to run it for real, start with
[docs/getting-started.md](docs/getting-started.md).

---

<p align="right"><a href="#top">Back to top ↑</a></p>

## How it works

```text
browser extension ─┐
macOS collector  ──┤
Windows collector ─┤
Linux collector  ──┼──► receiver ──► logs (Loki) ──┬──► portal
cloud scanners  ───┤       │                       │
network scanner ───┤       │                       └──► Grafana
MCP scanner ───────┘       │
                           └──────► Alertmanager ──► alerts
                             ▲
                             │
             registry (YAML, MR-reviewed)
```

- **receiver**: FastAPI service. Accepts findings, logs them as structured
  JSON, fires alerts for personal accounts, and serves the registry to
  collectors.
- **registry**: the source of truth for what counts as an AI tool: domains,
  extension IDs, config file paths and approval status. It is schema-validated
  in CI. Collectors fetch their identifier lists from the receiver at runtime,
  so adding a tool does not require endpoint code changes.
- **scanner**: cloud and fleet scanners for Entra ID sign-ins, Exchange signup
  evidence, Intune and Jamf software inventory, SentinelOne DNS telemetry and
  MCP security checks. Each module is optional; run the ones your estate
  supports.
- **endpoint**: collectors for macOS, Windows and Linux. These read local AI
  tool configuration to report which account each tool is signed into. This is
  the data most API-level products do not have.
- **discovery**: a scheduled job that looks at your fleet's DNS activity,
  filters out domains the registry already knows, and asks an LLM whether the
  rest look like AI services. Anything that does shows up in the portal's
  review queue as "new AI tool found on N devices". You then add it to the
  registry with one click, or dismiss it. Nothing is detected until a person
  decides. The portal generates a ready-to-apply CronJob for it. (If you set
  the GitLab variables it opens merge requests against the registry instead.)
- **portal**: the governance and relationship view. Findings arrive as isolated
  events; the portal correlates them into people, devices, tools and
  detection-source health. It reads from Loki, holds no database and is not in
  the ingest path, so collection carries on if it falls over.
- **Grafana**: the analytics view over Loki. Better suited to historical
  analysis, trends, counts and drilling into the underlying telemetry. Grafana
  panels can also be embedded into the portal.
- **Alertmanager**: optional alerting for findings such as personal-account use.

<p align="right"><a href="#top">Back to top ↑</a></p>

## Documentation

The root README is the front door. The detailed setup and operating guidance
lives under `docs/` and the component folders.

| I want to... | Start here |
|---|---|
| Try it without company infrastructure | [Testing guide](TESTING.md) |
| Deploy it | [Deployment](docs/deployment/README.md) |
| Go from zero to first finding | [Getting started](docs/getting-started.md) |
| Understand the architecture | [Architecture](docs/architecture.md) |
| Configure the receiver | [Receiver](receiver/README.md) |
| Configure the portal | [Portal](portal/README.md) |
| Record approvals, owners and review dates | [Governance decisions](docs/governance.md) |
| Produce evidence for an AI management system | [Evidence](docs/evidence.md) |
| Deploy macOS collection | [macOS collector](endpoint/macos/README.md) |
| Deploy Windows collection | [Windows collector](endpoint/windows/README.md) |
| Deploy Linux collection | [Linux collector](endpoint/linux/README.md) |
| Deploy the browser extension | [Browser extension](extension/README.md) |
| Configure cloud and network scanners | [Scanner docs](scanner/README.md) |
| Write another scanner | [Writing a scanner](docs/writing-a-scanner.md) |
| Review the trust model | [Security model](SECURITY.md) |
| Assess privacy impact | [Privacy and DPIA guidance](docs/deployment-privacy.md) |
| Something isn't working | [Troubleshooting](TROUBLESHOOTING.md) |

## What you need

- **Somewhere to run two containers.** A host with Docker Compose or a
  Kubernetes cluster. The receiver is stateless and the portal is separate, so
  Kubernetes is supported but not required.
- A log pipeline that ingests container stdout. The supplied dashboard and
  portal assume Loki, but the receiver itself emits structured JSON lines.
- Grafana if you want the analytics dashboard. Optional.
- Alertmanager if you want alerting. Optional.
- At least one detection source for the surfaces you care about. Currently
  supported: Microsoft Graph (Entra, Exchange, Intune), Jamf Pro, SentinelOne,
  Chrome/Edge managed extension policy, and endpoint collectors for macOS,
  Windows and Linux.
- Credentials for whichever sources you enable. Kubernetes Secrets on that
  route; files on disk on the Compose route.

Prebuilt multi-arch images are published to GHCR by CI, so nothing needs
building. Scanners run as scheduled jobs: CronJobs on Kubernetes, or anything
that can run a container on a schedule.

## Two ways to run it

**Managed (the default).** You install it once, log into the portal, and do
everything else there: connect the log store, set your corporate domains,
approve tools, add new tools to detection, enroll and revoke devices, and
download pre-configured deployment files for every surface. You never need to
touch this repository again after the install.

**Classic (`managed.enabled=false`, or the compose classic overlay).** For
teams that would rather manage everything as files in their own repo. Every
setting is a file or an environment variable: `governance.yaml` for approval
decisions, `registry/registry.yaml` for what gets detected, `CORP_DOMAINS`
and friends for config. The receiver keeps no state at all, so there is
nothing to back up and nothing to lose. Changes go through your normal merge
request review, which some teams prefer as their audit trail.

Both modes are the same codebase and the same finding schema. Managed is
classic plus a small state database, not a fork. If you are not sure which
you want, start with managed.

## Deployment order

In managed mode (the default) the whole install is one command plus the
portal:

```bash
helm install ai-guard oci://ghcr.io/amansk5/shadow-ai-guard/charts/ai-guard \
  --namespace ai-guard --create-namespace \
  --set ingress.enabled=true --set ingress.host=ai-guard.your.domain \
  --set portal.ingress.enabled=true --set portal.ingress.host=ai-guard-portal.your.domain
```

Then:

1. Get the one-time setup code from the receiver's log:
   `kubectl logs deploy/ai-guard -n ai-guard | grep setup`
2. Open the portal, create your admin account with that code.
3. Follow the first-run wizard. It walks you through the log store, your
   corporate domains, tool approvals, and gives you pre-configured downloads
   for the collectors, the browser extension and the scanners.

Docker Compose works the same way: `docker compose up` in `deploy/compose/`,
then the same setup code and wizard. Details for both are in
[Kubernetes](docs/deployment/kubernetes.md) and
[Compose](deploy/compose/README.md).

In classic mode, or by hand:

1. Deploy the receiver and publish the registry:
   [Docker Compose](deploy/compose/README.md) or
   [Kubernetes](docs/deployment/kubernetes.md).
2. Roll out one endpoint collector through your MDM or RMM, or run the script
   directly. Pilot on one machine first.
3. Open the portal and confirm what is reporting. Add Grafana if you want deeper
   telemetry and historical analysis.
4. Enable the scanners your estate supports and schedule them.
5. Add the browser extension by managed policy.

New here? [docs/getting-started.md](docs/getting-started.md) walks through the
deployment end to end.

<p align="right"><a href="#top">Back to top ↑</a></p>

## Finding schema

Every source uses the same shape. Any scanner or collector that emits it works
with everything downstream.

```json
{
  "tool": "claude-code",
  "surface": "cli",
  "os": "macos",
  "account_domain": "gmail.com",
  "device": "SERIAL123",
  "device_name": "ASK-SERIAL123",
  "user": "aman.test",
  "evidence": "~/.claude.json",
  "severity": "warn",
  "reported_at": "2026-01-01T09:00:00Z",
  "source": "collector-macos"
}
```

`severity` is `warn` when the account domain is not one of your corporate
domains, and `info` otherwise.

The `user` field carries an account name where the source can provide one, so a
finding can be followed up with the right person. See
[privacy](docs/deployment-privacy.md) for exactly when it is populated.

`device` carries the most stable identifier the source can obtain, usually a
hardware serial, because that is what Jamf, Intune, SentinelOne and most RMMs
key on. `device_name` carries the hostname, which is what a human recognises and
what a platform with no serial can still join on.

## Governance

The registry ships with every tool set to `approved: false`.

Approval is your organisation's decision, not this project's default. Discovery
can propose new tools; it never approves them automatically.

The findings, registry and portal can provide evidence for an AI management
system such as ISO/IEC 42001: what tools have been observed, where they were
seen, which accounts are being used and whether a tool has been approved.

Shadow AI Guard does **not** determine ISO/IEC 42001 compliance. Organisational
controls, risk decisions, policies, training, management review and other
evidence still require human ownership.

Before deploying, read
[docs/deployment-privacy.md](docs/deployment-privacy.md). This is workplace
monitoring in most jurisdictions and usually warrants a DPIA.

## Status and known limitations

This is an alpha. It runs in production in one environment, and the rough
edges are listed here rather than hidden.

The list keeps shrinking: registry fallback drift, the Entra scanner counting
failed sign-ins as usage, unreported delegated access, and browser extension
inventory have all been fixed and tested since the first release.

Current known limitations:

- **Snap Chromium profiles.** The collectors inventory installed browser
  extensions from Chrome, Chromium, Brave and Edge profiles, but snap Chromium
  on Linux keeps its profile under `~/snap` and is not read, so an AI extension
  there is invisible.
- **Sign-in coverage.** The Entra sign-in scan reads interactive sign-ins only.
  Non-interactive ones are covered separately as delegated access findings:
  one per user and app per day, carrying the OAuth scopes the app is using.
  Service principal and managed identity sign-ins are not read as usage; the
  service principal and consent scans show that a grant exists, not that
  anything is using it. The delegated access query needs the Graph beta
  endpoint because the `signInEventTypes` filter is not available on v1.0.
- **The Windows delivery path.** The Linux collector is driven end to end in CI
  and the macOS path has been run on a fresh cluster; the Windows collector has
  had the least real-world running. Pilot on one machine first.

> [!IMPORTANT]
> Treat findings as leads to follow up, not verdicts.

If you hit something wrong or missing, an issue with the finding JSON and what
you expected is genuinely useful.

<p align="right"><a href="#top">Back to top ↑</a></p>

## Security model

See [SECURITY.md](SECURITY.md).

Short version: reporting sources use a shared bearer token; public ingest should
be rate-limited; findings can carry usernames, account domains, device
identifiers and hostnames, so treat the log store and portal as sensitive; and
endpoint collectors run as root/SYSTEM through your MDM or RMM, so review them
like anything else you deploy at that privilege level.

<p align="right"><a href="#top">Back to top ↑</a></p>

## License

Shadow AI Guard is free and open source under Apache-2.0. Others may
legitimately charge for hosting, deployment, support or managed services, but
the software itself can always be obtained from this repository for free.
Before buying anything based on it, check what is actually being provided
beyond the code.

See [TRADEMARKS.md](TRADEMARKS.md) for how the project name may be used.
