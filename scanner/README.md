# AI Guard scanner

Cloud and fleet scanners for the shadow-ai-guard platform, plus a
standalone MCP security scanner. This component answers two questions:

1. **What AI tools are people in my org actually using?** Discovers shadow
   AI usage by correlating data from Entra ID, SentinelOne, Exchange
   Online, Intune, and Jamf Pro.

2. **Should I allow or block this AI integration?** Evaluates MCP server
   definitions against a security risk framework aligned to the OWASP
   Agentic AI Top 10.

It runs two ways: as a CLI for ad hoc scans and reports, and as a
scheduled CronJob (via `entrypoint.py`) that posts findings to the
platform receiver, where they join endpoint and browser findings on the
shared dashboard.

## Detection layers

| Scanner | What it catches | API |
|---|---|---|
| **Entra ID** | SSO sign-ins to AI tools, service principals, OAuth consent grants | Microsoft Graph |
| **SentinelOne** | DNS lookups and network connections to AI service domains from managed endpoints | Deep Visibility |
| **Exchange** | Signup/verification emails from AI service sender domains | Microsoft Graph |
| **Intune** | AI desktop apps discovered on Windows devices | Microsoft Graph |
| **Jamf** | AI desktop apps installed on managed Macs | Jamf Pro API |
| **MCP scanner** | Security risk assessment of MCP server integrations | Static analysis |

Each layer catches what the others miss: Entra sees OAuth flows but not
native signups; SentinelOne sees all browsing to AI domains regardless of
auth method, which is the proxy replacement for fully remote
organisations; Exchange catches the signup trail even without SSO;
Intune and Jamf see installed software; the MCP scanner evaluates
integration risk before you approve or block.

Note the SentinelOne scanners use the Deep Visibility API, which
SentinelOne has deprecated in favour of SDL v2. It remains the working
option on MSSP consoles, where SDL v2 endpoints are not yet available.
If your console supports SDL v2 natively, expect to adapt the queries.

## Quick start

```bash
git clone https://github.com/AmanSK5/shadow-ai-guard.git
cd shadow-ai-guard/scanner

python3 -m venv .venv
source .venv/bin/activate

# Install with hash-verified dependencies (recommended)
make install
```

`make install` uses `--require-hashes` to verify every dependency against
the SHA256 hashes committed in `requirements.lock`. If a package has been
tampered with on PyPI, the install refuses to proceed. See Supply chain
security below.

### Run the MCP scanner (no API credentials needed)

```bash
ai-guard mcp-scan examples/atlassian-rovo.yaml
ai-guard mcp-scan examples/github-readonly.yaml
```

### Run shadow AI discovery

```bash
ai-guard init
```

This creates two files:
- `.env` for your API credentials (git-ignored, never committed)
- `policy.yaml` to enable scanners and set blocked/approved services

Fill in `.env` for the scanners you want (each section is optional):

```bash
AIGUARD_ENTRA_TENANT_ID=your-tenant-id
AIGUARD_ENTRA_CLIENT_ID=your-app-client-id
AIGUARD_ENTRA_CLIENT_SECRET=your-client-secret

AIGUARD_S1_BASE_URL=https://your-instance.sentinelone.net
AIGUARD_S1_API_TOKEN=your-api-token

AIGUARD_JAMF_BASE_URL=https://your-instance.jamfcloud.com
AIGUARD_JAMF_CLIENT_ID=your-client-id
AIGUARD_JAMF_CLIENT_SECRET=your-client-secret
```

Then:

```bash
ai-guard scan                          # all enabled scanners
ai-guard scan --scanner sentinelone    # one scanner
ai-guard scan --format json --output report.json
ai-guard scan --format csv --output report.csv
```

### Run as part of the platform

The container image (see `Dockerfile`) runs `entrypoint.py`, which
executes the enabled scanners on a schedule and posts findings to the
receiver instead of writing a report. Configuration arrives as
environment variables (receiver URL and token, corporate domain,
credentials from your Kubernetes Secret or secret store). The `.env`
mechanism is for local CLI use only; deployed scanners do not use it.

## Entra app registration

The Entra, Exchange and Intune scanners share one app registration.
Required Graph API application permissions:

| Permission | Used by | Purpose |
|---|---|---|
| `AuditLog.Read.All` | Entra | Read sign-in logs (requires Entra ID P1/P2) |
| `Application.Read.All` | Entra | List service principals and consent grants |
| `Mail.ReadBasic.All` | Exchange | Message metadata only, for signup email detection |
| `DeviceManagementApps.Read.All` | Intune | Read discovered apps inventory |
| `User.Read.All` | All | Enumerate users |

## Policy configuration

`policy.yaml` controls which scanners run and how findings classify:

```yaml
policy:
  lookback_days: 30
  risk_overrides:
    GitHub Copilot: low
  approved_services:
    - GitHub Copilot
  blocked_services:
    - DeepSeek
```

## Registry

The scanner reads `ai_guard/registry/ai_services.yaml`, a curated mapping
of AI services to their identifiers across every detection layer: DNS
domains, Entra app IDs, email sender domains, bundle IDs, extension IDs
and MCP connector names. The platform also has a top-level registry
(`registry/`) that drives the receiver, endpoint collectors and browser
extension; consolidating the two into one source is on the roadmap. Until
then, additions for cloud and network detection go in this file, and
additions for endpoint and browser detection go in the top-level
registry.

PRs welcome for new services: at minimum `name`, `vendor`, `category`,
`risk_tier` and `domains`. The more identifiers, the more layers match.

## MCP security scanner

`mcp-scan` evaluates MCP server definitions against these checks:

| Check | OWASP category | Flags |
|---|---|---|
| Write access | AG04 Excessive Agency | Tools that create, update or delete |
| Broad OAuth scopes | AG06 Insufficient Access Controls | `read:all`, `.readwrite`, `admin` |
| No authentication | AG01 Agentic Identity and Trust | Servers with no auth requirement |
| Bulk data ingestion | AG03 Prompt Injection via Agent Tools | Tools whose output becomes AI context |
| Large tool surface | AG04 Excessive Agency | Servers exposing 20+ tools |
| No tool filtering | AG06 Insufficient Access Controls | Everything exposed, no allow/block lists |

Verdict: **BLOCK**, **ALLOW WITH CONDITIONS**, or **ALLOW**.

## Supply chain security

A security tool with compromised dependencies would be ironic.

- `requirements.in` is the human-readable dependency list
- `requirements.lock` is the committed lockfile with exact versions and
  SHA256 hashes
- `make install` uses `--require-hashes` and fails on any mismatch
- `make lock` regenerates after changing requirements.in, preserving
  versions already pinned in the lockfile
- `make upgrade` regenerates allowing every package to move to its newest
  compatible version; this is the one that clears a CVE, `make lock` alone
  will not
- `make verify` confirms the installed set still matches
- both compile inside `python:3.12-slim` so the lock matches the interpreter
  the image ships, not whatever Python you happen to have

This protects against a compromised package version on PyPI and unpinned
transitive dependencies. It does not protect against a compromised
version being the one you pinned. CI scans for that weekly with Trivy;
`make audit` is the same check locally.

## Requirements

Python 3.10+, and API credentials for whichever scanners you enable.

## License

Apache-2.0
