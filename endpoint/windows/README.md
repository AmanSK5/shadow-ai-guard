# Windows endpoint collector

PowerShell sibling of the macOS collector: same surfaces (cli, ide,
browser, desktop, mcp), same finding schema, same receiver. Reads AI tool
configuration files from the logged-on user's profile to report which
account each tool is signed into. Runs as SYSTEM via Intune and resolves
the logged-on user itself (owner of explorer.exe, with a most-recent
profile fallback), because SYSTEM's own profile contains nothing worth
scanning.

Which tools to look for is fetched from the receiver's
`/registry/collector` endpoint at runtime. Adding a new AI tool is a
registry merge request, not a script edit plus an Intune re-paste.

**EDR note:** the collector runs as SYSTEM, reads files in user home
directories, and POSTs data to an external URL. EDR tools may flag this as
suspicious; add an allowlist entry for the script and the receiver URL if
needed.

## Configuration

Intune platform scripts take no parameters, so configuration lives in
three variables at the top of the script. Set them before upload:

```powershell
$ReceiverBase     = 'https://ai-guard.example.com'   # your receiver ingest URL
$Token            = '__RECEIVER_TOKEN__'             # replace with the bearer token
$CorporateDomains = @('example.com')                 # accounts here are work; others warn
```

Keep the token inside single quotes (literal in PowerShell, so `$` in a
token cannot expand). Commit only the placeholder version; the tokenised copy 
exists only inside Intune. CI fails the build if the placeholder is missing, 
so a tokenised copy cannot reach main by accident.

If the receiver has `CORP_DOMAINS` set, its list overrides `$CorporateDomains`
at runtime, so the fleet follows a receiver-side change without an Intune
re-paste.

`$Token` can also be an enrollment token (`aige_...`) from a managed-mode
receiver: the machine then enrolls itself on first run, stores its own device
credential in `C:\ProgramData\ai-guard` (ACL-restricted to SYSTEM and
Administrators), and can be revoked individually from then on. Swapping the
constant is the whole migration.

## Trying it against a local receiver

No Intune needed. Edit the three variables at the top of the script, then run
it from an elevated PowerShell:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\ai-guard-collector.ps1
```

With `$ReceiverBase = 'http://localhost:8080'` and `$Token = 'demo-token'` it
reports to the demo in `demo/`, so `docker compose up` there gives you
somewhere for the findings to land.

Set `$CorporateDomains` to something that is not yours and your own accounts
show up as personal findings, which is the quickest way to see exactly what
the collector reports about you.

Leaving `$ReceiverBase` empty prints findings to the console instead of
POSTing them. Put the placeholder token back before committing: CI fails the
build if it is missing.

## Intune deployment

Deployed as a **Platform script** (Devices, Scripts and remediations,
Platform scripts), not a Proactive Remediation. Remediations offer
scheduled re-runs and console status but require Windows E3/E5 or the
Intune Suite remediations add-on; platform scripts need no extra
licensing, and the receiver is the reporting layer anyway.

Settings:
- Run this script using the logged on credentials: **No** (runs as SYSTEM)
- Enforce script signature check: **No** (unless you sign it)
- Run script in 64 bit PowerShell Host: **Yes**

Consequences of the platform-script model worth knowing:
- Scripts run at assignment and device check-in, then re-run when the
  script content changes. There is no tight recurring schedule, so
  Windows reports less frequently than a Jamf-scheduled Mac. If you have
  the Remediations entitlement, the same script works there and gains
  scheduling; alternatively have the script register a daily Scheduled
  Task (roadmap).
- No native per-device status in the Intune console. The collector's
  breadcrumb (`C:\ProgramData\ai-guard\last_scan.txt`) and the dashboard
  fill that role.

## Pilot first

Scope the script to one Windows device before the fleet. On that machine
after a sync, check:

- `C:\ProgramData\ai-guard\last_scan.txt` lists the expected tools with
  `[posted=N suppressed=N]` and no `PARSE-FAILED` marker
- findings arrive in the receiver's logs for that device with the `user`
  field populated (if `user` is empty, identity resolution needs
  attention on your image; that is the failure mode to catch on one
  machine instead of fifty)

## Reporting behaviour

Identical to macOS: warn findings post at most once per hour, info findings
at most once per 24 hours, state in C:\ProgramData\ai-guard\. A new tool or
an account change reports immediately at either severity.

One Windows-specific note: some AI tool config files cannot be parsed
whole (Claude Code stores per-project state whose keys differ only in
drive-letter casing, which .NET's JSON parser rejects as duplicates). The
collector therefore extracts only the fields it needs, line-wise, instead
of whole-file parsing. If you extend it, keep that pattern.