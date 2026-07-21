# Linux endpoint collector

Bash sibling of the macOS and Windows collectors: same surfaces (cli, ide,
desktop, mcp), same finding schema, same receiver. Reads AI tool
configuration files from the developer's home directory to report which
account each tool is signed into. Runs as root and resolves the human user
itself, because RMM and cron jobs run as root, whose home is `/root` and
contains nothing worth scanning.

Which tools to look for is fetched from the receiver's `/registry/collector`
endpoint at runtime. Adding a new AI tool is a registry merge request, not a
change to this script.

## The one requirement

Something that can run this script as root on a schedule. There is no MDM
dependency and no Linux-specific management product required. Any of these
work:

- an RMM with a script/automation feature (Level, NinjaOne, Action1,
  Tactical RMM, and similar)
- a configuration-management tool: an Ansible cron or systemd-timer role,
  a Salt state, a Puppet resource
- plain `cron` or a `systemd` timer, if you manage the fleet by hand

Because the only assumption is "run as root on a schedule", Linux coverage
does not depend on your fleet living in any particular management tool.

## Configuration

Three environment variables:

```
AIGUARD_RECEIVER_BASE   receiver base URL, e.g. https://ai-guard.example.com
AIGUARD_TOKEN           receiver bearer token
AIGUARD_CORP_DOMAINS    comma-separated corporate domains, e.g. example.com,example.co.uk
```

Set `AIGUARD_CORP_DOMAINS` correctly: an empty value means no domain counts
as corporate, so every account reports as a personal-account warning.

If `AIGUARD_RECEIVER_BASE` is unset the script prints findings to stdout
instead of POSTing, which is the local-test mode.

## What it reports

| surface | example | account? |
|---------|---------|----------|
| cli     | Claude Code, Codex CLI, Gemini CLI | yes, from the tool's config file |
| ide     | AI extensions in VS Code, Cursor | no, presence only |
| desktop | AI apps and local runtimes like Ollama | no, presence only |
| mcp     | MCP servers wired into AI tool configs | no, lists server names |

Account findings report the domain only, never the mailbox local part.

## Reporting behaviour

Identical to the other collectors: warn findings (personal accounts) post
every run; info findings post at most once per 24 hours (state in
`/var/lib/ai-guard/`); a new tool or an account change posts immediately.
If the registry cannot be fetched or parsed the script exits non-zero and
reports nothing, on the principle that an empty scan is indistinguishable
from a clean machine.

## Deployment example: an RMM with environment variables

Most RMMs inject configured values as environment variables, in which case
the script runs unchanged: set the three `AIGUARD_*` variables in the tool,
schedule the script as root, and scope it to a device group.

## Deployment example: an RMM with template substitution

Some RMMs substitute configured values into the script text as templates
rather than exposing them as environment variables. In that case add a
short mapping header above the script so the substituted values become the
environment variables the collector expects:

```bash
#!/usr/bin/env bash
export AIGUARD_RECEIVER_BASE="{{AIGUARD_RECEIVER_BASE}}"
export AIGUARD_TOKEN="{{AIGUARD_TOKEN}}"
export AIGUARD_CORP_DOMAINS="{{AIGUARD_CORP_DOMAINS}}"
# ... collector body follows ...
```

Use your tool's own template syntax in place of `{{...}}`. Keep this header
out of version control, the same way you would keep a token out of it: the
committed script stays generic.

## Deployment example: cron or systemd timer

Drop the script somewhere root-owned, supply the variables from an
environment file, and schedule it:

```bash
# /etc/ai-guard.env  (root-only: chmod 600)
AIGUARD_RECEIVER_BASE=https://ai-guard.example.com
AIGUARD_TOKEN=...
AIGUARD_CORP_DOMAINS=example.com

# crontab (root): hourly
0 * * * * . /etc/ai-guard.env && /opt/ai-guard/ai-guard-collector.sh
```

## Pilot first

Scope to one machine before the fleet. After a run, check:

- `/var/lib/ai-guard/last_scan.txt` lists the expected tools with
  `[posted=N suppressed=N]` and no error lines
- findings arrive in the receiver's logs for that device with the `user`
  field populated (if `user` is empty, the home-directory resolution needs
  attention on that image; that is the failure mode to catch on one machine
  rather than across the fleet)

## Notes

- Requires `python3` for JSON parsing, which is present on essentially every
  developer machine. A dependency-free line-wise fallback covers the account
  fields if it is somehow absent.
- Resolves the human user as the non-root-owned directory under `/home`,
  skipping package caches like `linuxbrew`. This is written for
  single-user developer workstations; a shared multi-user host would want
  the resolution loop extended to scan every real home.
- Evidence strings use a literal `~` for the user's home so usernames never
  appear in evidence paths.