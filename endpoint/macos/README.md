# macOS endpoint collector

Reads AI tool configuration files from the console user's home directory and
reports which account each tool is signed into, plus installed IDE
extensions, AI desktop apps, local runtimes and MCP server configurations.
Runs as root via your MDM; resolves the logged-in console user itself.

Which tools to look for is fetched from the receiver's `/registry/collector`
endpoint at runtime. Adding a new AI tool is a registry merge request, not a
change to this script.

**EDR note:** the collector runs as root, reads files in user home directories,
and POSTs data to an external URL. EDR tools may flag this as suspicious; add
an allowlist entry for the script path and the receiver URL if needed.

## What it reports

| surface | example | account? |
|---------|---------|----------|
| cli     | Claude Code, Codex CLI, Gemini CLI | yes, from the tool's config file |
| ide     | AI extensions in VS Code, Cursor, JetBrains | no, presence only |
| browser | AI extensions in Chrome, Brave, Edge | no, presence only |
| desktop | AI apps in /Applications, local runtimes like Ollama | no, presence only |
| mcp     | MCP servers wired into AI tool configs | no, lists server names |

Account findings carry the domain in `account_domain` and the console
username in `user`. An account on a domain outside your corporate list
reports as `warn`; everything else is `info`.

## Reporting behaviour

- `warn` findings (personal accounts) report at most once per hour. A
  personal account is a persistent state rather than an event, so repeating
  it at every check-in adds volume without adding information.
- `info` findings report at most once per 24 hours. State for both is kept in
  `/Library/Application Support/ai-guard/`, so you can schedule the policy
  frequently without flooding your logs. A new tool or an account change is a
  new key and reports immediately at either severity.
- If the registry cannot be fetched or parsed, the script exits 1 and reports
  nothing, on the principle that an empty scan is indistinguishable from a
  clean machine. The failure is visible in the policy log and as a failed
  policy run.

## Jamf deployment

1. **Script object**: add `ai-guard-collector.sh` as a script in Jamf
   (Settings, Computer Management, Scripts). No edits to the file are needed;
   configuration arrives as script parameters.

2. **Policy**: create a policy running the script with:
   - Parameter 4: receiver base URL, e.g. `https://ai-guard.example.com`
   - Parameter 5: the receiver bearer token
   - Parameter 6: corporate domains, comma-separated, e.g.
     `example.com,example.co.uk`. Leave this correct: an empty value means no
     domain counts as corporate and every account warns.
   - Trigger: Recurring Check-in, plus a custom trigger (e.g. `aiguard`) so
     you can run it on demand with `sudo jamf policy -event aiguard`.
   - Frequency: Ongoing. The 24 hour throttle above keeps the volume sane.

3. **Pilot on one machine first.** Scope the policy to a single Mac, run it,
   and check:
   - the policy log shows no `[ai-guard]` error lines
   - `/Library/Application Support/ai-guard/last_scan.txt` lists the tools
     you expect with `[posted=N suppressed=N]`
   - findings arrive in the receiver's logs for that device serial

   Then widen scope. Every deployment of this collector has found something
   on first contact with a real machine; give yourself the chance to see it
   on one machine instead of fifty.

4. Optional: a Jamf Extension Attribute that reads `last_scan.txt` gives you
   per-device scan status in inventory.

## Local testing

Run against a checked-out registry without a receiver:

```bash
AIGUARD_REGISTRY_FILE=registry/dist/collector.json sudo ./ai-guard-collector.sh
```

With no receiver URL set, findings print to stdout instead of POSTing.

To run directly against a live receiver, pass the same values the Jamf
policy would, as positional arguments. Jamf reserves parameters 1 to 3, so
the script reads from `$4` onward; fill the first three with placeholders:

```bash
sudo ./ai-guard-collector.sh _ _ _ \
  "https://ai-guard.example.com" "$TOKEN" "example.com,example.co.uk"
```

## Notes

- The script targets the console user's home, not root's, because it runs as
  root and the interesting files are the user's. Machines with no logged-in
  user skip cleanly.
- macOS ships bash 3.2; the script is written for it. No jq or python
  dependency; JSON parsing uses JXA (osascript), which is always present.
- Evidence strings use a literal `~` for the user's home so usernames never
  appear in evidence paths.