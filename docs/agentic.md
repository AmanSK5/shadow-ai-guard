# What runs without a person

Every other view in this portal starts from something somebody did. Somebody
signed in, somebody installed a tool, somebody pasted into a chat box. This
one starts from the absence of that.

A tool that begins on a timer, holds a credential no human signs into, and
reaches whatever it was pointed at while nobody is watching is a different
governance problem from a person using an assistant. Revoking somebody's
single sign-on stops the second and does nothing at all to the first.

The page answers two questions, and refuses several others.

## The two questions

**What is acting without a person.** Something on the machine starts an AI
tool on a schedule or a trigger, and nobody is present while it runs.

**What it can reach once it is running.** Configuring an MCP server hands a
model a capability. That capability is the blast radius of anything holding
the credential.

## The four signals

None of them require a new source. Three are read by the endpoint collectors
you already deploy, and one has been arriving for as long as the network
scanner has been configured.

### A scheduler starts it

The collectors read what schedules things on each platform: launchd on macOS,
systemd timers and cron on Linux, Scheduled Tasks on Windows. A job qualifies
when the command it runs names a binary the registry already lists for a
tool, so covering a new tool is a registry entry rather than a change to
three scripts.

Matching is deliberately word-ish: `claude` must not match
`claudeless-backup`, and each platform has a fixture asserting it does not.

### The credential has nobody behind it

Three states a collector can tell apart, where two of them used to arrive as
the same blank:

| What was found | Means |
|---|---|
| An account file with an account in it | a person |
| An account file with **no** account in it | a key that authenticates, with nobody behind it |
| A config directory and no account file | installed, never signed into |

The middle row is the one that matters. An API key in a unit file belongs to
no joiner and no leaver, so offboarding does not touch it. The collector
always knew which of the three it had seen; until recently it had no way to
say.

### Something reaches a model that is not a browser or a known tool

The network scan already records which process resolved a domain, and that
has been sitting in evidence text unread:

```
DNS lookup for api.anthropic.com (via python3)
```

A process reaching a model that is neither a browser nor a binary the
registry knows is a script with a key in it. There is no config file to
find, no MCP server, nothing installed to inventory - so this is the case
nothing else in an estate would surface, and it needs no collector change at
all.

Browsers are excluded because a person using a model in a browser is the
ordinary case every other page already covers. Known binaries are excluded
because the tool is then the finding rather than a mystery.

### An MCP server is configured

Read from the client config files the collectors already parse. What each
server can *do* is not yet assessed - see [what is not built](#what-is-not-built-yet).

## The day, as configured

Where a scheduler gives a cadence, the page draws it across a day. Four kinds
of lane, because four different things are true and only one of them is
"marks at these times":

| Lane | Means |
|---|---|
| marks | discrete runs at known times |
| band | often enough that individual ticks stop meaning anything |
| unphased | a known interval with no known start |
| continuous | no cadence at all; runs while somebody is logged in |

`unphased` exists because launchd's `StartInterval` counts from whenever the
job was loaded. The gaps between runs are true; the clock positions are not,
and the lane says so rather than implying four tidy times.

**A spec is what something is set to do, not what it was seen doing.** The
panel is titled "as configured" for that reason. Watching runs actually
happen needs process telemetry, which is a different source and a different
claim.

A cadence the parser cannot read draws **nothing**, and the row is listed
underneath as not drawn. A timeline with an invented time on it is worse than
a row left out.

## Two things this will not infer

Both are the kind of shortcut that looks like a feature and is not. Each has
a test named after the reason.

**A finding that says nothing about mode is not autonomous.** Absence reads
as unknown. "Ran with nobody watching" is an accusation, and silence is not
evidence for it - the same rule this platform applies in the other direction,
where a silent source is never read as a clean estate.

**A blank account domain is not a machine identity.** Inferring it would
manufacture the exact finding this page exists to report, on every estate
whose collectors have not been upgraded yet.

Both mean the page is empty on a deployment running older collectors, and it
says so rather than showing zero as though zero were the answer.

## What is not built yet

**The risk assessment on MCP servers.** Servers are listed without a verdict.
`ai-guard mcp-scan` scores a server against the OWASP Agentic AI Top 10, but
it assesses a *manifest* - a server's declared tools and auth scopes - and
neither the fleet report nor the client config contains that, because an MCP
server declares its tools at runtime rather than in the config that launches
it. Closing that needs a catalogue of known servers keyed on the package
rather than the display name.

**What it actually did.** Counting tool calls - "reached this server forty
times overnight" - is an outcome with no prompt in it, the same shape the
paste guard already reports. Whether it is reachable depends on what each
client logs locally.

**Observed runs.** Process telemetry would turn the day from configured into
observed, and would cover the two lane kinds a spec can never reach.

## What it does not answer, and why not yet

**What an agent was asked to do**, and whether it stayed within that brief.

This is a choice rather than a limitation, and it is worth being straight
about which. The prompt is on the machine and could be read. Endpoint tooling
reads plenty already - command lines, file writes, mail bodies - so this is a
question of proportion, not of capability.

The reasoning that survives contact with that:

- Reading what somebody typed is a heavier intrusion than knowing which tool
  they ran, and it answers no question on this page. Collecting it anyway is
  capability in search of a justification, which is the shape that gets
  monitoring programmes challenged.
- This is free software that arrives with `helm install`, often into an
  organisation that has done no assessment. A capability that ships exists on
  every deployment, and somebody will enable it without the conversation.

So the position is not *never*. It is **not by default, opt-in, and only once
the signals above have been run on a real estate and shown to be
insufficient** - which is also the evidence anyone would need to justify it.
This project already has the pattern for a capability like that: federated
sign-in refuses to point at anything but Microsoft unless told to in so many
words, and says so in its log on every boot when it has been.

## Where the fields come from

Four optional fields on a finding, bounded like every other label. A sender
that knows nothing of them is unaffected.

| Field | Values |
|---|---|
| `mode` | `interactive`, `autonomous` |
| `identity` | `person`, `machine`, `none` |
| `trigger` | free text: what starts it, in the scheduler's own words |
| `schedule` | the raw cadence, dialect-prefixed |

`schedule` carries the spec untranslated - `cron:0 2 * * *`,
`oncalendar:*:0/15`, `interval:21600`, `atlogin`, `event` - and is read once
in the portal. Normalising it in the collectors would mean doing it in a bash
script, a second bash script and a PowerShell script: three chances to
disagree about what a schedule means, where one parser is one place to be
wrong. It also keeps the spec readable by whoever has to go and find the
thing.

## If the page is empty

That is either true or a coverage gap, and the two look identical from here.
Check, in order:

1. **Are the collectors current?** The scheduler scan is script code. Machines
   need the collector that has it before anything populates these fields.
   Health shows which sources are reporting.
2. **Is anything actually scheduled?** A fleet where nobody has wired an AI
   tool into a timer is a fleet with nothing to show, and that is a finding
   in itself.
3. **Is the network scanner configured?** The bespoke-script signal comes from
   it, and it is the one that catches what has no config file to find.
