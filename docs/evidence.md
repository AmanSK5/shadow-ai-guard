# Evidence

Shadow AI Guard can produce a checksummed statement of what it observed, and an
index of where each kind of record lives. Both are read-only views over data the
platform already has. Nothing is stored, and neither adds a workflow.

## Evidence snapshot

`GET /api/evidence`, or **Download JSON** on the ISO 42001 page. Generated on
demand from Loki, the registry and the governance file.

```json
{
  "generated_at": "2026-08-12T19:08:55Z",
  "window": { "from": "2026-08-05T19:08:55Z", "to": "2026-08-12T19:08:55Z", "hours": 168 },
  "app_version": "0.9.4",
  "registry_sha256": "sha256:e982bf...",
  "governance_sha256": "sha256:21a696...",

  "tools_observed": 8,
  "tools_watched_for": 30,
  "decisions_recorded": 4,
  "tools_without_decision": 4,
  "sources_reporting": 6,
  "sources_known": 18,

  "checksum_scope": "manifest_without_snapshot_sha256",
  "reproducible": false,
  "snapshot_sha256": "sha256:97fad8..."
}
```

### What makes it evidence rather than a screenshot

**Provenance.** The window is timestamps, not `168h`: a relative window is
unreadable a month later and unverifiable at any distance. The registry and
governance files are identified by hash rather than described, so two snapshots
with the same `registry_sha256` used the same registry, which no version number
can tell you.

**Gaps beside totals.** Every count that could flatter has its denominator next
to it. `sources_reporting` without `sources_known` would let an estate with two
thirds of its collectors silent look complete, which is the failure this project
exists to catch, committed to a file and handed to an auditor. Likewise
`decisions_recorded` never appears without `tools_without_decision`.

**A checksum that covers what it claims to.** A field cannot hash itself, so
`snapshot_sha256` is computed over the manifest with that key removed, and
`checksum_scope` names the rule inside the document. A verification procedure
that lives only in documentation is one nobody can apply to a file they were
emailed. What that checksum does and does not prove is below, and it is less
than the word checksum suggests.

### Verifying one

```python
import json
from app.evidence import verify

verify(json.load(open("ai-guard-evidence-2026-08-12T1908Z-168h.json")))
```

Or by hand: remove `snapshot_sha256`, serialise the rest with sorted keys and no
whitespace, take the sha256, compare.

### What the checksum is worth

**Checksummed, not signed.** The digest is unkeyed and the rule for computing
it is printed inside the document, so anyone altering a count recomputes the
hash, replaces the field, and the file verifies. `verify()` returning true means
the file has not been corrupted or carelessly edited. It does not mean the file
is what the platform produced.

That is worth being blunt about, because a snapshot is offered as evidence and
the person reading it may have nothing else to go on. Detecting corruption in
transit, a truncated file, and a number changed in a text editor is genuinely
useful. Detecting somebody who wants the numbers to be different is a separate
property and this does not have it.

Getting it means signing the digest with a key the reader can verify and the
person editing the file cannot use: an organisational certificate, a KMS key, or
a transparency log. Until that exists, treat a snapshot the way you would treat
a printed report: its integrity comes from where you got it and who gave it to
you, not from the file.

**Not reproducible either.** Log retention means the same window may legitimately
return less next year, so a snapshot records what a query returned at a moment
and cannot be recreated from the source.

### Not stored

There is no snapshot history and no comparison between two of them. That would
need persistence, which this release does not add. Download the file and keep it
wherever you keep evidence.

## ISO/IEC 42001 evidence index

An index of what the platform can currently say and where each record lives.

| | |
|---|---|
| Inventory and usage | tools in use, tools watched for | AI register |
| Governance | decisions, tools without one, expired approvals | AI register |
| Monitoring coverage | sources reporting of sources known | Setup |
| Account governance | personal accounts, affected tools | Personal accounts |
| Data protection | paste events, overrides, content not retained | Paste guard |
| Integrations | MCP servers observed | MCP servers |
| Third parties | providers observed | AI register |

Below it, **review inputs**: the things somebody may need to look at, each
linking to where the evidence is.

### What it is not

**No compliance score, no percentage, no clause numbers.** A mapping asserted
without validation implies an authority this project does not have, and
reproducing the standard's own wording is not ours to do. The page says what it
is: evidence Shadow AI Guard can provide to support an AI management system.

**Not an assessment.** Review inputs are framed as inputs to a human review
rather than conclusions. The platform can say a tool has no recorded decision. It
cannot say whether that matters.

**Not a second Overview.** One row per theme, not a card per theme. The value is
knowing where the evidence lives, not seeing the same numbers rendered twice.

### The gaps are the point

`4 decisions recorded, 4 tools without one` rather than a tick. `6 of 18
expected sources reporting` rather than `6 sources reporting`. Wherever a number
could be read as progress, the denominator sits beside it.

## Paste guard

`GET /api/paste-guard`, and its own page.

Per tool: warned, overridden, blocked, devices, which detectors fired, first and
last seen. Overrides sort first, because somebody shown the detector by name who
pasted anyway is the row to follow up, and sorting by event count would bury one
override under twenty warnings that worked.

### Metadata only

The guard inspects clipboard content on the device and reports detector
identifiers. The matched text never reaches the receiver and never reaches the
portal, and `portal/app/paste_guard.py` has a test asserting that structurally:
it serialises the whole result and checks a secret is absent, rather than
checking the fields it expects to find.

Detector ids are constrained to `[a-z0-9_]`. That is not tidiness. `evidence` is
a 2048 character operator-adjacent field, and a parser that split on commas and
trusted the rest would carry anything appended to an id straight through.

### The heartbeat is counted separately

Heartbeats share `source: paste_guard`. They are excluded from the event counts:
counting them would report every device's daily check-in as a paste somebody
tried to make, a number wrong in the direction nobody checks because it only
rises and looks like activity.

They are reported as their own signal instead. `guard_devices` is the count of
devices whose guard checked in, and it is what stops `0 pastes stopped` meaning
both an estate where nobody pasted a secret and one where the extension was
never deployed. The extension writes its heartbeat only on confirmed delivery,
so a device here has a working chain end to end rather than merely the extension
installed.

`guard_versions` and `guard_modes` come free in the same string. More than one
version is a rollout that stalled. A device in warn mode where policy says block
is a policy that is not in force. Neither is visible in a count of what was
stopped.