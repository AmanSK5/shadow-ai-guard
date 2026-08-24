# Governance decisions

The register shows what AI tools are in use. A decision records what your
organisation concluded about one: approved, not approved, or under review,
with an owner and a date to revisit it.

In managed mode - the default - you record decisions in the portal: every
register card has an edit control, the wizard offers a baseline pass over
the common tools, and each write is stamped into the audit trail with who
made it. In classic mode the same decisions live in a YAML file in your
repo, reviewed the way the rest of your configuration is. This page covers
the rules both paths share, then the file format.

Recording nothing is fine. Without any decisions the portal falls back to
the registry's own `approved` flag, every tool reads as undecided, and the
owner and review columns show as not set. Nothing else changes.

## Why governance is separate from the registry

The registry answers *what is this tool and how do I detect it*. It ships with
the project, and it is the same for everyone.

Governance answers *what did we decide about it*. That is yours, and it is
nobody else's to ship: an upstream project has no business implying that Claude
is approved or that Engineering owns ChatGPT.

The separation is also physical. Approval used to be compiled into
`extension.json` and `scanner.json` and sent to detectors that never read it. A
browser extension has no use for your approval decisions, and now does not
receive them.

## Approval is not safety

**Approval records a governance position. It does not change finding
severity.**

Severity is decided by the reporter at the point of detection and depends on
the account domain. A personal account is a `warn` on any surface. The presence
of a tool is `info`. Neither changes because you approved something.

So both of these are correct and normal:

    Claude, corporate account      severity info     governance approved
    Claude, personal account       severity warn     governance approved

The second is still the thing to act on, because the risky part is the account,
not the tool. Approval must never quietly come to mean safe.

## The file (classic mode)

The portal path needs no file; everything below applies to it too, enforced
on the write path. The file is for classic deployments, or for anyone who
wants decisions in a repo:

```yaml
version: 1

tools:
  claude:
    status: approved
    owner: Engineering
    review_due: 2026-11-01
    reason: Enterprise tenant, DPA in place

  deepseek:
    status: not_approved
    owner: Security
    reason: No data processing agreement
```

Start from `governance/governance.yaml.example`, which has a worked entry for
each state.

### Fields

| field | required | notes |
|---|---|---|
| `status` | yes | `approved`, `not_approved` or `reviewing` |
| `review_due` | **on `approved`** | `YYYY-MM-DD`. Strongly expected on `reviewing`, optional on `not_approved` |
| `owner` | no | A team or a person. Not resolved against anything |
| `reason` | no | Free text, shown with the decision |

`review_due` is required on an approval and not on a refusal because that is
where the risk is. An approval with no expiry is the one that outlives the
person who made it and the reason it was made. A decision not to use something
does not rot in the same way.

### Three states, not five

`Restricted`, `Deprecated` and `Exception approved` are all defensible, and none
of them is needed to find out whether this model is useful. Start with three.

## Expiry

An approval past its `review_due` reports as **reviewing**, with the reason and
the previous decision alongside:

```
Claude
REVIEWING
approval expired 12 days ago
was approved
```

The record itself is never rewritten. A clock ticking over is not a decision,
and the history has to keep saying what a human decided on a date. The stored
status stays `approved`; only the derived status moves.

This is the same rule the platform already applies to detection sources. A
collector that has stopped reporting is not evidence a machine is clean, and an
approval nobody has revisited in eighteen months is not evidence a tool is safe.
It is evidence that nobody looked.

Expiry is evaluated when the page is rendered. There is no job to run and no
window where the stored value is right and the display is stale.

## Tool ids

Keys are tool ids as they appear in the registry. They are also **governance
subjects**, which is not quite the same thing: you can record a decision about a
tool the registry has never heard of. That is deliberate, because the tool most
urgently in need of a decision is often the one the register has just flagged as
observed and not registered.

A decision naming an id the registry does not know is **shown, not dropped**:

```
1 decision names a tool the registry does not know: github_copilot
```

Usually that is a typo. Occasionally it is an upstream rename that has quietly
un-made an approval you recorded. Both look identical from here, and both need
saying out loud: a decision that silently matches nothing is how an
organisation believes it has decided something it has not.

Treat tool ids as stable keys for this reason. Display names and metadata can
change; an id is what a decision is attached to.

## Exceptions

A temporary departure from the general decision, for a stated scope and period.

```yaml
exceptions:
  EX-001:
    tool: chatgpt
    scope:
      team: Marketing
    reason: Client campaign work, no personal data
    owner: Security
    expires: 2026-12-01
```

Keyed on its own id, not on the tool. A tool can have more than one, for
different teams or different reasons, and keying on the tool would allow exactly
one and would discard the previous the moment a second was written. An exception
is also a record with its own life: raised, applying, expired, and still visible
afterwards.

### It sits beside the decision, not in place of it

The register shows both. `ollama` reads as **not approved** with the Research
exception underneath, because the general position has not been withdrawn.
Showing the exception as the status would make a note about one team read as a
decision about everybody.

### expires is required

Unlike `review_due` on a decision, which is required only on an approval. A
departure from the general position with no end is not an exception, it is an
undocumented change of policy.

When it expires it simply stops applying. The underlying status is already what
it was, so **nothing becomes `reviewing`**: that is the expired-approval rule,
and applying it here would put a tool under review because a campaign finished.

Expired exceptions stay visible, quieter. One that has run its course is a
record of something an organisation decided and then let lapse, which is worth
seeing rather than losing.

### scope

Free-form keys such as `team` or `project`. The portal displays it and does not
resolve it against anything: enforcing scope would need identity the platform
does not have. It is a note for the reader about who the exception covers.

### Fields

| field | required | notes |
|---|---|---|
| `tool` | yes | An id the registry does not know validates and is reported, same as a decision |
| `expires` | yes | `YYYY-MM-DD` |
| `scope` | no | Free-form keys, displayed not enforced |
| `reason` | no | Free text |
| `owner` | no | A team or a person |

## Validating

```bash
python governance/validate.py path/to/governance.yaml
```

Exits non-zero on a schema error. Warns without failing on an id the registry
does not know, and on an approval with no owner.

Write dates however you like. YAML parses a bare `2026-11-01` as a date rather
than a string, and the validator normalises it, so quoting is optional rather
than a trap.

## Deploying

### Kubernetes

```bash
kubectl create configmap ai-guard-governance --from-file=governance.yaml
```

```yaml
portal:
  governance:
    existingConfigMap: ai-guard-governance
```

### Compose

Mount the file and point `GOVERNANCE_PATH` at it. `demo/docker-compose.yml`
does exactly that, and `demo/governance.yaml` is a worked example you can see
rendered by running the demo.

## The audit trail

In classic mode there is no write path. Decisions are edited in the file, and
the file goes through whatever review your repository already has.

That is not a limitation to be apologised for. A merge request is signed,
timestamped, reviewable, and carries a diff of exactly what changed and who
approved the change. Most governance portals build something weaker and call it
an audit log.

This document used to end: *if, after living with it, the recurring thought is
"I wish I could change this in the portal", that is evidence for a write
path.* Managed mode is that thought, made deliberate. With it enabled, the
register's cards gain an **edit** control: decisions (status, owner, review
date, reason) are recorded centrally in the receiver's state DB, every write
is stamped with who and when in the receiver's event log, and the same rules
the file's validator enforces apply on the write path - an approval without a
review date is refused there too.

The two coexist per tool: a portal-recorded decision wins, the file fills the
gaps, and the register labels which kind of decision it is showing ("set in
the portal"). Exceptions - scoped, expiring departures - remain file-only:
they are rarer, and the review a merge request gives them is worth more than
the convenience of an editor. The file-based path stays first-class either
way, so the argument above still holds for classic mode.