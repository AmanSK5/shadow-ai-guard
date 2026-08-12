# Governance decisions

The register shows what AI tools are in use. This is where you record what your
organisation has decided about them: approved, not approved, or under review,
with an owner and a date to revisit it.

Optional. Without it the portal falls back to the registry's own `approved`
flag, every tool reads as undecided, and the owner and review columns show as
not set. Nothing else changes.

## Why it is a separate file

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

## The file

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

There is no write path. Decisions are edited in the file, and the file goes
through whatever review your repository already has.

That is not a limitation to be apologised for. A merge request is signed,
timestamped, reviewable, and carries a diff of exactly what changed and who
approved the change. Most governance portals build something weaker and call it
an audit log.

If, after living with it, the recurring thought is *I wish I could change this
in the portal*, that is evidence for a write path. If editing the file turns
out to be fine, a great deal of engineering has been avoided.