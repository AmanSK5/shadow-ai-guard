"""Governance decisions: what an organisation decided about a tool.

Separate from the registry on purpose. The registry answers "what is this tool
and how do I detect it", and it ships with the project. Governance answers
"what did this organisation decide about it", and it cannot ship with anything:
an upstream project has no business implying that Claude is approved or that
Engineering owns ChatGPT.

The separation is also physical. Approval used to be compiled into
extension.json and scanner.json and shipped to detectors that never read it.
Governance state has no reason to reach a browser extension, and now does not.

Optional. A deployment with no governance file behaves as it did before this
existed: the registry's own `approved` flag stands as the default, and owner
and review date are simply not set.

Two ideas do the work here.

STORED AND EFFECTIVE ARE DIFFERENT. A decision is a record of what a human
decided on a date, and it must not change because a clock ticked over. But an
approval that has passed its review date is no longer a current decision
either. So the stored decision is kept as written and the effective status is
derived at read time, with the reason attached. That is the same separation the
platform already applies to findings: Loki holds what was observed, governance
is joined on top.

A DECISION THAT MATCHES NOTHING IS SURFACED, NOT DROPPED. If a governance
record names a tool the registry does not know, it is kept and flagged. The
common case is a typo: someone writes github_copilot for github-copilot and
their decision silently does nothing. The rarer case is an upstream rename,
where an approval quietly becomes un-made by somebody else's edit. Both look
identical from here and both need saying out loud.
"""

from __future__ import annotations

import os
import sys
from datetime import date

# The three states. Deliberately few: Restricted, Deprecated and Exception
# approved are all defensible and none of them is needed to find out whether
# this model is useful.
APPROVED = "approved"
NOT_APPROVED = "not_approved"
REVIEWING = "reviewing"
VALID_STATUSES = {APPROVED, NOT_APPROVED, REVIEWING}

# Why an effective status differs from the stored one. Empty when it does not.
EXPIRED = "approval_expired"


def load_governance(path):
    """Governance decisions keyed on tool id, or {} when none are configured.

    Returns {} rather than raising on a missing file, because governance is
    optional and its absence is a valid state. A file that exists and cannot be
    read is different: that is a deployment that meant to record decisions and
    is not, so it complains to stderr rather than passing silently.
    """
    if not path:
        return {}
    if not os.path.exists(path):
        print("governance file not found at %s: decisions will fall back to "
              "the registry's approved flag" % path, file=sys.stderr)
        return {}

    try:
        with open(path) as fh:
            import yaml
            doc = yaml.safe_load(fh) or {}
    except ImportError:
        print("pyyaml not installed: governance decisions will not be loaded",
              file=sys.stderr)
        return {}
    except Exception as e:
        print("could not read governance file (%s): decisions will fall back "
              "to the registry's approved flag" % e, file=sys.stderr)
        return {}

    return load_governance_from(doc)


def load_governance_from(doc):
    """The mapping itself, separated from reading a file so it can be tested
    without one."""
    out = {}
    for tool_id, rec in ((doc or {}).get("tools") or {}).items():
        if not isinstance(rec, dict):
            continue
        status = str(rec.get("status") or "").strip().lower()
        if status not in VALID_STATUSES:
            # A status nobody recognises is not a decision. Saying so beats
            # guessing, and beats treating it as approved.
            print("governance: %s has unknown status %r, ignoring the record"
                  % (tool_id, rec.get("status")), file=sys.stderr)
            continue
        out[str(tool_id)] = {
            "status": status,
            "owner": str(rec.get("owner") or "").strip(),
            "review_due": _parse_date(rec.get("review_due")),
            "reason": str(rec.get("reason") or "").strip(),
        }
    return out


def _parse_date(value):
    """A date, or None on anything unparseable.

    None means "no review date", which for an approval is a schema error caught
    at validation rather than something to guess about here. Treating an
    unreadable date as expired would revoke an approval because of a typo.
    """
    if not value:
        return None
    if isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value).strip())
    except (ValueError, TypeError):
        print("governance: could not read review_due %r, treating it as unset"
              % value, file=sys.stderr)
        return None


def effective(record, today=None):
    """(status, reason) as it stands today, from a stored decision.

    The stored decision is never modified. An approval past its review date
    reports as reviewing with the reason attached, because an approval nobody
    has revisited is not evidence a tool is safe, it is evidence that nobody
    looked. That is the same rule the platform already applies to a source that
    has stopped reporting.

    Evaluated on every read rather than by a scheduled job. There is no window
    where the stored value is right and the displayed one is stale, and no job
    to notice has stopped running.
    """
    if not record:
        return "", ""
    status = record.get("status") or ""
    due = record.get("review_due")
    today = today or date.today()

    if status == APPROVED and due and due < today:
        return REVIEWING, EXPIRED
    return status, ""


def days_overdue(record, today=None):
    """How long an approval has been expired, or 0. For display only."""
    due = (record or {}).get("review_due")
    if not due or (record or {}).get("status") != APPROVED:
        return 0
    today = today or date.today()
    return max(0, (today - due).days)


def decide(tool_id, governance, registry_approved, today=None):
    """The whole governance position for one tool, ready to render.

    Falls back to the registry's own flag when no decision has been recorded,
    so a deployment with no governance file behaves exactly as it did before
    this existed. That fallback is reported as such rather than dressed up as a
    decision: `source` says whether a human recorded this or whether it is the
    shipped default, and nobody should read "not approved by default" as
    "somebody decided against it".
    """
    rec = (governance or {}).get(tool_id)
    if rec:
        status, reason = effective(rec, today)
        return {
            "status": status,
            "stored_status": rec["status"],
            "reason": reason,
            "owner": rec.get("owner") or "",
            "review_due": rec["review_due"].isoformat() if rec.get("review_due") else "",
            "days_overdue": days_overdue(rec, today),
            "source": "governance",
        }

    if registry_approved is None:
        # Not in the registry either. Unknown, which is not the same as
        # not approved: nobody has decided anything about this tool.
        return {"status": "", "stored_status": "", "reason": "", "owner": "",
                "review_due": "", "days_overdue": 0, "source": "unknown"}

    status = APPROVED if registry_approved else NOT_APPROVED
    return {"status": status, "stored_status": status, "reason": "",
            "owner": "", "review_due": "", "days_overdue": 0,
            "source": "registry_default"}


def unmatched(governance, known_ids):
    """Governance records naming a tool the registry does not know.

    Kept and reported rather than dropped. A decision that matches nothing is
    almost always a typo, and occasionally an upstream rename that has quietly
    un-made somebody's approval. Silently ignoring it is how an organisation
    believes it has decided something it has not.

    A deliberate decision about a tool that is genuinely not in the registry
    lands here too, which is correct: the register already flags observed tools
    that are not registered, and this is the same gap seen from the other side.
    """
    return sorted(set(governance or {}) - set(known_ids or ()))