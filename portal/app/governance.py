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
EXCEPTED = "exception"


def load_governance(path):
    """(decisions, exceptions) from one file, or ({}, {}) when none configured.

    Returns {} rather than raising on a missing file, because governance is
    optional and its absence is a valid state. A file that exists and cannot be
    read is different: that is a deployment that meant to record decisions and
    is not, so it complains to stderr rather than passing silently.
    """
    if not path:
        return {}, {}
    if not os.path.exists(path):
        print("governance file not found at %s: decisions will fall back to "
              "the registry's approved flag" % path, file=sys.stderr)
        return {}, {}

    try:
        with open(path) as fh:
            import yaml
            doc = yaml.safe_load(fh) or {}
    except ImportError:
        print("pyyaml not installed: governance decisions will not be loaded",
              file=sys.stderr)
        return {}, {}
    except Exception as e:
        print("could not read governance file (%s): decisions will fall back "
              "to the registry's approved flag" % e, file=sys.stderr)
        return {}, {}

    return load_governance_from(doc), load_exceptions_from(doc)


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


def load_exceptions_from(doc):
    """Exceptions, keyed on their own id rather than on the tool.

    Keyed on an id because a tool can have more than one, for different teams
    or different reasons, and because an exception is a record with its own
    life: it is raised, it applies, it expires, and it stays visible
    afterwards. Keying on the tool would allow exactly one and would lose the
    previous one the moment a second was written.

    Expiry is mandatory here in a way it is not for a decision. An exception is
    a deliberate departure from the general position for a stated scope and
    period, and one without an end is not an exception, it is an undocumented
    change of policy.
    """
    out = {}
    for ex_id, rec in ((doc or {}).get("exceptions") or {}).items():
        if not isinstance(rec, dict):
            continue
        tool = str(rec.get("tool") or "").strip()
        expires = _parse_date(rec.get("expires"))
        if not tool:
            print("governance: exception %s names no tool, ignoring it" % ex_id,
                  file=sys.stderr)
            continue
        if not expires:
            # Caught by the schema, so reaching here means a file that got in
            # another way. An exception with no end applying forever is the
            # thing this must not do.
            print("governance: exception %s has no usable expiry, ignoring it"
                  % ex_id, file=sys.stderr)
            continue
        out[str(ex_id)] = {
            "id": str(ex_id),
            "tool": tool,
            "scope": rec.get("scope") or {},
            "reason": str(rec.get("reason") or "").strip(),
            "owner": str(rec.get("owner") or "").strip(),
            "expires": expires,
        }
    return out


def exceptions_for(tool_id, exceptions, today=None):
    """(active, expired) exceptions for one tool.

    Expired ones are returned rather than filtered out. An exception that has
    run its course is a record of something an organisation decided and then
    let lapse, and dropping it from the view loses the history at the moment it
    becomes most worth seeing.
    """
    today = today or date.today()
    mine = [e for e in (exceptions or {}).values() if e["tool"] == tool_id]
    active = sorted((e for e in mine if e["expires"] >= today),
                    key=lambda e: e["expires"])
    expired = sorted((e for e in mine if e["expires"] < today),
                     key=lambda e: e["expires"], reverse=True)
    return active, expired


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


def decide(tool_id, governance, registry_approved, today=None, exceptions=None):
    """The whole governance position for one tool, ready to render.

    Falls back to the registry's own flag when no decision has been recorded,
    so a deployment with no governance file behaves exactly as it did before
    this existed. That fallback is reported as such rather than dressed up as a
    decision: `source` says whether a human recorded this or whether it is the
    shipped default, and nobody should read "not approved by default" as
    "somebody decided against it".

    An active exception is reported alongside the decision, not in place of it.
    An exception is a departure from the general position for a stated scope,
    and the general position has not been withdrawn: replacing the status would
    lose what the organisation actually decided, and would make an exception
    for one team read as a decision about everybody. When it expires it simply
    stops applying, and the underlying status is already what it was. An
    expired exception does not make a tool reviewing: nothing about the
    decision changed, only the departure from it ended.
    """
    active, expired = exceptions_for(tool_id, exceptions, today)
    ex = {
        "exceptions": [_jsonable_exception(e) for e in active],
        "expired_exceptions": [_jsonable_exception(e) for e in expired],
    }

    rec = (governance or {}).get(tool_id)
    if rec:
        status, reason = effective(rec, today)
        return dict(ex, **{
            "status": status,
            "stored_status": rec["status"],
            "reason": reason,
            "owner": rec.get("owner") or "",
            "review_due": rec["review_due"].isoformat() if rec.get("review_due") else "",
            "days_overdue": days_overdue(rec, today),
            # Where the record came from. "governance" is the file, as it
            # always was; a record the portal wrote in managed mode arrives
            # with origin "portal" so the register can say which kind of
            # decision it is showing.
            "source": rec.get("origin") or "governance",
        })

    if registry_approved is None:
        # Not in the registry either. Unknown, which is not the same as
        # not approved: nobody has decided anything about this tool.
        return dict(ex, **{"status": "", "stored_status": "", "reason": "",
                           "owner": "", "review_due": "", "days_overdue": 0,
                           "source": "unknown"})

    status = APPROVED if registry_approved else NOT_APPROVED
    return dict(ex, **{"status": status, "stored_status": status, "reason": "",
                       "owner": "", "review_due": "", "days_overdue": 0,
                       "source": "registry_default"})


def _jsonable_exception(e):
    """An exception as plain data, with the date as a string."""
    return {"id": e["id"], "tool": e["tool"], "scope": e["scope"],
            "reason": e["reason"], "owner": e["owner"],
            "expires": e["expires"].isoformat()}


def unmatched_exceptions(exceptions, known_ids):
    """Exceptions naming a tool the registry does not know.

    Same treatment as an unmatched decision and for the same reason: usually a
    typo, occasionally a rename, and either way the exception is not applying
    to anything. Reported rather than dropped.
    """
    return sorted({e["tool"] for e in (exceptions or {}).values()
                   if e["tool"] not in set(known_ids or ())})


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