"""Evidence snapshots: a checksummed statement of what the platform observed.

Generated on demand from Loki, the registry and the governance file. Nothing is
stored. A snapshot is a claim about a moment, and this module's job is to make
that claim verifiable rather than to keep it.

WHAT MAKES THIS EVIDENCE RATHER THAN A SCREENSHOT

Provenance. The exact query window as timestamps, not "168h", because a
relative window is unreadable a month later and unverifiable at any distance.
The app version, so a reader knows which code produced it. Hashes of the
registry and governance files, so the inputs are identified rather than
described.

Gaps alongside totals. Every count that could flatter has its denominator
beside it: sources reporting AND sources known, decisions recorded AND tools
without one. A snapshot reporting only what it found would let an estate with
half its collectors silent look complete, which is the failure this project
exists to catch, committed to a file and handed to an auditor.

A checksum. The manifest is hashed with `snapshot_sha256` omitted, then the
digest is inserted, and `checksum_scope` says so in the document. A field
cannot cover itself, and a verification rule that lives only in documentation
is a rule nobody can apply to a file they were emailed.

WHAT THIS IS NOT

Reproducible. Loki has retention, so regenerating the same window next year may
legitimately return less. A snapshot records what a query returned at a moment,
and it cannot be recreated from the source later.

Tamper-evident. This was described that way and the description was wrong. The
digest is unkeyed and the rule for computing it is published in the document
itself, so anyone editing a count recomputes the hash, replaces the field, and
the file verifies. What the checksum detects is corruption in transit, a
truncated file, and an edit made without recomputing. Those are worth
detecting, and they are not the same as detecting an intent to deceive.

Making it tamper-evident means a signature over the digest, using a key the
reader can verify with and the person editing the file cannot sign with: an
organisational certificate, a KMS key, or a transparency log. That is a
deliberate piece of work rather than a stronger adjective, and until it exists
this says checksummed.
"""

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone

# How near a review has to be to count as due soon. Hardcoded for now: one
# threshold does not justify a configuration mechanism, and a number nobody can
# change is at least a number everybody reads the same way.
REVIEW_SOON_DAYS = 30

CHECKSUM_SCOPE = "manifest_without_snapshot_sha256"


def file_sha256(path):
    """sha256 of a file, or "" when there is none.

    Identifies the inputs rather than describing them. Two snapshots taken a
    month apart with the same registry hash used the same registry, which is
    not something a version number can tell you.
    """
    if not path or not os.path.exists(path):
        return ""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
    except OSError:
        return ""
    return "sha256:" + h.hexdigest()


def canonical(doc):
    """The bytes a checksum is taken over.

    Sorted keys and no incidental whitespace, so the same content hashes the
    same regardless of how it was assembled. Without this, a reordering
    anywhere upstream would change the digest and every previously issued
    snapshot would fail verification for no reason anyone could see.
    """
    return json.dumps(doc, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def checksum(doc):
    """The digest of a manifest, with snapshot_sha256 omitted.

    A field cannot cover itself. Verifying means removing that key, hashing
    what remains, and comparing, which is what checksum_scope names in the
    document so the rule travels with the file.

    Unkeyed, and the rule is public, so this detects corruption rather than
    alteration. See the module docstring.
    """
    return "sha256:" + hashlib.sha256(
        canonical({k: v for k, v in doc.items() if k != "snapshot_sha256"})
    ).hexdigest()


def _due_soon(rows, days=REVIEW_SOON_DAYS, now=None):
    """Tools whose review falls inside the next `days`, excluding overdue ones.

    Overdue is counted separately. Rolling the two together would let a review
    that lapsed six months ago sit in the same number as one due next week, and
    the first is a finding while the second is a diary entry.
    """
    now = now or datetime.now(timezone.utc)
    horizon = (now + timedelta(days=days)).date().isoformat()
    today = now.date().isoformat()
    return sum(1 for r in rows
               if r.get("review_due")
               and not r.get("days_overdue")
               and today <= r["review_due"] <= horizon)


def evidence_from(register_rows, status, personal, mcp, paste,
                  registry_path="", governance_path="",
                  app_version="", hours=0, now=None):
    """A snapshot manifest, checksummed.

    Takes derivations already computed rather than findings, so a snapshot and
    the pages it summarises cannot disagree: the same numbers, from the same
    read, arranged for export.
    """
    now = now or datetime.now(timezone.utc)
    rows = list(register_rows or [])
    observed = [r for r in rows if r.get("observed")]

    decided = [r for r in observed if r.get("status_source") == "governance"]
    by_status = {}
    for r in decided:
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1

    st = status or {}
    doc = {
        "generated_at": now.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        # The window as timestamps, not "168h". A relative window is
        # unreadable a month later and unverifiable at any distance.
        "window": {
            "from": (now - timedelta(hours=hours or 0)).replace(
                microsecond=0).isoformat().replace("+00:00", "Z"),
            "to": now.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "hours": int(hours) if float(hours or 0).is_integer() else hours,
        },
        "app_version": app_version,
        "registry_sha256": file_sha256(registry_path),
        "governance_sha256": file_sha256(governance_path),

        # Inventory. Both numbers, always: the registry is a watchlist, and
        # reporting only what was found would let a quiet estate look small.
        "tools_observed": len(observed),
        "tools_watched_for": sum(1 for r in rows if r.get("in_registry")),
        "tools_not_in_registry": sum(
            1 for r in observed if not r.get("in_registry")),
        "tool_device_pairs": sum(r.get("devices", 0) for r in observed),

        # Governance, with the gap stated rather than implied. "8 decisions"
        # sounds like progress; "8 of 23, and 15 need one" is the finding.
        "decisions_recorded": len(decided),
        "tools_without_decision": len(observed) - len(decided),
        "approved": by_status.get("approved", 0),
        "not_approved": by_status.get("not_approved", 0),
        "reviewing": by_status.get("reviewing", 0),
        "approvals_expired": sum(
            1 for r in decided if r.get("status_reason") == "approval_expired"),
        "tools_without_owner": sum(1 for r in decided if not r.get("owner")),
        "reviews_due_soon": _due_soon(decided, now=now),
        "reviews_due_soon_days": REVIEW_SOON_DAYS,
        "active_exceptions": sum(len(r.get("exceptions") or []) for r in rows),
        "expired_exceptions": sum(
            len(r.get("expired_exceptions") or []) for r in rows),

        # Coverage. Both, for the same reason as above and more sharply: a
        # source that has stopped reporting is indistinguishable from a clean
        # estate, and a snapshot that omitted the denominator would make that
        # indistinguishable on paper too.
        "sources_reporting": st.get("reporting", 0),
        "sources_known": st.get("total", 0),
        "sources_unexpected": len(st.get("unexpected") or []),

        # Account governance.
        "personal_accounts": len(personal or []),
        "personal_account_tools": len({r.get("tool") for r in (personal or [])
                                       if r.get("tool")}),
        "personal_account_devices": len({r.get("device") for r in (personal or [])
                                         if r.get("device")}),

        # Integrations.
        "mcp_servers": len(mcp or []),
        "mcp_findings": sum(r.get("findings", 0) for r in (mcp or [])),

        # Data protection. Counts and detector identifiers only. The paste
        # guard inspects content on the device and reports neither the text nor
        # anything derived from it, and this manifest must not become the first
        # place that changes.
        "paste_events": (paste or {}).get("events", 0),
        "paste_warned": (paste or {}).get("warned", 0),
        "paste_blocked": (paste or {}).get("blocked", 0),
        "paste_overridden": (paste or {}).get("overridden", 0),
        "paste_detectors": [d["detector"] for d in (paste or {}).get("detectors", [])],
        "paste_content_retained": False,
        # Without this, "paste_events: 0" in a snapshot reads as an estate
        # where nobody pasted a secret and an estate where the guard was never
        # deployed, and those are the same number. Same reason sources_known
        # sits beside sources_reporting.
        "paste_guard_devices": (paste or {}).get("guard_devices", 0),

        # Providers, from the registry's own vendor field.
        "providers": len({r.get("vendor") for r in observed if r.get("vendor")}),

        "checksum_scope": CHECKSUM_SCOPE,
        "reproducible": False,
        # tool_device_pairs is deliberately not "devices". A register row
        # carries a per-tool device count, so summing them counts a machine
        # once per tool it runs. The pair count is a real number; a distinct
        # device total is not recoverable from this input and is not guessed.
        # The reader of this file may have nothing else to go on, so it has to
        # say what its own checksum is worth. An unkeyed digest whose rule is
        # published alongside it detects corruption, not alteration: anyone
        # changing a count recomputes it. Calling that tamper-evident in a
        # document offered as evidence would be the worst place to overstate.
        "notes": (
            "Counts are for the stated window. Not reproducible: log retention "
            "may mean the same window returns less later. Checksummed, not "
            "signed: remove snapshot_sha256, hash the remaining document with "
            "sorted keys and no whitespace, and compare. That detects "
            "corruption and an edit made without recomputing, and does not "
            "detect deliberate alteration, because the digest is unkeyed and "
            "this rule is public."
        ),
    }
    doc["snapshot_sha256"] = checksum(doc)
    return doc


def verify(doc):
    """True when a manifest's checksum matches its contents.

    Here so the rule is executable rather than only described. A verification
    procedure that exists in prose is one every reader implements slightly
    differently.

    True means the file has not been corrupted or carelessly edited. It does
    not mean the file is what the platform produced: the digest is unkeyed and
    anyone altering a count can recompute it. Do not present a True from this
    as proof of integrity.
    """
    claimed = (doc or {}).get("snapshot_sha256")
    return bool(claimed) and claimed == checksum(doc)