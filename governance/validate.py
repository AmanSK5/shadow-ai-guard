#!/usr/bin/env python3
"""Validate a governance file against the schema.

Run over the shipped example in CI, and by a deployer over their own file:

    python governance/validate.py path/to/governance.yaml

Two things this does that a bare schema check does not.

It normalises dates. YAML parses an unquoted 2026-11-01 as a date object rather
than a string, so a schema that only accepts strings would reject the exact
format the file is written in. Requiring quotes instead would be a trap that
catches everyone once.

It warns rather than fails on a tool id the registry does not know. A decision
about an unregistered tool is legitimate, because the tool most urgently in
need of one is often the tool the register has just flagged as observed and not
registered. But it is also what a typo looks like, so it is reported either
way: a decision that silently matches nothing is how an organisation believes
it has decided something it has not.
"""

import json
import sys
from datetime import date
from pathlib import Path

HERE = Path(__file__).parent
SCHEMA = HERE / "schema.json"
REGISTRY = HERE.parent / "registry" / "registry.yaml"


def normalise(doc):
    """Dates back to ISO strings, so both YAML forms validate."""
    for rec in (doc.get("tools") or {}).values():
        if isinstance(rec, dict) and isinstance(rec.get("review_due"), date):
            rec["review_due"] = rec["review_due"].isoformat()
    return doc


def known_tool_ids():
    try:
        import yaml
        reg = yaml.safe_load(REGISTRY.read_text()) or {}
    except Exception:
        return None
    return {t.get("id") for t in reg.get("tools", []) if t.get("id")}


def main(path):
    import yaml
    from jsonschema import Draft202012Validator

    doc = normalise(yaml.safe_load(Path(path).read_text()) or {})
    validator = Draft202012Validator(json.loads(SCHEMA.read_text()))

    errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.path))
    for e in errors:
        where = " > ".join(str(p) for p in e.path) or "(root)"
        print("error: %s: %s" % (where, e.message), file=sys.stderr)
    if errors:
        return 1

    tools = doc.get("tools") or {}
    print("%s valid: %d decision%s" % (path, len(tools), "" if len(tools) == 1 else "s"))

    known = known_tool_ids()
    if known is not None:
        unknown = sorted(set(tools) - known)
        for tid in unknown:
            print("warning: %s is not a tool id in the registry. That is fine "
                  "for a deliberate decision about something not yet "
                  "registered, and it is also what a typo looks like."
                  % tid, file=sys.stderr)

    approved_no_owner = sorted(
        t for t, r in tools.items()
        if r.get("status") == "approved" and not r.get("owner"))
    for t in approved_no_owner:
        print("warning: %s is approved with no owner. An approval nobody owns "
              "is one nobody will review." % t, file=sys.stderr)

    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))