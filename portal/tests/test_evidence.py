"""Evidence snapshots: provenance, gaps, and a checksum that means something.

Three things separate this from a screenshot, and each has a way of going
quietly wrong.

Provenance. A window recorded as "168h" is unreadable a month later and
unverifiable at any distance, so the window is timestamps. The inputs are
identified by hash rather than described, because two snapshots with the same
registry hash used the same registry and no version number can tell you that.

Gaps beside totals. Every count that could flatter has its denominator next to
it. A snapshot reporting sources_reporting without sources_known would let an
estate with half its collectors silent look complete, which is the failure this
project exists to catch, committed to a file and handed to an auditor.

A checksum that covers what it claims to. A field cannot hash itself, so the
digest is taken with snapshot_sha256 removed and the document says so in
checksum_scope. A verification rule that lives only in documentation is one
nobody can apply to a file they were emailed.
"""

import json
from datetime import datetime, timezone

import pytest
from app.evidence import (
    CHECKSUM_SCOPE,
    REVIEW_SOON_DAYS,
    canonical,
    checksum,
    evidence_from,
    verify,
)

NOW = datetime(2026, 8, 12, 9, 0, tzinfo=timezone.utc)


def _row(**kw):
    base = {
        "observed": True, "in_registry": True, "status_source": "governance",
        "status": "approved", "stored_status": "approved", "status_reason": "",
        "owner": "Engineering", "review_due": "2027-01-01", "days_overdue": 0,
        "devices": 1, "vendor": "Anthropic",
        "exceptions": [], "expired_exceptions": [],
    }
    base.update(kw)
    return base


def _snap(rows=None, status=None, personal=None, mcp=None, paste=None, **kw):
    kw.setdefault("app_version", "0.9.0")
    kw.setdefault("hours", 168)
    kw.setdefault("now", NOW)
    return evidence_from(rows or [], status or {}, personal or [],
                         mcp or [], paste or {}, **kw)


# ─────────────────────────────────────────────
# The checksum
# ─────────────────────────────────────────────

def test_a_snapshot_verifies_against_itself():
    assert verify(_snap([_row()])) is True


def test_an_edit_without_recomputing_breaks_the_checksum():
    """What the digest actually catches.

    Not tampering. The hash is unkeyed and the rule for computing it is
    published inside the document, so anyone deliberately altering a count
    recomputes it and the file verifies. This catches corruption in transit, a
    truncated file, and somebody editing a number in a text editor.
    """
    doc = _snap([_row()])
    doc["tools_observed"] = 99

    assert verify(doc) is False


def test_a_recomputed_checksum_verifies_and_that_is_the_limit():
    """Stated as a test so nobody has to take the docstring's word for it.

    An unkeyed digest cannot distinguish the platform from anyone else who can
    run sha256. Presenting a True from verify() as proof of integrity would be
    reading more into it than it says, and this is the assertion that makes the
    limit impossible to miss.
    """
    doc = _snap([_row()])
    doc["tools_observed"] = 99
    doc["snapshot_sha256"] = checksum(doc)

    assert verify(doc) is True


def test_the_checksum_omits_the_field_that_carries_it():
    """A field cannot cover itself, and a digest computed over a document
    containing its own digest could never be recomputed."""
    doc = _snap([_row()])
    without = {k: v for k, v in doc.items() if k != "snapshot_sha256"}

    assert doc["snapshot_sha256"] == checksum(without)


def test_the_document_states_its_own_verification_rule():
    """The rule has to travel with the file. Somebody handed this a year from
    now needs to know what was hashed without finding the repository."""
    doc = _snap([_row()])

    assert doc["checksum_scope"] == CHECKSUM_SCOPE
    assert "snapshot_sha256" in doc["notes"]


def test_canonical_form_is_order_independent():
    """Otherwise a reordering anywhere upstream changes the digest and every
    snapshot already issued fails verification for a reason nobody can see."""
    a = {"b": 1, "a": {"d": 2, "c": 3}}
    b = {"a": {"c": 3, "d": 2}, "b": 1}

    assert canonical(a) == canonical(b)


def test_a_snapshot_with_no_checksum_does_not_verify():
    """An absent digest is not a passing one."""
    doc = _snap([_row()])
    del doc["snapshot_sha256"]

    assert verify(doc) is False


# ─────────────────────────────────────────────
# Provenance
# ─────────────────────────────────────────────

def test_the_window_is_timestamps_not_a_duration():
    """"168h" is unreadable a month later. The dates it covered are not."""
    doc = _snap([_row()], hours=168)

    assert doc["window"]["to"] == "2026-08-12T09:00:00Z"
    assert doc["window"]["from"] == "2026-08-05T09:00:00Z"
    assert doc["window"]["hours"] == 168


def test_the_inputs_are_identified_by_hash(tmp_path):
    """Two snapshots with the same registry hash used the same registry, which
    a version number cannot tell you."""
    reg = tmp_path / "registry.json"
    reg.write_text('{"tools": []}')
    doc = _snap([_row()], registry_path=str(reg))

    assert doc["registry_sha256"].startswith("sha256:")


def test_a_missing_input_hashes_to_empty_rather_than_failing():
    """A deployment with no governance file is a valid state, and a snapshot
    that refused to generate would be worse than one saying so."""
    doc = _snap([_row()], governance_path="/nowhere/governance.yaml")

    assert doc["governance_sha256"] == ""


def test_the_snapshot_does_not_claim_to_be_reproducible():
    """Log retention means the same window may legitimately return less later,
    so a snapshot records what a query returned and cannot be recreated."""
    doc = _snap([_row()])

    assert doc["reproducible"] is False
    assert "retention" in doc["notes"]


def test_the_snapshot_does_not_claim_to_be_tamper_evident():
    """It said tamper-evident and it was not.

    A document offered as evidence is the worst place to overstate what its own
    integrity check is worth, and the reader may have nothing but the file. The
    notes have to say the digest is unkeyed and the rule public, so a verified
    file means uncorrupted rather than unaltered.
    """
    notes = _snap([_row()])["notes"].lower()

    assert "tamper" not in notes
    assert "not signed" in notes
    assert "does not detect deliberate alteration" in notes


# ─────────────────────────────────────────────
# Gaps beside totals
# ─────────────────────────────────────────────

def test_coverage_carries_both_reporting_and_known():
    """The regression. A snapshot with only the numerator would let an estate
    with half its collectors silent look complete on paper."""
    doc = _snap([_row()], status={"reporting": 11, "total": 14, "unexpected": []})

    assert doc["sources_reporting"] == 11
    assert doc["sources_known"] == 14


def test_governance_carries_both_decided_and_undecided():
    """"8 decisions" sounds like progress. "8 of 23, and 15 need one" is the
    finding."""
    doc = _snap([_row(), _row(status_source="registry_default"),
                 _row(status_source="registry_default")])

    assert doc["decisions_recorded"] == 1
    assert doc["tools_without_decision"] == 2


def test_inventory_carries_both_observed_and_watched_for():
    doc = _snap([_row(), _row(observed=False)])

    assert doc["tools_observed"] == 1
    assert doc["tools_watched_for"] == 2


def test_an_expired_approval_is_counted_separately_from_a_review_due_soon():
    """One is a finding, the other is a diary entry, and a single number would
    let a review that lapsed six months ago sit beside one due next week."""
    doc = _snap([
        _row(status="reviewing", stored_status="approved",
             status_reason="approval_expired", days_overdue=193,
             review_due="2026-01-31"),
        _row(review_due="2026-08-20"),
    ])

    assert doc["approvals_expired"] == 1
    assert doc["reviews_due_soon"] == 1


def test_reviews_due_soon_excludes_dates_beyond_the_threshold():
    doc = _snap([_row(review_due="2027-01-01")])

    assert doc["reviews_due_soon"] == 0
    assert doc["reviews_due_soon_days"] == REVIEW_SOON_DAYS


def test_tools_without_an_owner_are_counted():
    """An approval nobody owns is one nobody will review."""
    doc = _snap([_row(owner=""), _row()])

    assert doc["tools_without_owner"] == 1


def test_a_tool_observed_and_not_in_the_registry_is_counted():
    doc = _snap([_row(in_registry=False, status_source="unknown")])

    assert doc["tools_not_in_registry"] == 1


def test_exceptions_are_counted_active_and_expired():
    doc = _snap([_row(exceptions=[{"id": "EX-1"}],
                      expired_exceptions=[{"id": "EX-2"}, {"id": "EX-3"}])])

    assert doc["active_exceptions"] == 1
    assert doc["expired_exceptions"] == 2


def test_the_device_number_is_named_for_what_it_actually_is():
    """A register row carries a per-tool device count, so summing them counts a
    machine once per tool it runs. Calling that "devices" would be a number
    quietly larger than the fleet.
    """
    doc = _snap([_row(devices=2), _row(devices=3)])

    assert doc["tool_device_pairs"] == 5
    assert "devices" not in doc


# ─────────────────────────────────────────────
# Paste guard stays metadata
# ─────────────────────────────────────────────

def test_paste_guard_counts_and_detector_ids_only():
    doc = _snap([_row()], paste={
        "events": 4, "warned": 3, "overridden": 1, "blocked": 0,
        "detectors": [{"detector": "aws_access_key", "count": 4}],
    })

    assert doc["paste_events"] == 4
    assert doc["paste_overridden"] == 1
    assert doc["paste_detectors"] == ["aws_access_key"]
    assert doc["paste_content_retained"] is False


def test_the_snapshot_says_that_content_is_not_retained():
    """Stated in the document rather than only in the docs. An auditor reading
    the file should not have to take it on trust."""
    doc = _snap([_row()])

    assert doc["paste_content_retained"] is False


def test_no_paste_data_produces_zeroes_not_absence():
    """A missing key reads as "we did not measure". Zero reads as "we measured
    and there were none", which is the true statement."""
    doc = _snap([_row()], paste={})

    assert doc["paste_events"] == 0
    assert doc["paste_detectors"] == []


# ─────────────────────────────────────────────
# Shape
# ─────────────────────────────────────────────

def test_an_empty_estate_still_produces_a_valid_snapshot():
    """A deployment that has just been installed is a legitimate state and
    should be able to produce evidence saying so."""
    doc = _snap([])

    assert doc["tools_observed"] == 0
    assert verify(doc) is True


def test_the_snapshot_is_json_serialisable():
    """It is downloaded as a file, so anything that cannot round-trip through
    JSON is a runtime error at the moment somebody needs it."""
    doc = _snap([_row()])

    assert json.loads(json.dumps(doc)) == doc


@pytest.mark.parametrize("key", [
    "generated_at", "window", "app_version", "registry_sha256",
    "governance_sha256", "tools_observed", "tools_watched_for",
    "decisions_recorded", "tools_without_decision", "approvals_expired",
    "active_exceptions", "expired_exceptions", "sources_reporting",
    "sources_known", "personal_accounts", "mcp_servers", "paste_events",
    "checksum_scope", "snapshot_sha256",
])
def test_the_manifest_carries_every_field_the_spec_asked_for(key):
    assert key in _snap([_row()])


def test_the_endpoint_produces_a_verifiable_snapshot():
    """End to end, because the endpoint assembles five derivations and a unit
    test of the aggregator would not catch one of them being wired wrong."""
    from unittest.mock import patch

    from app import derive
    from app import evidence as ev
    from app import main as pm

    findings = [
        {"tool": "claude", "device": "D1", "surface": "browser",
         "source": "browser_extension", "severity": "info",
         "reported_at": "2026-08-12T09:00:00Z"},
        {"tool": "chatgpt.com", "device": "D2", "surface": "browser",
         "source": "paste_guard", "severity": "warn",
         "evidence": "paste overridden: aws_access_key",
         "reported_at": "2026-08-12T09:00:00Z"},
    ]
    reg = {"tools": [{"id": "claude", "name": "Claude", "approved": False},
                     {"id": "chatgpt", "name": "ChatGPT", "approved": False,
                      "domains": ["chatgpt.com"]}]}

    with patch.object(pm, "_findings", lambda h: findings), \
            patch.object(derive, "load_registry", lambda p: reg):
        pm._cache.clear()
        body = json.loads(bytes(pm.evidence_snapshot(hours=168).body))

    assert ev.verify(body) is True
    assert body["tools_observed"] == 2
    assert body["paste_overridden"] == 1
    # No governance file in this test, so nothing is decided and the snapshot
    # should say so rather than leaving the field out.
    assert body["decisions_recorded"] == 0
    assert body["tools_without_decision"] == 2


def test_the_download_carries_provenance_in_the_filename():
    """A file emailed onwards keeps when it was taken and over what window,
    which a header comment inside JSON would not survive."""
    from unittest.mock import patch

    from app import derive
    from app import main as pm

    with patch.object(pm, "_findings", lambda h: []), \
            patch.object(derive, "load_registry", lambda p: {"tools": []}):
        pm._cache.clear()
        resp = pm.evidence_snapshot(hours=168, download=True)

    disposition = resp.headers["content-disposition"]
    assert "ai-guard-evidence-" in disposition
    assert "-168h.json" in disposition


def test_the_snapshot_says_how_many_devices_ran_the_guard():
    """paste_events: 0 with no denominator is the same failure as reporting
    sources without knowing how many were expected."""
    doc = _snap([_row()], paste={"events": 0, "guard_devices": 12})

    assert doc["paste_events"] == 0
    assert doc["paste_guard_devices"] == 12