"""Governance decisions, expiry, and what happens when a decision matches nothing.

Three things these hold to, and each exists because the obvious implementation
gets it wrong.

An approval that has passed its review date is not a current approval. Nobody
decided anything on the day it expired, so the stored decision must not change,
but the effective status must. Getting one without the other is the trap: a
model that mutates the record loses the history, and a model that only stores
loses the fact that the approval has lapsed.

Approval never means safe. Severity depends on the account domain and nothing
else, and no governance state changes that. An approved tool on a personal
account is still a warn, because the risky part is the account.

A decision that names a tool nothing recognises is surfaced, not dropped. The
common case is a typo, and a silently ignored decision is worse than no
decision: the organisation believes it has decided something it has not.
"""

from datetime import date

import pytest

from app.governance import (
    APPROVED,
    EXPIRED,
    NOT_APPROVED,
    REVIEWING,
    days_overdue,
    decide,
    effective,
    load_governance_from,
    unmatched,
)

TODAY = date(2026, 8, 12)


def _doc(**tools):
    return {"tools": tools}


# ─────────────────────────────────────────────
# Expiry: stored and effective are different
# ─────────────────────────────────────────────

def test_an_approval_in_date_is_approved():
    gov = load_governance_from(_doc(
        claude={"status": "approved", "review_due": "2026-11-01"}))
    assert effective(gov["claude"], TODAY) == (APPROVED, "")


def test_an_approval_expiring_today_is_still_approved():
    """The boundary. Due today means due, not overdue."""
    gov = load_governance_from(_doc(
        claude={"status": "approved", "review_due": "2026-08-12"}))
    assert effective(gov["claude"], TODAY) == (APPROVED, "")


def test_an_expired_approval_reads_as_reviewing():
    """The regression. A model with no expiry returns approved here."""
    gov = load_governance_from(_doc(
        claude={"status": "approved", "review_due": "2026-07-31"}))
    assert effective(gov["claude"], TODAY) == (REVIEWING, EXPIRED)


def test_the_stored_decision_is_not_rewritten_by_expiry():
    """A clock ticking over is not a decision.

    The history has to keep saying what a human decided on a date. Only the
    derived status moves.
    """
    gov = load_governance_from(_doc(
        claude={"status": "approved", "review_due": "2026-07-31"}))
    effective(gov["claude"], TODAY)

    assert gov["claude"]["status"] == APPROVED


def test_expiry_only_applies_to_approvals():
    """A review date on a not_approved record is a reminder, not a trigger.

    Expiring it into reviewing would silently soften a refusal.
    """
    gov = load_governance_from(_doc(
        grok={"status": "not_approved", "review_due": "2026-07-31"}))
    assert effective(gov["grok"], TODAY) == (NOT_APPROVED, "")


def test_reviewing_does_not_expire_into_anything():
    gov = load_governance_from(_doc(
        cursor={"status": "reviewing", "review_due": "2026-07-31"}))
    assert effective(gov["cursor"], TODAY) == (REVIEWING, "")


def test_an_approval_with_no_review_date_does_not_expire():
    """The schema requires review_due on an approval, so this is the shape of a
    file that got past validation some other way, or a date that would not
    parse. Revoking an approval because of a typo in a date is worse than
    leaving it standing and letting validation complain."""
    gov = load_governance_from(_doc(claude={"status": "approved"}))
    assert effective(gov["claude"], TODAY) == (APPROVED, "")


def test_an_unparseable_review_date_is_treated_as_unset():
    gov = load_governance_from(_doc(
        claude={"status": "approved", "review_due": "next Tuesday"}))
    assert gov["claude"]["review_due"] is None
    assert effective(gov["claude"], TODAY) == (APPROVED, "")


def test_days_overdue_counts_from_the_review_date():
    gov = load_governance_from(_doc(
        claude={"status": "approved", "review_due": "2026-07-31"}))
    assert days_overdue(gov["claude"], TODAY) == 12


def test_days_overdue_is_zero_for_a_current_approval():
    gov = load_governance_from(_doc(
        claude={"status": "approved", "review_due": "2026-11-01"}))
    assert days_overdue(gov["claude"], TODAY) == 0


# ─────────────────────────────────────────────
# Falling back to the registry
# ─────────────────────────────────────────────

def test_no_governance_file_falls_back_to_the_registry_flag():
    """A deployment that has not adopted this must behave exactly as before."""
    assert decide("claude", {}, False, TODAY)["status"] == NOT_APPROVED
    assert decide("claude", {}, True, TODAY)["status"] == APPROVED


def test_the_fallback_is_labelled_as_a_fallback():
    """Nobody should read the shipped default as somebody's decision.

    Every tool ships not approved, and a register that presented that as a
    governance position would be asserting a refusal nobody made.
    """
    assert decide("claude", {}, False, TODAY)["source"] == "registry_default"
    assert decide("claude", {"claude": {"status": APPROVED, "review_due": None}},
                  False, TODAY)["source"] == "governance"


def test_a_tool_in_neither_place_is_unknown_not_refused():
    """Unknown and not approved are different answers.

    A tool observed and absent from the registry is the register's most urgent
    row. Reporting it as not approved would imply a decision.
    """
    d = decide("mystery-ai", {}, None, TODAY)
    assert d["status"] == ""
    assert d["source"] == "unknown"


def test_a_governance_decision_overrides_the_registry_default():
    gov = load_governance_from(_doc(
        claude={"status": "approved", "review_due": "2026-11-01"}))
    assert decide("claude", gov, False, TODAY)["status"] == APPROVED


def test_an_expired_override_still_beats_the_registry_default():
    """The compound case. An expired approval reads as reviewing, not as the
    registry's not approved, because a lapsed decision is still a decision that
    was made."""
    gov = load_governance_from(_doc(
        claude={"status": "approved", "review_due": "2026-07-31"}))
    d = decide("claude", gov, False, TODAY)

    assert d["status"] == REVIEWING
    assert d["stored_status"] == APPROVED
    assert d["reason"] == EXPIRED
    assert d["days_overdue"] == 12


# ─────────────────────────────────────────────
# Records that match nothing
# ─────────────────────────────────────────────

def test_a_decision_naming_an_unknown_tool_is_surfaced():
    """The regression. Dropping it is how an organisation believes it has
    decided something it has not.

    The likely cause is a typo, and the rarer one is an upstream rename that
    quietly un-made an approval somebody recorded. Both look the same from
    here and both need saying.
    """
    gov = load_governance_from(_doc(
        github_copilot={"status": "approved", "review_due": "2027-01-01"}))

    assert unmatched(gov, ["github-copilot", "claude"]) == ["github_copilot"]


def test_a_matched_decision_is_not_reported_as_unmatched():
    gov = load_governance_from(_doc(
        claude={"status": "approved", "review_due": "2027-01-01"}))
    assert unmatched(gov, ["claude"]) == []


def test_no_governance_produces_no_unmatched_records():
    assert unmatched({}, ["claude"]) == []
    assert unmatched(None, None) == []


# ─────────────────────────────────────────────
# Loading
# ─────────────────────────────────────────────

@pytest.mark.parametrize("status", ["approved", "not_approved", "reviewing"])
def test_the_three_states_load(status):
    gov = load_governance_from(_doc(x={"status": status, "review_due": "2027-01-01"}))
    assert gov["x"]["status"] == status


def test_an_unrecognised_status_is_not_a_decision():
    """Not silently coerced. Guessing which of three states somebody meant is
    how a tool ends up approved by a typo."""
    gov = load_governance_from(_doc(x={"status": "Approved-ish"}))
    assert "x" not in gov


def test_status_is_read_case_insensitively():
    gov = load_governance_from(_doc(x={"status": "Approved", "review_due": "2027-01-01"}))
    assert gov["x"]["status"] == APPROVED


def test_a_malformed_record_is_skipped_not_fatal():
    """One bad entry must not cost an organisation every other decision."""
    gov = load_governance_from({"tools": {"good": {"status": "reviewing"},
                                          "bad": "not a mapping"}})
    assert set(gov) == {"good"}


def test_an_empty_or_absent_file_loads_as_no_decisions():
    assert load_governance_from({}) == {}
    assert load_governance_from(None) == {}
    assert load_governance_from({"tools": None}) == {}


def test_owner_and_reason_are_carried_through():
    gov = load_governance_from(_doc(
        claude={"status": "approved", "review_due": "2027-01-01",
                "owner": "Engineering", "reason": "Enterprise tenant"}))
    assert gov["claude"]["owner"] == "Engineering"
    assert gov["claude"]["reason"] == "Enterprise tenant"


# ─────────────────────────────────────────────
# The boundary that must not move
# ─────────────────────────────────────────────

def test_governance_carries_no_severity():
    """Detection severity and governance status are independent dimensions.

    Severity describes what was observed and depends on the account domain.
    Governance describes what the organisation decided. An approved tool on a
    personal account is still warn, because the risky part is the account, and
    an unapproved tool on a corporate account is still info, because nothing
    risky was observed.

    Asserted structurally: nothing this module returns is a severity, so
    nothing downstream can read one out of it. The moment a severity key
    appears here, approved has started to mean safe.
    """
    gov = load_governance_from(_doc(
        claude={"status": "approved", "review_due": "2027-01-01"}))
    d = decide("claude", gov, False, TODAY)

    assert "severity" not in d
    assert "severity" not in gov["claude"]