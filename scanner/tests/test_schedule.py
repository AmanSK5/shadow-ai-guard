# Copyright 2026 Aman Karir
# SPDX-License-Identifier: Apache-2.0
# Part of Shadow AI Guard, https://github.com/AmanSK5/shadow-ai-guard

"""Running once, or on a repeat, from the one image.

The behaviour worth pinning is not the sleeping. It is that a CronJob still
gets exactly what it had before, that a failed pass on an interval does not
take the container down with it, and that the health file answers on the last
pass that SUCCEEDED rather than the last one that ran.
"""
import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import schedule  # noqa: E402


# ---- the interval ---------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("", 0), ("0", 0), ("   ", 0),          # unset means one pass, as before
    ("90", 90), ("45s", 45), ("30m", 1800),
    ("6h", 21600), ("24H", 86400), ("7d", 604800),
])
def test_interval_parses(raw, expected):
    assert schedule.interval_seconds(raw) == expected


@pytest.mark.parametrize("raw", ["sixty", "6 hours", "-1", "1w", ""])
def test_a_bad_interval_is_named_not_guessed(raw):
    """A typo must not silently become 'run once' - that is the mode where
    nothing ever runs again and nothing says why."""
    if raw == "":
        assert schedule.interval_seconds(raw) == 0
        return
    with pytest.raises(ValueError) as e:
        schedule.interval_seconds(raw)
    assert "AIGUARD_RUN_INTERVAL" in str(e.value)


# ---- one pass, which is what the CronJob asks for --------------------------

def test_no_interval_runs_once_and_returns_the_job_code(tmp_path):
    calls = []
    code = schedule.run_scheduled(
        lambda: calls.append(1) or 0, say=lambda m: None,
        name="t", interval=0, path=tmp_path / "h.json")
    assert code == 0 and len(calls) == 1


def test_no_interval_propagates_a_failure(tmp_path):
    """The CronJob's whole failure signal is the exit code."""
    code = schedule.run_scheduled(
        lambda: 1, say=lambda m: None,
        name="t", interval=0, path=tmp_path / "h.json")
    assert code == 1


def test_a_single_pass_asserts_no_liveness(tmp_path):
    """A one-shot container exits; there is nothing to call stale."""
    health = tmp_path / "h.json"
    schedule.run_scheduled(lambda: 0, say=lambda m: None,
                           name="t", interval=0, path=health)
    assert schedule.health_exit_code(health, now=time.time() + 10_000_000) == 0


# ---- on an interval -------------------------------------------------------

def test_an_interval_keeps_going_and_sleeps_between(tmp_path):
    slept = []
    calls = []
    schedule.run_scheduled(
        lambda: calls.append(1) or 0, say=lambda m: None, name="t",
        interval=600, path=tmp_path / "h.json",
        sleep=slept.append, passes=3)
    assert len(calls) == 3
    # Two gaps for three passes: it sleeps between them, not after the last.
    assert slept == [600, 600]


def test_a_failed_pass_does_not_stop_the_loop(tmp_path):
    """Exiting would restart the container against whatever just refused it."""
    codes = iter([1, 1, 0])
    calls = []
    code = schedule.run_scheduled(
        lambda: calls.append(1) or next(codes), say=lambda m: None,
        name="t", interval=600, path=tmp_path / "h.json",
        sleep=lambda s: None, passes=3)
    assert len(calls) == 3
    assert code == 0


def test_an_exception_is_a_failed_pass_not_a_crash(tmp_path):
    said = []
    calls = []

    def boom():
        calls.append(1)
        raise RuntimeError("the receiver is not there")

    schedule.run_scheduled(boom, say=said.append, name="t", interval=600,
                           path=tmp_path / "h.json",
                           sleep=lambda s: None, passes=2)
    assert len(calls) == 2
    assert any("the receiver is not there" in m for m in said)


def test_sys_exit_from_the_job_is_a_failed_pass(tmp_path):
    """discovery uses sys.exit for a fatal misconfiguration."""
    calls = []

    def bail():
        calls.append(1)
        raise SystemExit("DV query did not finish")

    schedule.run_scheduled(bail, say=lambda m: None, name="t", interval=600,
                           path=tmp_path / "h.json",
                           sleep=lambda s: None, passes=2)
    assert len(calls) == 2
    assert json.loads((tmp_path / "h.json").read_text())["ok"] is False


def test_a_silly_interval_is_floored(tmp_path):
    """A typo must not point a scanner at the receiver in a tight loop."""
    slept = []
    schedule.run_scheduled(lambda: 0, say=lambda m: None, name="t",
                           interval=1, path=tmp_path / "h.json",
                           sleep=slept.append, passes=2)
    assert slept == [schedule.MIN_INTERVAL]


# ---- the health file ------------------------------------------------------

def test_health_reports_the_last_success_not_the_last_run(tmp_path):
    """The whole point: a loop that runs and achieves nothing looks identical
    to a working one from outside the container."""
    health = tmp_path / "h.json"
    schedule.run_scheduled(lambda: 0, say=lambda m: None, name="t",
                           interval=600, path=health,
                           sleep=lambda s: None, passes=1)
    succeeded_at = json.loads(health.read_text())["last_success"]
    assert succeeded_at

    schedule.run_scheduled(lambda: 1, say=lambda m: None, name="t",
                           interval=600, path=health,
                           sleep=lambda s: None, passes=2)
    state = json.loads(health.read_text())
    assert state["ok"] is False
    assert state["last_success"] == succeeded_at     # carried through the failures

    # Still healthy just after that success, stale once the grace has passed.
    when = time.time()
    assert schedule.health_exit_code(health, now=when) == 0
    stale = when + 600 * schedule.GRACE_PASSES + schedule.GRACE_SECONDS + 1
    assert schedule.health_exit_code(health, now=stale) == 1


def test_health_is_unhealthy_before_any_pass_finishes(tmp_path):
    """No file at all. The container's start period is what stops this being
    reported while a first slow scan is still running."""
    assert schedule.health_exit_code(tmp_path / "never-written.json") == 1


def test_health_survives_a_truncated_file(tmp_path):
    health = tmp_path / "h.json"
    health.write_text('{"last_run": "2026-0')
    assert schedule.health_exit_code(health) == 1


def test_the_health_file_is_written_whole(tmp_path, monkeypatch):
    """Written beside and renamed, so a healthcheck reading at the wrong
    moment gets the old file rather than half of the new one."""
    health = tmp_path / "h.json"
    schedule.record(health, ok=True, interval=600)
    seen = {}

    real = Path.replace

    def watched(self, target):
        seen["before"] = json.loads(Path(target).read_text())
        return real(self, target)

    monkeypatch.setattr(Path, "replace", watched)
    schedule.record(health, ok=False, interval=600)
    assert seen["before"]["ok"] is True          # the old file, intact


def test_an_unwritable_health_file_does_not_fail_the_pass(tmp_path):
    """A scan that worked is not undone by a volume nobody can write to, but
    it does not go unmentioned either."""
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("x")
    said = []
    code = schedule.run_scheduled(
        lambda: 0, say=said.append, name="t", interval=0,
        path=blocker / "h.json")
    assert code == 0
    assert any("health file" in m for m in said)


# ---- the duplicate ---------------------------------------------------------

def test_the_two_copies_have_not_drifted():
    """schedule.py is duplicated in scanner/ and discovery/ because the two
    images build from their own directories. Duplication is the cost of that;
    silent drift is not."""
    here = Path(__file__).resolve().parents[1] / "schedule.py"
    there = here.parents[1] / "discovery" / "schedule.py"
    assert there.exists(), "discovery/schedule.py is missing"
    assert here.read_bytes() == there.read_bytes(), (
        "scanner/schedule.py and discovery/schedule.py have diverged; "
        "change one and copy it over the other")
