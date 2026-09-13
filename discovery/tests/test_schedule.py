# Copyright 2026 Aman Karir
# SPDX-License-Identifier: Apache-2.0
# Part of Shadow AI Guard, https://github.com/AmanSK5/shadow-ai-guard

"""Discovery's half of the scheduling contract.

The behaviour is covered in full by scanner/tests/test_schedule.py against the
same file. What has to be asserted from this side is that the copy here has
not drifted - CI only runs a component's suite when that component changed, so
a test living solely in the scanner's suite would not see an edit made here -
and that discovery's own exit style survives the wrapper.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import schedule  # noqa: E402


def test_the_two_copies_have_not_drifted():
    """schedule.py is duplicated in scanner/ and discovery/ because the two
    images build from their own directories. Duplication is the cost of that;
    silent drift is not."""
    here = Path(__file__).resolve().parents[1] / "schedule.py"
    there = here.parents[1] / "scanner" / "schedule.py"
    assert there.exists(), "scanner/schedule.py is missing"
    assert here.read_bytes() == there.read_bytes(), (
        "discovery/schedule.py and scanner/schedule.py have diverged; "
        "change one and copy it over the other")


def test_a_fatal_misconfiguration_still_exits_as_before(tmp_path):
    """discovery calls sys.exit on a bad environment. Without an interval it
    is still a CronJob, and the exit code is the only failure signal one has."""
    def bail():
        raise SystemExit(1)

    code = schedule.run_scheduled(bail, say=lambda m: None, name="discovery",
                                  interval=0, path=tmp_path / "h.json")
    assert code == 1


def test_on_an_interval_that_same_exit_is_survivable(tmp_path):
    """A SentinelOne query that fails once must not take the container down:
    a weekly pass would then need a human to start it again."""
    calls = []

    def bail():
        calls.append(1)
        raise SystemExit("DV query did not finish")

    schedule.run_scheduled(bail, say=lambda m: None, name="discovery",
                           interval=604800, path=tmp_path / "h.json",
                           sleep=lambda s: None, passes=2)
    assert len(calls) == 2
    assert json.loads((tmp_path / "h.json").read_text())["ok"] is False


def test_main_returning_none_is_a_successful_pass(tmp_path):
    """discovery's main() returns nothing at all on the happy path, including
    when it finds no candidates, and that is a pass that worked."""
    code = schedule.run_scheduled(lambda: None, say=lambda m: None,
                                  name="discovery", interval=0,
                                  path=tmp_path / "h.json")
    assert code == 0
    assert json.loads((tmp_path / "h.json").read_text())["ok"] is True
