"""Tests for the scanner entrypoint exit-code logic.

Covers the bug where a partial reporting failure (some sent, some failed)
exited 0, masking lost findings behind a successful CronJob status.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from entrypoint import _exit_code


def test_all_sent_none_failed():
    assert _exit_code(sent=5, failed=0) == 0


def test_some_sent_some_failed():
    assert _exit_code(sent=3, failed=2) == 1


def test_none_sent_all_failed():
    assert _exit_code(sent=0, failed=5) == 1
