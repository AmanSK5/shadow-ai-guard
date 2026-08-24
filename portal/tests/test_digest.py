"""The weekly digest: the schedule computation and the text it sends.

The background loop itself is not under test - it is a sleep around these
two functions. What can be quietly wrong is the arithmetic (a digest that
fires on the wrong day, or twice) and the text (numbers that disagree with
the pages the reader opens next), so those are what get pinned down.
"""

import os
from datetime import datetime, timezone

os.environ.setdefault("PORTAL_AUTH", "none")

from app import main


def dt(y, m, d, h=0):
    return datetime(y, m, d, h, tzinfo=timezone.utc)


# 2026-08-24 is a Monday.


def test_next_digest_is_the_coming_slot():
    # Sunday evening -> Monday 08:00.
    assert main.next_digest(dt(2026, 8, 23, 20), "mon", 8) == dt(2026, 8, 24, 8)
    # Monday 07:59 -> the same morning.
    assert main.next_digest(dt(2026, 8, 24, 7), "mon", 8) == dt(2026, 8, 24, 8)


def test_next_digest_never_returns_now_or_the_past():
    # Exactly on the slot -> a week later, so a send at 08:00 cannot
    # reschedule itself for the moment it just fired.
    assert main.next_digest(dt(2026, 8, 24, 8), "mon", 8) == dt(2026, 8, 31, 8)
    # Monday afternoon -> next Monday.
    assert main.next_digest(dt(2026, 8, 24, 15), "mon", 8) == dt(2026, 8, 31, 8)


def test_next_digest_unknown_day_falls_back_to_monday():
    assert main.next_digest(dt(2026, 8, 22, 0), "someday", 8).weekday() == 0


def test_digest_text_carries_the_numbers_the_pages_show():
    g = {
        "personal_accounts": [
            {"user": "kaya", "device": "MAC-1", "tool": "chatgpt"},
            {"user": "", "device": "WIN-2", "tool": "gemini"},
        ],
        "counts": {"tools": 9, "devices": 61},
        "tools": {"chatgpt": {"devices": ["a", "b"]},
                  "claude": {"devices": ["a"]}},
    }
    s = {"groups": [
        {"group": "endpoint", "sources": [{"source": "x", "reporting": True}]},
        {"group": "cloud", "sources": [{"source": "y", "reporting": False},
                                       {"source": "z", "reporting": False}]},
    ]}
    text = main.digest_text(g, s, 168)
    assert "last 7 days" in text
    assert "2 personal accounts across 2 people" in text
    assert "9 tools in use on 61 devices" in text
    assert "chatgpt (2)" in text
    assert "2 detection sources silent" in text


def test_digest_text_singular_forms_and_empty_estate():
    g = {"personal_accounts": [{"user": "kaya", "device": "", "tool": "t"}],
         "counts": {"tools": 0, "devices": 0}, "tools": {}}
    text = main.digest_text(g, {"groups": []}, 24)
    assert "1 personal account across 1 person" in text
    assert "top tools" not in text
    assert "silent" not in text
