"""Entra sign-in log handling.

Two behaviours worth pinning:

  1. Only successful sign-ins count as usage. A Conditional Access block is
     the control working, not shadow AI, and reporting it as usage sends
     someone chasing a user who never got in.
  2. first_seen and last_seen bracket the real window. Graph returns newest
     first, so anything that assigns rather than compares ends up with the
     two inverted.
"""

import asyncio

import pytest

from ai_guard.config import ScannerConfig
from ai_guard.registry import AIService
from ai_guard.scanners import entra as entra_mod
from ai_guard.scanners.entra import EntraScanner

SERVICE = AIService(
    name="ChatGPT",
    vendor="OpenAI",
    category="chatbot",
    risk_tier="high",
    entra_app_ids=["app-chatgpt"],
)


class FakeRegistry:
    """Only the two members EntraScanner touches during a sign-in scan."""

    services = [SERVICE]

    def match_entra_app_id(self, app_id):
        return SERVICE if app_id == "app-chatgpt" else None


def _entry(ts, error_code=0, upn="alice@example.com"):
    return {
        "userPrincipalName": upn,
        "appDisplayName": "ChatGPT",
        "appId": "app-chatgpt",
        "createdDateTime": ts,
        "status": {"errorCode": error_code},
    }


def _run(entries, monkeypatch):
    async def fake_paginate(client, url, max_pages=20):
        return entries

    monkeypatch.setattr(entra_mod, "paginate", fake_paginate)
    scanner = EntraScanner(FakeRegistry(), ScannerConfig(enabled=True))
    return asyncio.run(scanner._scan_sign_in_logs(client=None))


def test_failed_sign_ins_are_not_usage(monkeypatch):
    """A blocked attempt must not produce a finding."""
    findings = _run(
        [
            _entry("2026-07-20T10:00:00Z", error_code=53003),  # CA blocked
            _entry("2026-07-19T10:00:00Z", error_code=50126),  # bad password
        ],
        monkeypatch,
    )
    assert findings == []


def test_failed_sign_ins_do_not_inflate_the_count(monkeypatch):
    """One success among failures counts once, not three times."""
    findings = _run(
        [
            _entry("2026-07-20T10:00:00Z", error_code=53003),
            _entry("2026-07-19T10:00:00Z", error_code=0),
            _entry("2026-07-18T10:00:00Z", error_code=53003),
        ],
        monkeypatch,
    )
    assert len(findings) == 1
    assert findings[0].occurrence_count == 1


def test_missing_status_is_ignored_rather_than_assumed_good(monkeypatch):
    """An entry with no status must not be counted as a successful sign-in."""
    entry = _entry("2026-07-20T10:00:00Z")
    del entry["status"]
    assert _run([entry], monkeypatch) == []


def test_seen_window_is_not_inverted(monkeypatch):
    """Graph returns newest first; first_seen must still be the oldest."""
    findings = _run(
        [
            _entry("2026-07-20T10:00:00Z"),
            _entry("2026-07-15T10:00:00Z"),
            _entry("2026-07-10T10:00:00Z"),
        ],
        monkeypatch,
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.occurrence_count == 3
    assert f.first_seen.day == 10, "first_seen should be the oldest sign-in"
    assert f.last_seen.day == 20, "last_seen should be the newest sign-in"
    assert f.first_seen < f.last_seen


def test_seen_window_survives_reordered_results(monkeypatch):
    """Order-independent: the window is correct whatever order Graph returns."""
    findings = _run(
        [
            _entry("2026-07-15T10:00:00Z"),
            _entry("2026-07-20T10:00:00Z"),
            _entry("2026-07-10T10:00:00Z"),
        ],
        monkeypatch,
    )
    f = findings[0]
    assert f.first_seen.day == 10
    assert f.last_seen.day == 20


def test_distinct_users_produce_distinct_findings(monkeypatch):
    findings = _run(
        [
            _entry("2026-07-20T10:00:00Z", upn="alice@example.com"),
            _entry("2026-07-20T11:00:00Z", upn="bob@example.com"),
        ],
        monkeypatch,
    )
    assert {f.user_upn for f in findings} == {
        "alice@example.com",
        "bob@example.com",
    }
