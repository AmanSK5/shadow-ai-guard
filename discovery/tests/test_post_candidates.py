"""The receiver emit path: candidates go to the portal's queue, not a forge.

The properties: the payload matches the receiver's own validation contract
(so a 422 means genuine drift, not routine noise); values the classifier
left unknown travel as empty rather than as the words "unknown"/
"unreviewed"; and a classic receiver (no queue) fails the run loudly with
the fix in the message instead of dropping candidates.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import discover


def _group(**kw):
    base = {
        "name": "Mystery AI",
        "vendor": "unknown",
        "category": "unreviewed",
        "confidence": "high",
        "domains": ["mystery-ai.example"],
        "devices": {"mac-1", "mac-2"},
    }
    base.update(kw)
    return base


class _Resp:
    def __init__(self, status_code=200):
        self.status_code = status_code

    def raise_for_status(self):
        pass


def test_the_payload_matches_the_receivers_contract(monkeypatch):
    sent = []

    def fake_post(url, json=None, headers=None, timeout=None):
        sent.append((url, json, headers))
        return _Resp()

    monkeypatch.setattr(discover.httpx, "post", fake_post)
    monkeypatch.setattr(discover, "RECEIVER_URL", "http://receiver")
    discover.post_candidates(
        [_group(), _group(name="Acme Copilot", vendor="Acme",
                          category="coding", confidence="?")],
        "aigd_test")

    ((url, body, headers),) = sent
    assert url == "http://receiver/candidates"
    assert headers["Authorization"] == "Bearer aigd_test"
    first, second = body["candidates"]
    assert first == {
        "kind": "domain", "name": "Mystery AI", "vendor": "", "category": "",
        "confidence": "high", "domains": ["mystery-ai.example"], "devices": 2,
        "evidence": "seen in fleet DNS over the last 7 days",
    }
    # A concrete vendor/category rides along; an unmapped confidence
    # becomes empty rather than a value the receiver would refuse.
    assert second["vendor"] == "Acme" and second["category"] == "coding"
    assert second["confidence"] == ""


def test_a_big_run_is_posted_in_receiver_sized_batches(monkeypatch):
    sent = []
    monkeypatch.setattr(
        discover.httpx, "post",
        lambda url, json=None, headers=None, timeout=None:
        (sent.append(len(json["candidates"])), _Resp())[1])
    monkeypatch.setattr(discover, "RECEIVER_URL", "http://receiver")
    discover.post_candidates(
        [_group(name="Tool %d" % i) for i in range(130)], "aigd_test")
    assert sent == [100, 30]


def test_a_classic_receiver_fails_the_run_with_the_fix_in_the_message(
        monkeypatch, capsys):
    monkeypatch.setattr(
        discover.httpx, "post",
        lambda url, json=None, headers=None, timeout=None: _Resp(404))
    monkeypatch.setattr(discover, "RECEIVER_URL", "http://receiver")
    with pytest.raises(SystemExit) as e:
        discover.post_candidates([_group()], "aigd_test")
    assert "classic mode" in str(e.value)
    assert "GITLAB" in str(e.value)
