"""The Loki read walks the whole window, and says so when it cannot.

Loki caps one query_range response at `limit` entries. Before issue #104
the portal made one request and presented the newest 5,000 findings as the
whole estate - every register count, coverage number, and checksummed
evidence manifest was silently computed over a sample. The properties that
close that:

- the read paginates backward until a page comes back short of the limit,
- the safety cap (max_findings) stops a pathological window, and stopping
  there is REPORTED via the result's truncated flag, never swallowed,
- page boundaries do not skip or duplicate entries.
"""

import io
import json
import urllib.parse
import urllib.request

import pytest

from app import derive


def _loki_response(entries):
    """One query_range payload: entries as (ts_ns, dict) pairs."""
    values = [(str(ts), json.dumps(doc)) for ts, doc in entries]
    body = json.dumps(
        {"data": {"result": [{"stream": {}, "values": values}]}})
    return io.BytesIO(body.encode())


class _FakeLoki:
    """Answers urlopen the way Loki answers query_range: the newest
    `limit` entries at or before `end`, newest first."""

    def __init__(self, findings):
        # findings: list of (ts_ns, dict), any order
        self.findings = sorted(findings, key=lambda p: p[0], reverse=True)
        self.requests = []  # the (start, end, limit) each call asked for

    def __call__(self, req, timeout=None):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(req.full_url).query)
        start = int(q["start"][0])
        end = int(q["end"][0])
        limit = int(q["limit"][0])
        self.requests.append((start, end, limit))
        window = [(ts, doc) for ts, doc in self.findings
                  if start <= ts <= end]
        # BytesIO is already a context manager, which is all urlopen's
        # caller needs from it.
        return _loki_response(window[:limit])


def _findings(n, newest_ts):
    """n findings one second apart, newest first."""
    step = 1_000_000_000
    return [(newest_ts - i * step, {"tool": "tool-%d" % i, "device": "d"})
            for i in range(n)]


@pytest.fixture
def loki(monkeypatch):
    def install(findings):
        fake = _FakeLoki(findings)
        monkeypatch.setattr(urllib.request, "urlopen", fake)
        return fake
    return install


def test_a_window_larger_than_one_page_is_fetched_completely(loki):
    import time
    now = int(time.time() * 1e9)
    fake = loki(_findings(12, now))
    out = derive.fetch_from_loki("http://loki", hours=1, limit=5)
    assert len(out) == 12
    assert out.truncated is False
    # Three pages: 5 + 5 + 2, and the short page ended the walk.
    assert len(fake.requests) == 3


def test_every_finding_arrives_exactly_once(loki):
    import time
    now = int(time.time() * 1e9)
    fake = loki(_findings(12, now))
    out = derive.fetch_from_loki("http://loki", hours=1, limit=5)
    tools = [f["tool"] for f in out]
    assert sorted(tools) == sorted("tool-%d" % i for i in range(12))
    # Each page asks for strictly older entries than the last: the next
    # end is below the previous page's oldest timestamp, so the boundary
    # entry cannot be served twice.
    ends = [end for _, end, _ in fake.requests]
    assert ends == sorted(ends, reverse=True) and len(set(ends)) == len(ends)


def test_a_single_short_page_costs_one_request(loki):
    import time
    now = int(time.time() * 1e9)
    fake = loki(_findings(3, now))
    out = derive.fetch_from_loki("http://loki", hours=1, limit=5)
    assert len(out) == 3
    assert out.truncated is False
    assert len(fake.requests) == 1


def test_hitting_the_cap_stops_and_is_reported_not_swallowed(loki):
    import time
    now = int(time.time() * 1e9)
    loki(_findings(30, now))
    out = derive.fetch_from_loki("http://loki", hours=1, limit=5,
                                 max_findings=10)
    assert len(out) == 10
    assert out.truncated is True


def test_the_cap_flag_is_false_when_the_cap_was_merely_reached_exactly(loki):
    """Exactly max_findings in the window, landing on a short final page:
    the whole window WAS read, so nothing was truncated."""
    import time
    now = int(time.time() * 1e9)
    loki(_findings(7, now))
    out = derive.fetch_from_loki("http://loki", hours=1, limit=5,
                                 max_findings=7)
    # 5 + 2: the second page is short, the walk ends before the cap check
    # ever fires with a full page in hand.
    assert len(out) == 7
    assert out.truncated is False


def test_a_plain_list_reads_as_complete():
    """Test doubles and old callers hand back plain lists; getattr
    callers must read those as not-truncated rather than crash."""
    assert getattr([], "truncated", False) is False
    assert derive.Findings().truncated is False
