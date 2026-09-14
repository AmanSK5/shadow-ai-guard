# Copyright 2026 Aman Karir
# SPDX-License-Identifier: Apache-2.0
# Part of Shadow AI Guard, https://github.com/AmanSK5/shadow-ai-guard

"""A read in parallel spans, and a reader that keeps the window.

Two properties matter more than the speed either buys:

- a parallel read returns exactly what a serial one does - no finding lost
  or repeated at a span boundary, and the cap still keeps the newest and
  still says when it cut,
- an incremental read answers what a full read would have answered at the
  same moment: new findings arrive once, old ones age out, and anything
  the reader cannot vouch for sends it back to a full read.
"""

import io
import json
import urllib.parse
import urllib.request

import pytest

from app import derive

HOUR = 3600 * 10**9
END = 1_800_000_000 * 10**9  # a fixed "now", so spans are deterministic


class _FakeLoki:
    """query_range as Loki answers it: the newest `limit` entries in
    [start, end], newest first. Values arrive grouped by stream, which is
    why the read sorts each page."""

    def __init__(self, findings):
        self.findings = []
        self.requests = []
        self.add(findings)

    def add(self, findings):
        self.findings = sorted(self.findings + list(findings),
                               key=lambda p: p[0], reverse=True)

    def __call__(self, req, timeout=None):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(req.full_url).query)
        start, end, limit = (int(q["start"][0]), int(q["end"][0]),
                             int(q["limit"][0]))
        self.requests.append((start, end, limit))
        window = [(ts, doc) for ts, doc in self.findings
                  if start <= ts <= end][:limit]
        odd = [(str(ts), json.dumps(d)) for i, (ts, d) in enumerate(window) if i % 2]
        even = [(str(ts), json.dumps(d)) for i, (ts, d) in enumerate(window) if not i % 2]
        body = {"data": {"result": [{"stream": {"s": "a"}, "values": odd},
                                    {"stream": {"s": "b"}, "values": even}]}}
        return io.BytesIO(json.dumps(body).encode())


@pytest.fixture
def loki(monkeypatch):
    def install(findings):
        fake = _FakeLoki(findings)
        monkeypatch.setattr(urllib.request, "urlopen", fake)
        return fake
    return install


def _spread(n, newest, span, tag="f"):
    """n findings evenly over `span` ns ending at `newest`, newest first."""
    step = span // n
    return [(newest - i * step, {"tool": "%s-%d" % (tag, i)}) for i in range(n)]


def test_a_parallel_read_returns_exactly_what_a_serial_read_does(loki):
    loki(_spread(3000, END, 168 * HOUR))
    serial = derive.fetch_from_loki("http://loki", 168, limit=100, end_ns=END)
    par = derive.fetch_from_loki("http://loki", 168, limit=100, end_ns=END,
                                 parallel=4)
    assert par.timestamps == sorted(serial.timestamps, reverse=True)
    assert len(set(par.timestamps)) == 3000
    assert par.truncated is False and serial.truncated is False
    assert [f["tool"] for f in par] == [
        f["tool"] for _, f in sorted(zip(serial.timestamps, serial), key=lambda e: -e[0])]


def test_findings_on_span_edges_are_neither_lost_nor_repeated(loki):
    spans = 28
    width = (168 * HOUR) // spans
    edge_ts = set()
    for i in range(spans + 1):
        for d in (-1, 0, 1):
            ts = END - i * width + d
            if END - 168 * HOUR <= ts <= END:
                edge_ts.add(ts)
    loki([(ts, {"tool": "edge"}) for ts in edge_ts])
    par = derive.fetch_from_loki("http://loki", 168, limit=7, end_ns=END,
                                 parallel=5)
    assert sorted(par.timestamps) == sorted(edge_ts)


def test_a_parallel_read_at_the_cap_keeps_the_newest_and_says_so(loki):
    loki(_spread(3000, END, 168 * HOUR))
    par = derive.fetch_from_loki("http://loki", 168, limit=100, end_ns=END,
                                 parallel=4, max_findings=1000)
    newest = sorted((ts for ts, _ in _spread(3000, END, 168 * HOUR)),
                    reverse=True)[:1000]
    assert par.timestamps == newest
    assert par.truncated is True


def test_a_parallel_read_that_reaches_the_cap_exactly_with_nothing_older_is_whole(loki):
    # All inside the newest span, ending on a short page: that span is known
    # to be whole, so only the older spans are in question.
    fake = loki(_spread(450, END, 5 * HOUR))
    par = derive.fetch_from_loki("http://loki", 168, limit=100, end_ns=END,
                                 parallel=2, max_findings=450)
    assert len(par) == 450
    assert par.truncated is False
    # Older spans were not walked: one probe asked whether anything existed.
    assert any(limit == 1 for _, _, limit in fake.requests)


def _reader(clock, **kw):
    return derive.IncrementalLokiReader(clock=lambda: clock[0], **kw)


def _fetch(hours, limit=100, max_findings=100_000, parallel=1):
    return lambda **window: derive.fetch_from_loki(
        "http://loki", hours, limit=limit, max_findings=max_findings,
        parallel=parallel, **window)


def test_the_second_read_asks_only_for_what_is_new(loki):
    fake = loki(_spread(1200, END, 24 * HOUR))
    clock = [END / 1e9]
    reader = _reader(clock, overlap_seconds=60)
    first = reader.read("store", _fetch(24), 24, 100_000)
    assert len(first) == 1200 and reader.last["mode"] == "full"

    fake.add([(END + 10**9 * s, {"tool": "new-%d" % s}) for s in range(1, 51)])
    clock[0] += 60
    fake.requests.clear()
    second = reader.read("store", _fetch(24), 24, 100_000)

    assert reader.last == {"mode": "incremental", "new": 50}
    assert all(start >= END - 60 * 10**9 for start, _, _ in fake.requests)
    assert len(fake.requests) == 1
    assert len(second) == 1250   # the oldest is still inside the window
    assert len(set(second.timestamps)) == len(second)
    assert second.timestamps == sorted(second.timestamps, reverse=True)
    assert second[0]["tool"] == "new-50"


def test_what_leaves_the_window_leaves_the_reader(loki):
    loki(_spread(240, END, 24 * HOUR))
    clock = [END / 1e9]
    reader = _reader(clock)
    reader.read("store", _fetch(24), 24, 100_000)
    clock[0] += 2 * 3600
    later = reader.read("store", _fetch(24), 24, 100_000)
    cutoff = END + 2 * HOUR - 24 * HOUR
    assert min(later.timestamps) >= cutoff
    # Window starts are inclusive: 22 hours of six-minute steps is 221.
    assert len(later) == 221


def test_a_different_log_store_is_read_in_full(loki):
    loki(_spread(100, END, HOUR))
    clock = [END / 1e9]
    reader = _reader(clock)
    reader.read("store-a", _fetch(24), 24, 100_000)
    reader.read("store-b", _fetch(24), 24, 100_000)
    assert reader.last["mode"] == "full"


def test_it_reads_in_full_again_after_the_resync_interval(loki):
    loki(_spread(100, END, HOUR))
    clock = [END / 1e9]
    reader = _reader(clock, resync_seconds=100)
    reader.read("store", _fetch(24), 24, 100_000)
    clock[0] += 50
    reader.read("store", _fetch(24), 24, 100_000)
    assert reader.last["mode"] == "incremental"
    clock[0] += 51
    reader.read("store", _fetch(24), 24, 100_000)
    assert reader.last["mode"] == "full"


def test_a_wider_window_than_the_one_held_is_a_full_read(loki):
    loki(_spread(480, END, 48 * HOUR))
    clock = [END / 1e9]
    reader = _reader(clock)
    # Six-minute steps and an inclusive window start: 24 hours is 241.
    assert len(reader.read("store", _fetch(24), 24, 100_000)) == 241
    wide = reader.read("store", _fetch(48), 48, 100_000)
    assert reader.last["mode"] == "full" and len(wide) == 480
    narrow = reader.read("store", _fetch(24), 24, 100_000)
    assert reader.last["mode"] == "incremental" and len(narrow) == 241


def test_more_than_the_cap_since_the_last_read_falls_back_to_a_full_read(loki):
    fake = loki(_spread(50, END, HOUR))
    clock = [END / 1e9]
    reader = _reader(clock)
    reader.read("store", _fetch(24, limit=20, max_findings=100), 24, 100)
    fake.add([(END + 10**6 * i, {"tool": "burst"}) for i in range(1, 201)])
    clock[0] += 1
    out = reader.read("store", _fetch(24, limit=20, max_findings=100), 24, 100)
    assert reader.last["mode"] == "full"
    assert len(out) == 100 and out.truncated is True


def test_the_cap_holds_across_incremental_reads(loki):
    fake = loki(_spread(100, END, HOUR))
    clock = [END / 1e9]
    reader = _reader(clock)
    first = reader.read("store", _fetch(24, max_findings=100), 24, 100)
    assert len(first) == 100
    fake.add([(END + 10**9 * s, {"tool": "more"}) for s in range(1, 31)])
    clock[0] += 60
    out = reader.read("store", _fetch(24, max_findings=100), 24, 100)
    assert reader.last["mode"] == "incremental"
    assert len(out) == 100 and out.truncated is True
    assert out.timestamps[0] == END + 30 * 10**9


def test_a_narrower_window_inside_a_capped_store_is_not_called_truncated(loki):
    fake = loki(_spread(100, END, 24 * HOUR))
    fake.add([(END - 10**9 * s, {"tool": "recent"}) for s in range(1, 11)])
    clock = [END / 1e9]
    reader = _reader(clock)
    reader.read("store", _fetch(24, max_findings=50), 24, 50)
    recent = reader.read("store", _fetch(24, max_findings=50), 0.01, 50)
    assert recent.truncated is False


def test_a_stand_in_without_timestamps_is_passed_through_and_not_kept():
    clock = [END / 1e9]
    reader = _reader(clock)
    calls = []

    def fetch(**window):
        calls.append(window)
        return [{"tool": "x"}]

    assert reader.read("store", fetch, 24, 10) == [{"tool": "x"}]
    assert reader.read("store", fetch, 24, 10) == [{"tool": "x"}]
    assert len(calls) == 2 and reader.last["mode"] == ""


def test_the_portal_reads_incrementally_after_the_first_read(monkeypatch, loki):
    import time
    from app import main as portal_main

    now = int(time.time() * 1e9)
    fake = loki(_spread(300, now, 6 * HOUR))
    monkeypatch.setattr(portal_main, "LOKI_URL", "http://loki.example.com:3100")
    monkeypatch.setattr(portal_main, "LOKI_INCREMENTAL", True)
    monkeypatch.setattr(portal_main, "_loki_reader", derive.IncrementalLokiReader())

    assert len(portal_main._findings(24)) == 300
    assert portal_main._loki_reader.last["mode"] == "full"
    fake.add([(int(time.time() * 1e9), {"tool": "latest"})])
    again = portal_main._findings(24)
    assert portal_main._loki_reader.last["mode"] == "incremental"
    assert len(again) == 301 and again[0]["tool"] == "latest"
