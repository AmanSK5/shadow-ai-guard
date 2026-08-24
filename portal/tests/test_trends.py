"""Tests for trends_from: the per-day series behind the overview's sparklines
and deltas.

The rest of the portal is totals over the window; this is the one derivation
that keeps time. The properties that matter: findings land in the right UTC
day bucket, per-tool activity counts distinct devices rather than findings, a
cloud-only tool does not flatline at zero, and the excluded classes (the
platform's own agents, bridge targets) stay excluded here as everywhere else.
"""

import os
from datetime import datetime, timedelta, timezone

os.environ.setdefault("PORTAL_AUTH", "none")

from app import derive


def day(offset=0, hour=12):
    """An ISO timestamp `offset` days before now, inside the current day."""
    t = datetime.now(timezone.utc) - timedelta(days=offset)
    return t.replace(hour=hour, minute=0, second=0, microsecond=0) \
            .strftime("%Y-%m-%dT%H:%M:%SZ")


def finding(**kw):
    f = {
        "tool": "claude-code", "surface": "cli", "os": "macos",
        "account_domain": "", "device": "MAC-1", "user": "sam",
        "severity": "info", "source": "collector-macos",
        "reported_at": day(0),
    }
    f.update(kw)
    return f


def test_window_shape_and_day_order():
    t = derive.trends_from([], hours=168)
    assert len(t["days"]) == 7
    assert t["days"] == sorted(t["days"])          # oldest first
    assert t["days"][-1] == datetime.now(timezone.utc).date().isoformat()
    assert t["devices"] == [0] * 7
    assert t["personal"] == [0] * 7


def test_findings_land_in_their_day_and_devices_are_distinct():
    fs = [
        finding(reported_at=day(2)),
        finding(reported_at=day(2), surface="ide"),   # same device, same day
        finding(reported_at=day(2), device="MAC-2"),
        finding(reported_at=day(0)),
    ]
    t = derive.trends_from(fs, hours=168)
    assert t["devices"][-3] == 2      # two distinct devices two days ago
    assert t["devices"][-1] == 1
    assert t["tools"]["claude-code"][-3] == 2
    assert t["tools"]["claude-code"][-1] == 1


def test_personal_series_counts_warn_with_account_only():
    fs = [
        finding(severity="warn", account_domain="gmail.com"),
        finding(severity="warn", account_domain=""),      # no account: not personal
        finding(severity="info", account_domain="gmail.com"),
    ]
    t = derive.trends_from(fs, hours=168)
    assert t["personal"][-1] == 1


def test_cloud_only_tool_falls_back_to_findings_per_day():
    fs = [finding(tool="fireflies", surface="cloud", device="",
                  source="entra_sign_in"),
          finding(tool="fireflies", surface="cloud", device="",
                  source="entra_sign_in")]
    t = derive.trends_from(fs, hours=168)
    assert t["tools"]["fireflies"][-1] == 2


def test_agents_and_bridges_are_not_tools_here_either():
    fs = [finding(tool="paste-guard"),
          finding(tool="slack", source="sentinelone_bridge")]
    t = derive.trends_from(fs, hours=168)
    assert "paste-guard" not in t["tools"]
    assert "slack" not in t["tools"]
    # ...but the machine still counts as active: the agent ran on it.
    assert t["devices"][-1] == 1


def test_tool_first_seen_is_the_oldest_timestamp():
    fs = [finding(reported_at=day(1)), finding(reported_at=day(5))]
    t = derive.trends_from(fs, hours=168)
    assert t["tool_first_seen"]["claude-code"] == day(5)


def test_out_of_window_findings_are_ignored():
    t = derive.trends_from([finding(reported_at="2020-01-01T00:00:00Z")],
                           hours=168)
    assert sum(t["devices"]) == 0


def test_graph_carries_trends():
    g = derive.graph_from([finding()], hours=48)
    assert len(g["trends"]["days"]) == 2
    assert sum(g["trends"]["devices"]) == 1
