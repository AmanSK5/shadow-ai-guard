"""Paste guard events, and the two things that would make them wrong.

The heartbeat shares this source. It is the same `source: paste_guard` with
`tool: paste-guard` and evidence starting "heartbeat", and it is how a device
proves the guard works rather than merely being installed. Counting it as a
detection would report every device's daily heartbeat as a paste somebody tried
to make: a number wrong in the direction nobody checks, because it only ever
goes up and looks like activity.

And the content must never appear. The guard inspects the clipboard on the
device and reports detector identifiers only. Nothing here may reintroduce a
path that carries what matched, which is asserted structurally rather than
left to review.
"""

import pytest
from app.paste_guard import _parse, paste_guard_from


def _f(**kw):
    base = {
        "tool": "chatgpt.com", "surface": "browser", "source": "paste_guard",
        "severity": "warn", "evidence": "paste warned: aws_access_key",
        "device": "D1", "reported_at": "2026-08-12T09:00:00Z",
    }
    base.update(kw)
    return base


def _heartbeat(device="D1", version="1.3.0"):
    return _f(tool="paste-guard", severity="info", device=device,
              evidence=f"heartbeat version={version} mode=warn reason=installed")


# ─────────────────────────────────────────────
# The heartbeat is not a detection
# ─────────────────────────────────────────────

def test_a_heartbeat_is_not_counted_as_a_paste():
    """The regression. Both share source: paste_guard."""
    out = paste_guard_from([_heartbeat()])

    assert out["events"] == 0
    assert out["rows"] == []


def test_heartbeats_do_not_inflate_the_device_count():
    """Every device sends one daily. A device count that included them would
    report the whole fleet as having pasted something."""
    out = paste_guard_from([_heartbeat("D1"), _heartbeat("D2"), _heartbeat("D3")])

    assert out["devices"] == 0


def test_a_real_paste_is_counted_alongside_heartbeats():
    out = paste_guard_from([_heartbeat("D1"), _f(device="D1"), _heartbeat("D2")])

    assert out["events"] == 1
    assert out["devices"] == 1


def test_a_paste_event_carrying_the_guards_own_name_is_ignored():
    """Belt and braces. A paste event should never be tool: paste-guard, and if
    a future change made one it would be the heartbeat leaking through."""
    out = paste_guard_from([_f(tool="paste-guard")])

    assert out["events"] == 0


# ─────────────────────────────────────────────
# Parsing
# ─────────────────────────────────────────────

@pytest.mark.parametrize("evidence,action,detectors", [
    ("paste warned: aws_access_key", "warned", ["aws_access_key"]),
    # Anything not shaped like a detector id is dropped rather than tidied up.
    # This is the exact string that broke the content test: a parser that
    # split on commas and trusted the rest carried the secret through.
    ("paste warned: aws_access_key (AKIAIOSFODNN7EXAMPLE)", "warned", []),
    ("paste warned: aws_access_key, Not An Id", "warned", ["aws_access_key"]),
    ("paste warned: AWS_ACCESS_KEY", "warned", []),
    ("paste blocked: private_key", "blocked", ["private_key"]),
    ("paste overridden: aws_access_key,payment_card", "overridden",
     ["aws_access_key", "payment_card"]),
    ("paste warned: a, b , c", "warned", ["a", "b", "c"]),
    ("paste warned:", "warned", []),
])
def test_parse_reads_the_action_and_detectors(evidence, action, detectors):
    assert _parse(evidence) == (action, detectors)


@pytest.mark.parametrize("evidence", [
    "heartbeat version=1.3.0 mode=warn reason=installed",
    "paste sniffed: something",     # an action nobody defined
    ".claude.json mcpServers: figma",
    "",
    None,
])
def test_parse_rejects_anything_that_is_not_a_paste_event(evidence):
    """An action nobody recognises is not a paste event. Guessing which of
    three it meant is how a block gets counted as a warning."""
    assert _parse(evidence) == (None, [])


# ─────────────────────────────────────────────
# Counting
# ─────────────────────────────────────────────

def test_actions_are_counted_separately():
    """warned is the guard working. overridden is somebody deciding to paste
    anyway after being shown what it was. Collapsing them into one total would
    lose the only distinction that matters here."""
    out = paste_guard_from([
        _f(evidence="paste warned: aws_access_key"),
        _f(evidence="paste warned: aws_access_key"),
        _f(evidence="paste overridden: aws_access_key"),
        _f(evidence="paste blocked: private_key"),
    ])

    assert (out["warned"], out["overridden"], out["blocked"]) == (2, 1, 1)
    assert out["events"] == 4


def test_rows_are_per_tool_and_keep_both_events_and_devices():
    """Five pastes on one machine and five across five machines are different
    situations, and one number cannot tell them apart."""
    out = paste_guard_from([
        _f(device="D1"), _f(device="D1"), _f(device="D2"),
    ])
    row = out["rows"][0]

    assert row["events"] == 3
    assert row["devices"] == 2


def test_overrides_sort_first():
    """One override matters more than twenty warnings that worked, and sorting
    by event count would bury it."""
    out = paste_guard_from(
        [_f(tool="claude.ai", evidence="paste overridden: private_key")]
        + [_f(tool="chatgpt.com") for _ in range(20)]
    )

    assert out["rows"][0]["tool"] == "claude.ai"


def test_a_tool_reported_by_domain_and_by_id_is_one_row():
    """The extension reports the hostname it saw."""
    from app.derive import load_domain_map_from
    dm = load_domain_map_from({"tools": [{"id": "chatgpt", "domains": ["chatgpt.com"]}]})
    out = paste_guard_from([_f(tool="chatgpt.com"), _f(tool="chatgpt")], dm)

    assert len(out["rows"]) == 1
    assert out["rows"][0]["tool"] == "chatgpt"
    assert out["rows"][0]["events"] == 2


def test_detectors_are_counted_across_the_estate_commonest_first():
    out = paste_guard_from([
        _f(evidence="paste warned: aws_access_key"),
        _f(evidence="paste warned: aws_access_key"),
        _f(evidence="paste warned: payment_card"),
    ])

    assert out["detectors"] == [
        {"detector": "aws_access_key", "count": 2},
        {"detector": "payment_card", "count": 1},
    ]


def test_first_and_last_seen_span_the_events():
    out = paste_guard_from([
        _f(reported_at="2026-08-01T00:00:00Z"),
        _f(reported_at="2026-08-12T00:00:00Z"),
        _f(reported_at="2026-08-05T00:00:00Z"),
    ])
    row = out["rows"][0]

    assert row["first_seen"] == "2026-08-01T00:00:00Z"
    assert row["last_seen"] == "2026-08-12T00:00:00Z"


def test_findings_from_other_sources_are_ignored():
    out = paste_guard_from([
        _f(source="browser_extension", evidence="paste warned: aws_access_key"),
        _f(source="collector-macos", evidence="paste warned: aws_access_key"),
    ])

    assert out["events"] == 0


def test_no_findings_is_an_empty_result_not_an_error():
    out = paste_guard_from([])

    assert out["events"] == 0
    assert out["rows"] == []
    assert out["detectors"] == []


# ─────────────────────────────────────────────
# The content must not be here
# ─────────────────────────────────────────────

def test_the_matched_content_never_appears_in_the_output():
    """Asserted structurally, not by review.

    The guard inspects the clipboard on the device and sends detector
    identifiers. If a future change ever carried the matched text into a
    finding, this module must not pass it on, and a test that only checked the
    fields it expects would not notice a new one appearing.
    """
    import json

    secret = "AKIAIOSFODNN7EXAMPLE"
    out = paste_guard_from([
        # A finding that wrongly carried the content, in two plausible places.
        _f(evidence=f"paste warned: aws_access_key ({secret})"),
        _f(content=secret, matched=secret),
    ])

    assert secret not in json.dumps(out)


def test_only_known_fields_are_carried_from_a_finding():
    """A finding gaining a field must not silently reach the output.

    The receiver's Finding model is not this module's to control, and a new
    field there should require a decision here rather than arriving by
    default.
    """
    import json

    out = paste_guard_from([_f(surprise_field="should not appear",
                               user="someone@example.com")])
    body = json.dumps(out)

    assert "surprise_field" not in body
    assert "should not appear" not in body
    # The user is deliberately absent too: a paste event says a machine tried
    # to paste something, and attributing it to a person is the identity map's
    # job rather than a guess made here.
    assert "someone@example.com" not in body


def test_the_endpoint_returns_metadata_and_excludes_heartbeats():
    """End to end, because the heartbeat exclusion and the domain map both
    live outside paste_guard_from and a unit test would miss either.

    Calls the endpoint function rather than going over HTTP: TestClient needs
    httpx, which is not in the portal's lockfile, and a test that breaks for a
    dependency the thing it tests does not have is a test that breaks for the
    wrong reason.
    """
    import json as _json
    from unittest.mock import patch

    from app import derive
    from app import main as pm

    findings = [_heartbeat("D1"), _heartbeat("D2"),
                _f(device="D1", evidence="paste overridden: aws_access_key"),
                _f(device="D2", tool="chatgpt")]
    reg = {"tools": [{"id": "chatgpt", "domains": ["chatgpt.com"]}]}

    with patch.object(pm, "_findings", lambda h, request=None: findings), \
            patch.object(derive, "load_registry", lambda p: reg):
        pm._cache.clear()
        body = _json.loads(bytes(pm.paste_guard_events(None, hours=168).body))

    assert body["events"] == 2
    assert body["overridden"] == 1
    # Both findings resolve to one tool through the domain map.
    assert [r["tool"] for r in body["rows"]] == ["chatgpt"]
    assert body["devices"] == 2


# ─────────────────────────────────────────────
# The heartbeat as its own signal
# ─────────────────────────────────────────────

def test_devices_running_the_guard_are_counted_from_heartbeats():
    """Zero events means nothing on its own.

    An estate where nobody pasted a secret and an estate where the extension
    was never deployed produce the same event count. The heartbeat is the only
    thing that separates them, and the extension writes lastHeartbeat only on
    confirmed delivery, so a device here has a working chain end to end rather
    than merely the extension installed.
    """
    out = paste_guard_from([_heartbeat("D1"), _heartbeat("D2")])

    assert out["events"] == 0
    assert out["guard_devices"] == 2


def test_heartbeats_still_do_not_count_as_events():
    """Both facts at once: counted as devices, never as detections."""
    out = paste_guard_from([_heartbeat("D1"), _heartbeat("D2"), _f(device="D1")])

    assert out["events"] == 1
    assert out["devices"] == 1
    assert out["guard_devices"] == 2


def test_versions_are_reported_per_device():
    """A fleet split across versions is a rollout that stalled, which is worth
    seeing before somebody wonders why a fix did not take."""
    out = paste_guard_from([
        _heartbeat("D1", "1.3.0"), _heartbeat("D2", "1.3.0"),
        _heartbeat("D3", "1.2.1"),
    ])

    assert out["guard_versions"] == [
        {"version": "1.3.0", "devices": 2},
        {"version": "1.2.1", "devices": 1},
    ]


def test_modes_are_reported_per_device():
    """A device in warn mode where policy says block is a policy not in
    force, and it is invisible in any count of what was stopped."""
    out = paste_guard_from([
        _f(tool="paste-guard", severity="info", device="D1",
           evidence="heartbeat version=1.3.0 mode=block reason=alarm"),
        _f(tool="paste-guard", severity="info", device="D2",
           evidence="heartbeat version=1.3.0 mode=warn reason=alarm"),
    ])

    assert out["guard_modes"] == [
        {"mode": "block", "devices": 1},
        {"mode": "warn", "devices": 1},
    ]


def test_a_device_reporting_several_heartbeats_is_counted_once():
    """They fire on a schedule, so a window contains many per device."""
    out = paste_guard_from([_heartbeat("D1") for _ in range(20)])

    assert out["guard_devices"] == 1


def test_a_malformed_heartbeat_still_counts_the_device():
    """The device checked in, which is the fact that matters. An unparseable
    version is a reason to report fewer details, not to lose the device."""
    out = paste_guard_from([_f(tool="paste-guard", severity="info", device="D1",
                               evidence="heartbeat")])

    assert out["guard_devices"] == 1
    assert out["guard_versions"] == []


def test_no_heartbeats_reports_zero_devices_not_absence():
    out = paste_guard_from([_f()])

    assert out["guard_devices"] == 0
    assert out["guard_versions"] == []