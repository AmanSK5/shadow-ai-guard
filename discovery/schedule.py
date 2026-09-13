# Copyright 2026 Aman Karir
# SPDX-License-Identifier: Apache-2.0
# Part of Shadow AI Guard, https://github.com/AmanSK5/shadow-ai-guard

"""Run a scheduled job once, or on a repeat, from the same image.

Under Kubernetes these components are CronJobs: one pass, then exit, and the
scheduler owns the timing. Docker Compose has no scheduler at all - there is
no `schedule:` key and never has been - so a Compose deployment had no way to
run them, and got a receiver and a portal with two of the four components
quietly missing. Under Compose the same image now runs as an ordinary
long-lived service and keeps its own time.

AIGUARD_RUN_INTERVAL picks between the two. Unset or 0 means one pass and
exit, which is what a CronJob wants and what these components have always
done, so the Kubernetes side is unchanged. Anything else is the gap between
passes.

The gap is measured from the end of one pass to the start of the next rather
than as a wall-clock period, so a pass that runs long delays the next one
instead of stacking on top of it. That is the same bargain as
`concurrencyPolicy: Forbid` on the CronJob side.

A failed pass does NOT exit. Exiting would restart the container and hammer
whatever had just refused it - a scanner that cannot reach the receiver would
do that for as long as nobody was watching. The failure is recorded and the
next pass runs on schedule; sustained failure surfaces through the health
file instead.

The health file records when a pass last SUCCEEDED, not when one last ran. A
wedged loop looks exactly like a healthy container from the outside, and the
timestamp that tells the two apart is the one that stops moving when things
go wrong.

This file is deliberately duplicated in scanner/ and discovery/ rather than
shared. The two images build from their own directories (CI passes
`context: <component>`), so sharing it would mean moving both build contexts
to the repository root for fifty lines. A test in each suite asserts the two
copies have not drifted.
"""
from __future__ import annotations

import json
import os
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

DEFAULT_HEALTH_FILE = "/tmp/ai-guard-health.json"

# Below this the interval is almost certainly a typo, and honouring it would
# point a scanner at the receiver in a tight loop. Floored, with a line in the
# log saying so, rather than refused: a deployment that starts is easier to
# diagnose than one that does not.
MIN_INTERVAL = 60

# How far past a due pass the health file still reads as healthy: one whole
# missed pass, plus five minutes. Tight enough to notice a wedged loop within
# a cycle, loose enough that one slow scan is not reported as a failure.
GRACE_PASSES = 2
GRACE_SECONDS = 300

_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def interval_seconds(raw: str | None = None) -> int:
    """Seconds between passes, or 0 for a single pass.

    Accepts plain seconds or a suffixed value: 90s, 30m, 6h, 1d.
    """
    if raw is None:
        raw = os.environ.get("AIGUARD_RUN_INTERVAL", "")
    raw = (raw or "").strip().lower()
    if not raw:
        return 0
    unit = _UNITS.get(raw[-1], 1)
    digits = raw[:-1] if raw[-1] in _UNITS else raw
    try:
        value = int(digits)
    except ValueError:
        raise ValueError(
            "AIGUARD_RUN_INTERVAL: expected seconds, or a value like 6h, "
            f"got {raw!r}"
        ) from None
    if value < 0:
        raise ValueError(f"AIGUARD_RUN_INTERVAL cannot be negative, got {raw!r}")
    return value * unit


def health_path() -> Path:
    return Path(os.environ.get("AIGUARD_HEALTH_FILE", DEFAULT_HEALTH_FILE))


def _read(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return {}


def record(path: Path, *, ok: bool, interval: int,
           say: Callable[[str], None] | None = None) -> None:
    """Write the heartbeat, carrying the last success through a failed pass."""
    now = datetime.now(timezone.utc)
    previous = _read(path).get("last_success")
    body = {
        "last_run": now.isoformat(timespec="seconds"),
        "last_success": now.isoformat(timespec="seconds") if ok else previous,
        "ok": ok,
        "interval": interval,
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # Written beside and renamed: a healthcheck reading at the wrong
        # moment gets the old file, never half of the new one.
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(body))
        tmp.replace(path)
    except OSError as e:
        # The health file is an aid. Losing it must never fail a pass that
        # otherwise worked, but silence here would be the second unexplained
        # thing in a row, so it is said out loud.
        if say:
            say(f"could not write the health file at {path}: {e}")


def health_exit_code(path: Path | None = None,
                     now: float | None = None) -> int:
    """0 while a pass has succeeded recently enough, 1 otherwise.

    Everything it needs is in the file, including the interval, so the
    healthcheck does not have to be given the same environment as the run.
    """
    path = path or health_path()
    state = _read(path)
    if not state:
        # No file at all. During the container's start period this is simply
        # too early and the runtime ignores the result; after it, a component
        # that has never finished a pass is not healthy.
        return 1
    interval = int(state.get("interval") or 0)
    if not interval:
        # Single-pass mode. The container exits when the pass ends, so there
        # is no liveness to assert and nothing to report as stale.
        return 0
    last = state.get("last_success")
    if not last:
        return 1
    try:
        when = datetime.fromisoformat(last).timestamp()
    except ValueError:
        return 1
    now = time.time() if now is None else now
    return 0 if now - when <= interval * GRACE_PASSES + GRACE_SECONDS else 1


def _one_pass(job: Callable[[], int | None], say: Callable[[str], None]) -> int:
    """Run the job once and turn anything it does into an exit code."""
    try:
        code = job()
    except SystemExit as e:
        # Both components use sys.exit for a fatal misconfiguration.
        code = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
    except Exception:
        say("pass failed with an unhandled error")
        say(traceback.format_exc())
        return 1
    return 0 if code is None else int(code)


def run_scheduled(job: Callable[[], int | None], *,
                  say: Callable[[str], None],
                  name: str,
                  interval: int | None = None,
                  path: Path | None = None,
                  sleep: Callable[[float], None] = time.sleep,
                  passes: int | None = None) -> int:
    """One pass and exit, or a pass every interval for as long as it runs.

    `passes` bounds the loop for tests; production leaves it None, which is
    forever.
    """
    interval = interval_seconds() if interval is None else interval
    path = path or health_path()

    if not interval:
        code = _one_pass(job, say)
        record(path, ok=code == 0, interval=0, say=say)
        return code

    if interval < MIN_INTERVAL:
        say(f"{name}: interval {interval}s is below the {MIN_INTERVAL}s floor, using the floor")
        interval = MIN_INTERVAL

    say(f"{name}: running now and every {interval}s after each pass finishes; "
        f"health at {path}")
    done = 0
    while passes is None or done < passes:
        code = _one_pass(job, say)
        record(path, ok=code == 0, interval=interval, say=say)
        if code != 0:
            # Deliberately not fatal. See the module docstring: exiting here
            # restarts the container against whatever just refused it.
            say(f"{name}: pass failed (exit {code}); the next one runs in {interval}s")
        done += 1
        if passes is not None and done >= passes:
            break
        sleep(interval)
    return 0
