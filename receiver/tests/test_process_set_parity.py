"""The three services must agree on what a process name means.

The receiver decides at ingest whether a process becomes a candidate; the
portal decides at render whether it becomes an agentic row; the scanner
decides at collection whether to write "(via ...)" at all. They share no
library, so the sets are written out three times - and three copies of a set
that must agree is a drift risk, which is the shape of bug this whole area
has already produced once.

Checked here rather than assumed. A name treated as a resolver by one service
and a mystery by another produces a candidate for something the portal will
never show, or a row for something the receiver already dismissed.
"""

import os
import pathlib
import sys

os.environ.setdefault("AUTH_TOKEN", "test-token-for-ci")

_ROOT = pathlib.Path(__file__).resolve().parents[2]

from app import main  # noqa: E402


def _load(path, names):
    """Read a module's module-level sets without importing its package."""
    src = (_ROOT / path).read_text()
    ns = {}
    exec(compile(src.split("\ndef ", 1)[0], str(path), "exec"), ns)  # noqa: S102
    return {n: ns[n] for n in names if n in ns}


def test_the_receiver_and_the_portal_agree_on_what_names_nothing():
    portal = (_ROOT / "portal/app/derive.py").read_text()
    start = portal.index("UNATTRIBUTABLE_PROCESSES = {")
    block = portal[start:portal.index("}", start) + 1]
    ns = {}
    exec(compile(block, "derive", "exec"), ns)  # noqa: S102
    assert ns["UNATTRIBUTABLE_PROCESSES"] == main._UNATTRIBUTABLE


def test_the_receiver_and_the_scanner_agree_too():
    scanner = (_ROOT / "scanner/ai_guard/scanners/sentinelone.py").read_text()
    start = scanner.index("_UNATTRIBUTABLE_PROCESSES = {")
    block = scanner[start:scanner.index("}", start) + 1]
    ns = {}
    exec(compile(block, "sentinelone", "exec"), ns)  # noqa: S102
    assert ns["_UNATTRIBUTABLE_PROCESSES"] == main._UNATTRIBUTABLE


def test_a_helper_and_an_exe_normalise_the_same_way_everywhere():
    """Normalisation is written three times too. If the receiver strips a
    suffix the portal keeps, one queues a candidate the other will not show."""
    sys.path.insert(0, str(_ROOT / "scanner"))
    from ai_guard.registry import normalise_process as scanner_norm

    cases = ["OneDrive.Sync.Service.exe", "Google Chrome Helper (Renderer)",
             "chrome.exe", "Claude Helper", "curl", "stable",
             r"C:\Program Files\x\Code.exe"]
    for c in cases:
        assert main._norm_process(c) == scanner_norm(c), c
