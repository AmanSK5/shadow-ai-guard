"""Local audit logging for ai-guard.

Records who ran the tool, which scanners were invoked, and how many records
were processed. Written to a file owned by that user at mode 600, appended to
one line at a time.

NOT tamper-evident. It was described that way and the description was wrong.
The file is owned and writable by the same account that runs the scanner, and
appending is a convention rather than a property: anyone who can run the tool
can edit or truncate its record of having done so. Mode 600 keeps other local
users out, which is a different and much smaller claim.

What this is good for is answering "what did this run do" afterwards, and
noticing a scanner that was invoked when nobody meant it to be. What it cannot
do is survive somebody who wants it not to.

An audit trail that resists the person being audited has to leave the machine:
ship these entries to a log store that account cannot write to, or to anything
append-only it does not control. That is a deployment decision rather than a
change here, and worth making before this file is relied on for anything.

Separate from report output: this records tool usage, not findings.
"""

from __future__ import annotations

import getpass
import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Default audit log location.  Override via AIGUARD_AUDIT_LOG env var.
_DEFAULT_AUDIT_DIR = Path.home() / ".ai-guard"
_DEFAULT_AUDIT_FILE = _DEFAULT_AUDIT_DIR / "audit.log"


def _audit_path() -> Path:
    override = os.environ.get("AIGUARD_AUDIT_LOG")
    if override:
        return Path(override)
    return _DEFAULT_AUDIT_FILE


def _ensure_audit_dir(path: Path) -> None:
    """Create the audit log directory with restricted permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.parent.chmod(stat.S_IRWXU)  # 700
    except (OSError, AttributeError):
        pass


def _secure_append(path: Path, line: str) -> None:
    """Append a line to the audit log with restricted permissions."""
    _ensure_audit_dir(path)
    with open(path, "a") as f:
        f.write(line + "\n")
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 600
    except (OSError, AttributeError):
        pass


def log_scan_start(
    scanners: list[str],
    config_path: Optional[str] = None,
) -> None:
    """Record that a scan was started."""
    entry = {
        "event": "scan_start",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "operator": _get_operator(),
        "scanners": scanners,
        "config_path": config_path,
        "pid": os.getpid(),
    }
    _secure_append(_audit_path(), json.dumps(entry))


def log_scan_complete(
    scanners: list[str],
    finding_counts: dict[str, int],
    error_counts: dict[str, int],
    duration_seconds: float,
    output_path: Optional[str] = None,
) -> None:
    """Record that a scan completed."""
    entry = {
        "event": "scan_complete",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "operator": _get_operator(),
        "scanners": scanners,
        "finding_counts": finding_counts,
        "error_counts": error_counts,
        "total_findings": sum(finding_counts.values()),
        "duration_seconds": round(duration_seconds, 1),
        "output_path": output_path,
        "pid": os.getpid(),
    }
    _secure_append(_audit_path(), json.dumps(entry))


def log_mcp_scan(config_path: str) -> None:
    """Record an MCP scan invocation."""
    entry = {
        "event": "mcp_scan",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "operator": _get_operator(),
        "config_path": config_path,
        "pid": os.getpid(),
    }
    _secure_append(_audit_path(), json.dumps(entry))


def _get_operator() -> str:
    """Best-effort identification of who is running the tool."""
    try:
        return getpass.getuser()
    except Exception:
        return os.environ.get("USER", os.environ.get("USERNAME", "unknown"))