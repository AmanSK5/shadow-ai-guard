"""Local audit logging for ai-guard.

Writes a tamper-evident audit trail of who ran the tool, which scanners
were invoked, and how many records were processed. The audit log is
written with restricted permissions (chmod 600).

This is separate from report output — the audit log records tool usage,
not findings.
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
