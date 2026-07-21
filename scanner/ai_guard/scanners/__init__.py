"""Scanner modules for AI tool discovery."""

from ai_guard.scanners.entra import EntraScanner
from ai_guard.scanners.sentinelone import SentinelOneScanner
from ai_guard.scanners.exchange import ExchangeScanner
from ai_guard.scanners.intune import IntuneScanner
from ai_guard.scanners.jamf import JAMFScanner
from ai_guard.scanners.mcp import MCPScanner

ALL_SCANNERS = {
    "entra": EntraScanner,
    "sentinelone": SentinelOneScanner,
    "exchange": ExchangeScanner,
    "intune": IntuneScanner,
    "jamf": JAMFScanner,
    "mcp": MCPScanner,
}

__all__ = [
    "EntraScanner",
    "SentinelOneScanner",
    "ExchangeScanner",
    "IntuneScanner",
    "JAMFScanner",
    "MCPScanner",
    "ALL_SCANNERS",
]
