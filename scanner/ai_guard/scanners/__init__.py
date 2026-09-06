# Copyright 2026 Aman Karir
# SPDX-License-Identifier: Apache-2.0
# Part of Shadow AI Guard, https://github.com/AmanSK5/shadow-ai-guard

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
