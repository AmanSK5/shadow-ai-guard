#!/usr/bin/env python3
"""ai-guard scanner entrypoint for the daily CronJob.

Differs from `ai-guard scan` on a laptop in three ways:

  1. The registry comes from the receiver's /registry endpoint, so a merged
     discovery MR reaches this scan the next morning with no image rebuild.
  2. Findings are POSTed to the receiver instead of rendered to a terminal.
  3. Scanners that need local files (MCP) are skipped: there are none in a pod.
     MCP configs are covered by the endpoint collector, which runs on devices.

Environment:
  RECEIVER_URL           http://ai-guard-receiver.<namespace>.svc.cluster.local
  RECEIVER_TOKEN         the shared bearer token, or an enrollment token
                         (aige_...) from a managed-mode receiver: the run then
                         enrolls as a scanner and reports with its own credential
  AIGUARD_SCANNER_ID     this scanner's identity on the receiver (default
                         "scanner"; set per deployment if you run several)
  AIGUARD_STATE_DIR      optional writable dir that keeps the device credential
                         between runs (device.cred); unset means enroll per run
  AIGUARD_REGISTRY_URL   $RECEIVER_URL/registry  (set by the CronJob)
  CORPORATE_DOMAIN       example.com
  AIGUARD_*              scanner credentials, from the ai-guard-scanner secret
  DRY_RUN                if set, print the payloads instead of POSTing

Exit codes:
  0  scan completed, findings reported (or none found)
  1  enrollment refused, no scanner could run, or any finding failed to report
"""
from __future__ import annotations


import asyncio

import logging
import os
import sys
from pathlib import Path

from ai_guard.config import Config
from ai_guard.registry import Registry
from ai_guard.scanners.entra import EntraScanner
from ai_guard.scanners.exchange import ExchangeScanner
from ai_guard.scanners.intune import IntuneScanner
from ai_guard.scanners.jamf import JAMFScanner
from ai_guard.scanners.sentinelone import SentinelOneScanner

from receiver_reporter import (DEVICE_PREFIX, ENROLL_PREFIX, EnrollmentError,
                               ReceiverReporter, resolve_credential)

logging.basicConfig(
    level=logging.INFO,
    format='{"ts":"%(asctime)s","level":"%(levelname)s","msg":"%(message)s"}',
)
log = logging.getLogger("ai-guard-scanner")

# MCP is deliberately absent: it reads local config files, of which a pod has
# none. The endpoint collector covers that surface on real devices.
SCANNERS = {
    "sentinelone": SentinelOneScanner,
    "entra": EntraScanner,
    "exchange": ExchangeScanner,
    "intune": IntuneScanner,
    "jamf": JAMFScanner,
}

DRY_RUN = os.environ.get("DRY_RUN", "").strip().lower() in {"1", "true", "yes", "on"}


async def run() -> int:
    policy_path = Path(os.environ.get("POLICY_PATH", "policy.yaml"))
    config = Config.from_file(policy_path) if policy_path.exists() else Config.default()

    # The bearer for the whole run: the registry fetch and every report. In
    # managed mode this is where the scanner enrolls; refused is fatal before
    # any scanning, so the CronJob fails rather than reporting nothing. A dry
    # run does not enroll: it would reissue the real scanner's credential in
    # place (or 409 against it), and printing payloads needs no identity.
    token = os.environ.get("RECEIVER_TOKEN", "")
    if DRY_RUN:
        if token.startswith(ENROLL_PREFIX):
            log.info("dry run: not enrolling; the registry fetch will fall back to the bundled copy")
    else:
        try:
            token = resolve_credential(
                os.environ.get("RECEIVER_URL", ""), token,
                os.environ.get("AIGUARD_SCANNER_ID", "scanner"),
            )
        except EnrollmentError as e:
            log.error("%s", e)
            return 1

    registry = Registry(token=token)  # picks up AIGUARD_REGISTRY_URL from the environment
    if registry.fetch_status == 401 and token.startswith(DEVICE_PREFIX):
        # The stored credential was revoked (or reissued elsewhere). The
        # registry fallback would let the run carry on, find nothing, and
        # exit 0 - a dead scanner with a green CronJob. Loud and fatal instead,
        # and never re-enrolled from here: the operator deletes the stored
        # credential to enroll again.
        log.error("the receiver refused this scanner's device credential (revoked?);"
                  " delete device.cred under AIGUARD_STATE_DIR and supply a valid"
                  " enrollment token to re-enroll")
        return 1
    log.info(
        "registry loaded from %s: %d services, %d bridge targets",
        registry.source,
        len(registry.services),
        len(registry.bridge_targets),
    )
    if not registry.services:
        log.error("registry is empty, refusing to scan")
        return 1

    all_findings = []
    ran = 0

    for name, cls in SCANNERS.items():
        sconf = config.scanners.get(name)
        if not sconf or not sconf.enabled:
            log.info("%s: disabled in policy", name)
            continue

        scanner = cls(registry, sconf)
        ok, message = scanner.check_prerequisites()
        if not ok:
            log.warning("%s: skipped (%s)", name, message)
            continue

        log.info("%s: scanning", name)
        result = await scanner.scan()
        ran += 1

        for err in result.errors:
            log.error("%s: %s", name, err)
        log.info(
            "%s: %d findings in %.1fs",
            name,
            result.finding_count,
            result.duration_seconds,
        )
        all_findings.extend(result.findings)

    if ran == 0:
        log.error("no scanner ran: check credentials and policy.yaml")
        return 1

    if not all_findings:
        log.info("scan complete: no findings")
        return 0

    reporter = ReceiverReporter(token=token, dry_run=DRY_RUN)
    sent, failed = reporter.send(all_findings)

    if DRY_RUN:
        log.info("dry run: %d findings not sent", sent)
        return 0

    log.info("reported %d findings, %d failed", sent, failed)

    # Findings we could not report are findings we do not have. Fail loudly so
    # the CronJob's failure shows up rather than a silently empty dashboard.
    return _exit_code(sent, failed)


def _exit_code(sent: int, failed: int) -> int:
    """Non-zero when any finding failed to report."""
    return 1 if failed > 0 else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(run()))