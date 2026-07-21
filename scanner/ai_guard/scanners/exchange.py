"""Exchange Online scanner.

Queries Microsoft Graph for message traces matching known AI service
sender domains. Catches signup confirmations, verification emails, and
usage receipts that indicate a user registered for an AI tool with
their work email.

Required Graph API permission: Mail.ReadBasic.All (application)
This permission allows reading subject, sender, and timestamps only,
NOT email bodies. This is sufficient for signup email detection and
follows the principle of least privilege.

Only enabled Member accounts are scanned. B2B guests have no mailbox in
this tenant (each lookup is a guaranteed 404 × every sender domain), and
disabled accounts are leavers whose mail is history, not shadow AI.

Sender domains are OR-combined into a handful of requests per user
instead of one request per domain: with ~23 registry email domains that
is 4 requests per mailbox rather than 23.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional
from datetime import datetime, timedelta, timezone

from ai_guard.config import ScannerConfig
from ai_guard.registry import Registry
from ai_guard.scanners.base import (
    BaseScanner,
    DetectionSource,
    Finding,
    ScanResult,
)
from ai_guard.utils.auth import AuthError, MSGraphAuth
from ai_guard.utils.graph import GRAPH_V1, get_active_member_upns

logger = logging.getLogger(__name__)

# Signup/verification keywords for subject filtering (applied locally to
# metadata already narrowed server-side to AI sender domains).
SIGNUP_KEYWORDS = [
    "verify", "confirm", "welcome", "activate",
    "sign up", "signup", "registration", "account",
    "get started", "receipt", "subscription", "trial",
]

# How many sender domains to OR into a single $filter. Conservative:
# Graph starts rejecting filters well before URL limits, and 6 keeps the
# expression comfortably simple.
DOMAINS_PER_REQUEST = 6


class ExchangeScanner(BaseScanner):
    name = "exchange"

    def __init__(self, registry: Registry, config: ScannerConfig):
        super().__init__(registry, config)
        self._auth: Optional[MSGraphAuth] = None

    def check_prerequisites(self) -> tuple[bool, str]:
        try:
            # Reuses the same Entra app registration as the Entra scanner
            # but needs Mail.ReadBasic.All application permission
            self._auth = MSGraphAuth.from_env(
                self.config.credential_env_prefix or "AIGUARD_ENTRA"
            )
            return True, "Exchange credentials loaded (via Entra app registration)"
        except AuthError as e:
            return False, str(e)

    async def scan(self) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        start = datetime.now(timezone.utc)
        try:
            client = await self._auth.graph_client()
            lookback = self.config.options.get("lookback_days", 30)

            # Enabled Members only: guests have no mailbox here, disabled
            # accounts are history. This list is what "everyone" means.
            users = sorted(await get_active_member_upns(client))

            target_users = self.config.options.get("target_users", [])
            if target_users:
                target_set = {u.lower() for u in target_users}
                users = [u for u in users if u in target_set]
                logger.info("Exchange scanner scoped to %d target users", len(users))

            logger.info("Exchange: scanning %d mailboxes", len(users))

            skipped_count = 0
            for i, user_upn in enumerate(users):
                if i > 0 and i % 5 == 0:
                    # Pause every 5 users to stay under Graph mailbox limits
                    await asyncio.sleep(2)
                try:
                    user_findings = await self._scan_user_mailbox(
                        client, user_upn, lookback
                    )
                    result.findings.extend(user_findings)
                except Exception as e:
                    skipped_count += 1
                    logger.warning("Exchange: skipped user %s: %s", user_upn, e)

            if skipped_count:
                result.errors.append(
                    f"Exchange: {skipped_count} user(s) skipped due to errors "
                    f"(check logs for details)"
                )
            await client.aclose()
        except Exception as e:
            result.errors.append(f"Exchange scan failed: {e}")

        result.duration_seconds = (datetime.now(timezone.utc) - start).total_seconds()
        return result

    def _domain_chunks(self) -> list[list[str]]:
        domains = sorted(self.registry.all_email_domains)
        return [
            domains[i:i + DOMAINS_PER_REQUEST]
            for i in range(0, len(domains), DOMAINS_PER_REQUEST)
        ]

    @staticmethod
    def _chunk_filter(since: str, chunk: list[str]) -> str:
        """One $filter covering a group of sender domains.

        contains() on the address keeps parity with the previous per-domain
        behaviour; the '@' prefix stops 'openai.com' matching
        'notopenai.com.evil.example'.
        """
        senders = " or ".join(
            f"contains(sender/emailAddress/address, '@{d}')" for d in chunk
        )
        return f"receivedDateTime ge {since} and ({senders})"

    async def _scan_user_mailbox(
        self, client, user_upn: str, lookback_days: int
    ) -> list[Finding]:
        """Search a user's mailbox for emails from known AI service domains.

        Server-side $filter narrows to AI sender domains and the lookback
        window; $select limits the response to metadata. Email bodies are
        never requested.
        """
        findings: list[Finding] = []
        since = (datetime.now(timezone.utc) - timedelta(days=lookback_days)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )

        chunks = self._domain_chunks()
        if not chunks:
            return findings

        # domain -> [message, ...]
        by_domain: dict[str, list[dict]] = {}

        for chunk in chunks:
            url = (
                f"/users/{user_upn}/messages"
                f"?$filter={self._chunk_filter(since, chunk)}"
                f"&$select=sender,receivedDateTime,subject"
                f"&$top=100"
                f"&$orderby=receivedDateTime desc"
            )

            # Follow @odata.nextLink pagination to avoid silently
            # truncated results when a user has many matching messages.
            messages: list[dict] = []
            current_url = url
            for _page in range(20):
                resp = await client.get(current_url)

                # 403/404: no mailbox we can read (unlicensed, on-prem,
                # hidden). If the first chunk says so, the rest will too.
                if resp.status_code in (403, 404):
                    return findings

                # 429: honour Retry-After, retry once, then move on.
                if resp.status_code == 429:
                    wait = int(resp.headers.get("Retry-After", "5"))
                    logger.warning(
                        "Exchange: throttled on %s, waiting %ds", user_upn, wait
                    )
                    await asyncio.sleep(wait)
                    resp = await client.get(current_url)
                    if resp.status_code in (403, 404):
                        return findings
                    if resp.status_code == 429:
                        logger.warning(
                            "Exchange: still throttled on %s, skipping chunk",
                            user_upn,
                        )
                        break

                resp.raise_for_status()
                data = resp.json()
                messages.extend(data.get("value", []))

                next_link = data.get("@odata.nextLink")
                if not next_link:
                    break
                # nextLink is a full URL; strip back to path+query.
                if next_link.startswith(GRAPH_V1):
                    current_url = next_link[len(GRAPH_V1):]
                else:
                    current_url = next_link

            for msg in messages:
                address = (
                    (msg.get("sender") or {})
                    .get("emailAddress", {})
                    .get("address", "")
                ).lower()
                if "@" not in address:
                    continue
                sender_domain = address.rsplit("@", 1)[1]
                # Attribute to the registry domain that matched. The sender
                # may be a subdomain (mail.anthropic.com matched via
                # '@anthropic.com' contains), so suffix-match.
                for d in chunk:
                    if sender_domain == d or sender_domain.endswith("." + d) \
                            or address.endswith("@" + d):
                        by_domain.setdefault(d, []).append(msg)
                        break

        for domain, messages in by_domain.items():
            service = self.registry.match_email_domain(domain)
            if not service:
                continue

            relevant_count = 0
            earliest_ts = None
            latest_ts = None
            for msg in messages:
                subject = (msg.get("subject") or "").lower()
                if any(kw in subject for kw in SIGNUP_KEYWORDS):
                    relevant_count += 1
                    msg_ts = msg.get("receivedDateTime", "")
                    if msg_ts:
                        if earliest_ts is None or msg_ts < earliest_ts:
                            earliest_ts = msg_ts
                        if latest_ts is None or msg_ts > latest_ts:
                            latest_ts = msg_ts

            if relevant_count > 0:
                findings.append(
                    Finding(
                        service=service,
                        source=DetectionSource.EXCHANGE_EMAIL,
                        risk_tier=service.risk_tier,
                        user_upn=user_upn,
                        detail=(
                            f"Received {relevant_count} signup/verification "
                            f"email(s) from {domain}"
                        ),
                        first_seen=_parse_ts(earliest_ts),
                        last_seen=_parse_ts(latest_ts),
                        occurrence_count=relevant_count,
                        raw_evidence={
                            "sender_domain": domain,
                            "message_count": relevant_count,
                        },
                    )
                )
        return findings


def _parse_ts(ts_str: str) -> Optional[datetime]:
    if not ts_str:
        return None
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None