"""Entra ID scanner.

Queries Microsoft Graph API for:
  1. Sign-in logs: SSO authentications to known AI services
  2. Service principals: AI apps registered in the tenant
  3. OAuth2 permission grants: consent grants (delegated + application)

Findings are limited to enabled Member accounts. Guests SSO through this
tenant on their own employer's behalf, so their AI usage is not your
organisation's shadow AI. Disabled accounts are leavers whose sign-ins are
records, not active risk. Service-principal findings carry no user and are
kept.
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
from ai_guard.utils.graph import get_active_member_upns, paginate

logger = logging.getLogger(__name__)


class EntraScanner(BaseScanner):
    name = "entra"

    def __init__(self, registry: Registry, config: ScannerConfig):
        super().__init__(registry, config)
        self._auth: Optional[MSGraphAuth] = None

    def check_prerequisites(self) -> tuple[bool, str]:
        try:
            self._auth = MSGraphAuth.from_env(
                self.config.credential_env_prefix or "AIGUARD_ENTRA"
            )
            return True, "Entra credentials loaded"
        except AuthError as e:
            return False, str(e)

    async def scan(self) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        start = datetime.now(timezone.utc)
        try:
            client = await self._auth.graph_client()

            members = await get_active_member_upns(client)

            findings = await asyncio.gather(
                self._scan_sign_in_logs(client),
                self._scan_service_principals(client),
                self._scan_consent_grants(client),
                return_exceptions=True,
            )
            for batch in findings:
                if isinstance(batch, Exception):
                    result.errors.append(str(batch))
                else:
                    result.findings.extend(batch)

            # Keep findings that either have no user (service principals,
            # tenant-level grants) or belong to an enabled Member.
            before = len(result.findings)
            result.findings = [
                f for f in result.findings
                if f.user_upn is None or f.user_upn.lower() in members
            ]
            dropped = before - len(result.findings)
            if dropped:
                logger.info(
                    "Entra: dropped %d finding(s) for guests/disabled accounts",
                    dropped,
                )

            # Apply target_users filter if configured
            target_users = self.config.options.get("target_users", [])
            if target_users:
                target_set = {u.lower() for u in target_users}
                result.findings = [
                    f for f in result.findings
                    if f.user_upn is None or f.user_upn.lower() in target_set
                ]
                logger.info("Entra scanner filtered to %d target users", len(target_set))

            await client.aclose()
        except Exception as e:
            result.errors.append(f"Entra scan failed: {e}")

        result.duration_seconds = (datetime.now(timezone.utc) - start).total_seconds()
        return result

    async def _scan_sign_in_logs(self, client) -> list[Finding]:
        """Check sign-in logs for authentications to known AI app IDs.

        Follows @odata.nextLink pagination to avoid truncated results.
        """
        findings = []
        lookback = self.config.options.get("lookback_days", 30)
        since = (datetime.now(timezone.utc) - timedelta(days=lookback)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        url = (
            f"/auditLogs/signIns"
            f"?$filter=createdDateTime ge {since}"
            f"&$select=userPrincipalName,appDisplayName,appId,createdDateTime,"
            f"status,resourceDisplayName"
            f"&$top=999"
            f"&$orderby=createdDateTime desc"
        )
        try:
            all_entries = await paginate(client, url)
        except Exception as e:
            raise RuntimeError(
                f"Failed to query sign-in logs (requires Entra ID P1/P2 license): {e}"
            ) from e

        # Aggregate by (user, app) to avoid duplicate findings
        seen: dict[tuple[str, str], Finding] = {}
        for entry in all_entries:
            app_id = entry.get("appId", "")
            app_name = entry.get("appDisplayName", "")
            upn = entry.get("userPrincipalName", "")
            ts = entry.get("createdDateTime", "")

            service = self.registry.match_entra_app_id(app_id)
            if not service:
                # Also try matching app display name against known service names
                for svc in self.registry.services:
                    if svc.name.lower() in app_name.lower():
                        service = svc
                        break
            if not service:
                continue

            key = (upn, service.name)
            if key in seen:
                seen[key].occurrence_count += 1
                seen[key].last_seen = _parse_ts(ts)
            else:
                finding = Finding(
                    service=service,
                    source=DetectionSource.ENTRA_SIGN_IN,
                    risk_tier=service.risk_tier,
                    user_upn=upn,
                    detail=f"SSO sign-in to {service.name} (app: {app_name})",
                    timestamp=_parse_ts(ts),
                    first_seen=_parse_ts(ts),
                    last_seen=_parse_ts(ts),
                    raw_evidence={"app_id": app_id, "app_name": app_name},
                )
                seen[key] = finding

        findings.extend(seen.values())
        return findings

    async def _scan_service_principals(self, client) -> list[Finding]:
        """Check for AI tool service principals registered in the tenant."""
        findings = []
        url = "/servicePrincipals?$select=appId,displayName,appOwnerOrganizationId,publisherName&$top=999"
        try:
            all_sps = await paginate(client, url)
        except Exception as e:
            raise RuntimeError(f"Failed to query service principals: {e}") from e

        for sp in all_sps:
            app_id = sp.get("appId", "")
            display_name = sp.get("displayName", "")
            publisher = sp.get("publisherName", "")

            service = self.registry.match_entra_app_id(app_id)
            if not service:
                # Fuzzy match on display name / publisher
                for svc in self.registry.services:
                    if (
                        svc.name.lower() in display_name.lower()
                        or svc.vendor.lower() in (publisher or "").lower()
                    ):
                        service = svc
                        break
            if not service:
                continue

            findings.append(
                Finding(
                    service=service,
                    source=DetectionSource.ENTRA_SERVICE_PRINCIPAL,
                    risk_tier=service.risk_tier,
                    detail=f"Service principal registered: {display_name} (publisher: {publisher})",
                    raw_evidence={
                        "app_id": app_id,
                        "display_name": display_name,
                        "publisher": publisher,
                    },
                )
            )
        return findings

    async def _scan_consent_grants(self, client) -> list[Finding]:
        """Check for OAuth2 permission grants to known AI services."""
        findings = []
        url = "/oauth2PermissionGrants?$top=999"
        try:
            all_grants = await paginate(client, url)
        except Exception as e:
            raise RuntimeError(f"Failed to query consent grants: {e}") from e

        # We need to resolve clientId (service principal ID) to app details.
        # Build a cache of service principal IDs we care about.
        sp_cache: dict[str, str] = {}  # sp_object_id -> app_id
        for grant in all_grants:
            client_id = grant.get("clientId", "")  # This is the SP object ID
            scope = grant.get("scope", "")
            consent_type = grant.get("consentType", "")
            principal_id = grant.get("principalId", "")

            # Look up the service principal to get the app ID
            if client_id not in sp_cache:
                try:
                    sp_resp = await client.get(
                        f"/servicePrincipals/{client_id}?$select=appId,displayName"
                    )
                    if sp_resp.status_code == 200:
                        sp_data = sp_resp.json()
                        sp_cache[client_id] = sp_data.get("appId", "")
                except Exception as e:
                    logger.warning(
                        "Failed to resolve service principal %s: %s", client_id, e
                    )
                    continue

            app_id = sp_cache.get(client_id, "")
            service = self.registry.match_entra_app_id(app_id)
            if not service:
                continue

            # Resolve principal to UPN if it's a user consent
            upn = None
            if principal_id and consent_type == "Principal":
                try:
                    user_resp = await client.get(
                        f"/users/{principal_id}?$select=userPrincipalName"
                    )
                    if user_resp.status_code == 200:
                        upn = user_resp.json().get("userPrincipalName")
                except Exception as e:
                    logger.debug("Failed to resolve user %s: %s", principal_id, e)

            findings.append(
                Finding(
                    service=service,
                    source=DetectionSource.ENTRA_CONSENT_GRANT,
                    risk_tier=service.risk_tier,
                    user_upn=upn,
                    detail=f"OAuth consent grant for {service.name}: scopes=[{scope}], type={consent_type}",
                    raw_evidence={
                        "app_id": app_id,
                        "scope": scope,
                        "consent_type": consent_type,
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