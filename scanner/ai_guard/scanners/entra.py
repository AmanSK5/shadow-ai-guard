"""Entra ID scanner.

Queries Microsoft Graph API for:
  1. Sign-in logs: SSO authentications to known AI services
  2. Delegated access: services using a token they were granted earlier
  3. Service principals: AI apps registered in the tenant
  4. OAuth2 permission grants: consent grants (delegated + application)

Findings are limited to enabled Member accounts. Guests SSO through this
tenant on their own employer's behalf, so their AI usage is not your
organisation's shadow AI. Disabled accounts are leavers whose sign-ins are
records, not active risk. Service-principal findings carry no user and are
kept.

Only successful sign-ins count as usage. A blocked attempt is an access
control working, whether that is app assignment or Conditional Access,
not shadow AI to report.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
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
from ai_guard.utils.graph import GRAPH_BETA, get_active_member_upns, paginate

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
                self._scan_delegated_access(client),
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
        """Check sign-in logs for successful authentications to known AI apps.

        Only successful sign-ins count as usage. A failed attempt means the
        user tried and did not get in, which is frequently Conditional Access
        working as intended; counting those as usage overstates exposure and
        reports a working control as a finding.

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
            f"&$select=userPrincipalName,appDisplayName,appId,createdDateTime,status"
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
        failed = 0
        no_status = 0

        for entry in all_entries:
            status = entry.get("status")
            if not isinstance(status, dict) or "errorCode" not in status:
                # Absent rather than failed. Do not guess, and do not let a
                # change to the $select silently inflate the numbers.
                no_status += 1
                continue
            if status.get("errorCode") != 0:
                failed += 1
                continue

            app_id = entry.get("appId", "")
            app_name = entry.get("appDisplayName", "")
            upn = entry.get("userPrincipalName", "")
            ts = _parse_ts(entry.get("createdDateTime", ""))

            service = self.registry.match_entra_app_id(app_id)
            if not service:
                service = _match_service_by_name(self.registry, app_name)
            if not service:
                continue

            key = (upn, service.name)
            if key in seen:
                found = seen[key]
                found.occurrence_count += 1
                # Compare rather than assign. Graph returns newest first, so
                # assigning would leave the oldest timestamp in last_seen.
                # Comparing also survives a change to the $orderby.
                if ts:
                    if found.first_seen is None or ts < found.first_seen:
                        found.first_seen = ts
                    if found.last_seen is None or ts > found.last_seen:
                        found.last_seen = ts
            else:
                seen[key] = Finding(
                    service=service,
                    source=DetectionSource.ENTRA_SIGN_IN,
                    risk_tier=service.risk_tier,
                    user_upn=upn,
                    detail=f"SSO sign-in to {service.name} (app: {app_name})",
                    timestamp=ts,
                    first_seen=ts,
                    last_seen=ts,
                    raw_evidence={"app_id": app_id, "app_name": app_name},
                )

        if failed:
            logger.info(
                "Entra: ignored %d failed sign-in(s); only successful "
                "authentications count as usage",
                failed,
            )
        if no_status:
            logger.warning(
                "Entra: %d sign-in(s) had no status field and were ignored. "
                "Check the $select in the signIns query.",
                no_status,
            )

        findings.extend(seen.values())
        return findings

    async def _scan_delegated_access(self, client) -> list[Finding]:
        """Ongoing delegated access: an AI service using a token it already holds.

        The sign-in scan above sees interactive sign-ins, which is a person in
        front of a browser. It misses the case where a service was consented to
        once and has been reading someone's data ever since: no sign-in, no
        browser, just the vendor's backend refreshing a token against Graph.

        On a real tenant those two populations barely overlap. For one AI
        service over a day and a half: one user interactive, eight users
        non-interactive, no user in both. Those eight were invisible.

        Three things shape how this is done:

        Query per app, not tenant-wide. Unfiltered non-interactive sign-ins
        paginate past 999 in under two days and take about 25 seconds; filtered
        to one app it is a fraction of a page and a few seconds.

        Drive off service principals, not registry app ids. Most registry
        entries carry no entra_app_ids, so keying on those would miss the
        services that matter. The tenant's own service principal list already
        says which AI apps exist here, and the registry matches them by name.

        Count events, report relationships. Fifteen token refreshes and one
        token refresh mean the same thing: the service has access and is using
        it. Findings aggregate per user and app across the window, the same
        shape as the sign-in scan, with occurrence_count carrying the volume.
        """
        findings: list[Finding] = []
        lookback = self.config.options.get("lookback_days", 30)
        since = (datetime.now(timezone.utc) - timedelta(days=lookback)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )

        apps = await self._tenant_ai_app_ids(client)
        if not apps:
            logger.info("Entra: no known AI service principals in tenant, "
                        "skipping delegated access scan")
            return findings

        for app_id, service in apps.items():
            # signInEventTypes lives on the beta endpoint. paginate() only
            # rewrites nextLinks that start with the v1.0 base, so a beta
            # absolute URL passes through untouched and httpx uses it as is.
            url = (
                f"{GRAPH_BETA}/auditLogs/signIns"
                f"?$filter=signInEventTypes/any(t: t eq 'nonInteractiveUser')"
                f" and createdDateTime ge {since}"
                f" and appId eq '{app_id}'"
                # No $select. authenticationProcessingDetails carries the OAuth
                # scopes, which is the field that makes this finding a judgement
                # rather than an inventory, and Graph silently omits it from a
                # restricted projection. The payload is larger; the alternative
                # is a finding that cannot tell a calendar read from a mail read.
                f"&$top=200"
            )
            try:
                entries = await paginate(client, url)
            except Exception as e:
                # One app failing should not lose the others. The scan result
                # carries the error; it does not vanish.
                logger.warning(
                    "Entra: delegated access query failed for %s: %r",
                    service.name, e,
                )
                continue

            seen: dict[str, Finding] = {}
            failed = 0

            for entry in entries:
                # Same rule as the sign-in scan: a failed token refresh is not
                # access being used, it is access being refused.
                status = entry.get("status")
                if not isinstance(status, dict) or "errorCode" not in status:
                    continue
                if status.get("errorCode") != 0:
                    failed += 1
                    continue

                upn = entry.get("userPrincipalName", "")
                if not upn:
                    continue
                ts = _parse_ts(entry.get("createdDateTime", ""))
                scopes = _oauth_scopes(entry)

                found = seen.get(upn)
                if found:
                    found.occurrence_count += 1
                    if ts:
                        if found.first_seen is None or ts < found.first_seen:
                            found.first_seen = ts
                        if found.last_seen is None or ts > found.last_seen:
                            found.last_seen = ts
                    # Scopes can differ between refreshes. Keep the union, so
                    # a permission that appeared once is not lost behind the
                    # one that appeared last.
                    merged = set(found.raw_evidence.get("scopes", [])) | set(scopes)
                    found.raw_evidence["scopes"] = sorted(merged)
                    continue

                looks_like_bot = _looks_like_service_account(upn, service)
                seen[upn] = Finding(
                    service=service,
                    source=DetectionSource.ENTRA_DELEGATED_ACCESS,
                    risk_tier=service.risk_tier,
                    user_upn=upn,
                    detail=(
                        f"{service.name} holds delegated access and is using it"
                        + (" (service account)" if looks_like_bot else "")
                    ),
                    timestamp=ts,
                    first_seen=ts,
                    last_seen=ts,
                    raw_evidence={
                        "app_id": app_id,
                        "app_name": entry.get("appDisplayName", ""),
                        "scopes": sorted(set(scopes)),
                        "resource": entry.get("resourceDisplayName", ""),
                        "credential_type": entry.get("clientCredentialType", ""),
                        # Named rather than hidden. The check is a guess based
                        # on the account name matching the service, and a guess
                        # that silently drops findings is worse than one that
                        # labels them.
                        "service_account_guess": looks_like_bot,
                    },
                )

            if failed:
                logger.info(
                    "Entra: ignored %d failed token refresh(es) for %s",
                    failed, service.name,
                )
            # Scopes only reach the detail once the union is final.
            for f in seen.values():
                scopes = f.raw_evidence.get("scopes", [])
                if scopes:
                    f.detail += f", scopes: {', '.join(scopes)}"
            findings.extend(seen.values())

        return findings

    async def _tenant_ai_app_ids(self, client) -> dict:
        """app id -> service, for AI services with a service principal here.

        Deliberately a separate query rather than reusing the service principal
        scan's results: that scan runs concurrently with this one, and coupling
        them would mean serialising the scan or passing state between two
        coroutines for the sake of one cheap call.
        """
        url = "/servicePrincipals?$select=appId,displayName,publisherName&$top=999"
        apps: dict = {}
        try:
            all_sps = await paginate(client, url)
        except Exception as e:
            logger.warning("Entra: could not list service principals: %s", e)
            return apps

        for sp in all_sps:
            app_id = sp.get("appId", "")
            display_name = sp.get("displayName", "") or ""
            publisher = sp.get("publisherName", "") or ""
            if not app_id:
                continue
            service = self.registry.match_entra_app_id(app_id)
            if not service:
                service = _match_service_by_name(self.registry, display_name)
            if service:
                apps[app_id] = service
        return apps

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
                service = _match_service_by_name(self.registry, display_name)
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


def _match_service_by_name(registry, display_name: str):
    """Match a registry service to an application's display name.

    Whole words, and the longest name wins.

    A substring match makes "Continue" a match for anything containing the
    word inside another, and a plain first-match loop lets "Claude" claim an
    application called "Claude Code" purely because it appears earlier in the
    registry. Both put a confident, wrong tool name on a finding, which is
    worse than no finding: somebody acts on it.

    Publisher is deliberately not consulted. Matching a registry vendor
    against publisherName meant every application published by Microsoft or
    Google matched whichever of their tools the registry happened to list
    first. That never fired on the tenant this was written against, because
    publisherName came back empty there, so it was latent rather than
    harmless.
    """
    if not display_name:
        return None
    haystack = display_name.lower()
    best_name = ""
    best_svc = None
    for svc in registry.services:
        name = (svc.name or "").lower()
        if not name:
            continue
        # Lookarounds rather than \b: several registry names end in
        # punctuation ("Fireflies.ai", "Microsoft Copilot (Free)"), where \b
        # does not match the way it reads like it should.
        if re.search(r"(?<!\w)" + re.escape(name) + r"(?!\w)", haystack):
            if len(name) > len(best_name):
                best_name, best_svc = name, svc
    return best_svc


def _oauth_scopes(entry: dict) -> list[str]:
    """Delegated permissions from a sign-in's processing details.

    Graph puts them in authenticationProcessingDetails as a key/value list,
    where the value is itself a JSON array in a string. This is the field that
    turns a finding into a judgement: Calendars.Read on a meeting transcription
    tool is the job, Mail.Read or Files.ReadWrite.All on the same tool is not.
    """
    details = entry.get("authenticationProcessingDetails") or []
    if not isinstance(details, list):
        return []
    for item in details:
        if not isinstance(item, dict):
            continue
        if item.get("key") != "Oauth Scope Info":
            continue
        raw = item.get("value") or ""
        try:
            parsed = json.loads(raw)
        except (ValueError, TypeError):
            return []
        if isinstance(parsed, list):
            return [str(s) for s in parsed if s]
        return []
    return []


def _looks_like_service_account(upn: str, service) -> bool:
    """Whether a principal is probably the vendor's own account, not a person.

    A guess, and labelled as one wherever it is used. The alternative is a
    flag in the registry, which would be exact but needs every deployment to
    maintain it. Getting this wrong labels a person as a bot, which is visible
    and correctable; suppressing the finding instead would not be.
    """
    local = (upn or "").split("@", 1)[0].lower().replace(".", "").replace("-", "")
    if not local:
        return False
    name = (service.name or "").lower().replace(" ", "").replace(".", "")
    vendor = (service.vendor or "").lower().replace(" ", "").replace(".", "")
    return bool(name and local == name) or bool(vendor and local == vendor)


def _parse_ts(ts_str: str) -> Optional[datetime]:
    if not ts_str:
        return None
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None