"""Shared Microsoft Graph helpers.

Both the Entra and Exchange scanners need the same two things: pagination
that follows @odata.nextLink, and the set of users that actually count as
"our users" — enabled Member accounts, not B2B guests and not disabled
leavers. Guests generate mailbox 404s in Exchange and misattributed
findings in Entra; disabled accounts are history, not shadow AI.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

GRAPH_V1 = "https://graph.microsoft.com/v1.0"


async def paginate(client, url: str, max_pages: int = 20) -> list[dict]:
    """Follow @odata.nextLink pagination to collect all results.

    Prevents silent data truncation when results exceed the page size.
    """
    all_items: list[dict] = []
    current_url = url
    for page in range(max_pages):
        resp = await client.get(current_url)
        resp.raise_for_status()
        data = resp.json()
        all_items.extend(data.get("value", []))
        next_link = data.get("@odata.nextLink")
        if not next_link:
            break
        # nextLink is a full URL — the client already has base_url set,
        # so strip it back to path+query.
        if next_link.startswith(GRAPH_V1):
            current_url = next_link[len(GRAPH_V1):]
        else:
            current_url = next_link
        if page == max_pages - 1:
            logger.warning(
                "Graph: hit pagination limit (%d pages) for %s — "
                "results may be incomplete",
                max_pages, url[:80],
            )
    return all_items


async def get_active_member_upns(client) -> set[str]:
    """UPNs of enabled Member users — the accounts that count as our users.

    Excludes:
      * Guests (userType eq 'Guest'): B2B collaborators invited into the
        tenant. They have no mailbox here, and their AI usage is their own
        employer's problem, not your organisation's shadow AI.
      * Disabled accounts: leavers and service stubs. Their historical
        sign-ins are records, not active shadow AI.

    The filter runs server-side. userType belongs to Graph's "advanced
    query" set, which wants ConsistencyLevel: eventual plus $count — both
    are harmless on tenants where the plain filter would also have worked,
    so they are always sent.

    Returned lowercased, because every comparison against this set is
    case-insensitive.
    """
    url = (
        "/users"
        "?$filter=userType eq 'Member' and accountEnabled eq true"
        "&$select=userPrincipalName"
        "&$count=true"
        "&$top=999"
    )
    client.headers["ConsistencyLevel"] = "eventual"
    try:
        users = await paginate(client, url)
    finally:
        client.headers.pop("ConsistencyLevel", None)

    upns = {
        u["userPrincipalName"].lower()
        for u in users
        if u.get("userPrincipalName")
    }
    logger.info("Graph: %d active member users in tenant", len(upns))
    return upns