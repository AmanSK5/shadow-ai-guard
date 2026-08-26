"""Vendor user sync for the budget view.

Each provider here is a vendor whose admin API can list the members of a
paid workspace. The receiver holds the connection key (state.py, the same
recoverable-by-design trade as the log store password) and this module
spends it: one outward call per sync, against a URL hardcoded below -
never one the request supplies, so there is nothing here for a crafted
request to point somewhere else.

What a provider returns is a member list, not a judgement: email, name, the
vendor's own role string, a seat tier where the API exposes one, and any
usage counters the vendor reports. The reconciliation against what the
fleet actually does happens in the portal, against findings this module
never sees.

Providers are deliberately few and honest about what each can do:

  anthropic   Claude work orgs (Team / Enterprise). GET /v1/organizations/
              users with a scoped admin key (read:members is enough). The
              API paginates; seat tiers are not exposed, so tier stays
              blank and the operator records tiers on the subscription.
  fireflies   Fireflies.ai. One GraphQL query for the team's users, which
              also reports per-user usage (transcripts, minutes) - the
              rare vendor that hands over the usage half too.

ChatGPT Business is the named absence: OpenAI exposes no admin API on
that plan (SCIM and the Compliance API are Enterprise-only), so it is a
guided CSV import in the portal, and the wizard says so rather than
pretending a connector could exist.
"""

import json

import httpx

# One bound for every provider: a member list bigger than this is either the
# wrong key (a reseller org?) or an API looping; both deserve a refusal
# that names the cap rather than an unbounded crawl.
MAX_MEMBERS = 5000
_TIMEOUT = 15.0

ANTHROPIC_URL = "https://api.anthropic.com/v1/organizations/users"
FIREFLIES_URL = "https://api.fireflies.ai/graphql"

# What the portal needs to offer the wizard: which providers exist, what
# each one's key looks like and where an admin creates it. Data, not
# secrets - served as-is by /admin/budget.
PROVIDERS = {
    "anthropic": {
        "label": "Anthropic (Claude Enterprise / Console)",
        "key_hint": "Scoped Admin API key with the read:members scope. The "
                    "org's primary owner creates it at claude.ai > "
                    "Organization settings > API (Console orgs: Settings > "
                    "Admin keys). Select read-only scopes: this sync never "
                    "writes. Claude Team plans do not offer admin keys - "
                    "the API section simply is not there - so a Team "
                    "workspace uses the Import path instead, from "
                    "Organization settings > Members.",
        "syncs": "members and roles. Seat tiers are not in the API - "
                 "record them on the subscription.",
    },
    "fireflies": {
        "label": "Fireflies.ai",
        "key_hint": "API key from fireflies.ai > Integrations > Fireflies "
                    "API. A team admin's key lists the whole team.",
        "syncs": "members, admin flag, and per-user usage (transcripts, "
                 "minutes).",
    },
}


class SyncError(Exception):
    """A failed sync, carrying what the operator should hear. Never the
    key, and never a raw vendor body - those are logged nowhere and
    echoed nowhere."""


def _refusal(status: int, vendor: str) -> SyncError:
    if status == 401:
        return SyncError("%s answered 401: the key is wrong, expired or "
                         "revoked" % vendor)
    if status == 403:
        return SyncError("%s answered 403: the key lacks the scope this "
                         "sync needs (read:members for Anthropic)" % vendor)
    if status == 429:
        return SyncError("%s answered 429 (rate limited): try again in a "
                         "minute" % vendor)
    return SyncError("%s answered HTTP %d" % (vendor, status))


async def sync_anthropic(api_key: str) -> list[dict]:
    """The org's members via the Anthropic Admin API, all pages.

    Pagination is id-based: page with after_id until has_more is false.
    The page cap backs MAX_MEMBERS - the loop cannot run away even if the
    API misbehaves.
    """
    members: list[dict] = []
    after = ""
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        for _ in range(MAX_MEMBERS // 100 + 1):
            params = {"limit": "100"}
            if after:
                params["after_id"] = after
            try:
                r = await client.get(
                    ANTHROPIC_URL, params=params,
                    headers={"x-api-key": api_key,
                             "anthropic-version": "2023-06-01"})
            except httpx.HTTPError as e:
                raise SyncError("could not reach the Anthropic API (%s)"
                                % type(e).__name__)
            if r.status_code != 200:
                raise _refusal(r.status_code, "the Anthropic API")
            try:
                body = r.json()
            except json.JSONDecodeError:
                raise SyncError("the Anthropic API answered 200, but not "
                                "with JSON")
            for u in body.get("data") or []:
                email = str(u.get("email") or "").strip().lower()
                if not email:
                    continue
                members.append({
                    "email": email,
                    "name": str(u.get("name") or "")[:200],
                    "role": str(u.get("role") or "")[:64],
                    "seat_tier": "",
                    "usage": {},
                })
                if len(members) > MAX_MEMBERS:
                    raise SyncError("more than %d members: refusing rather "
                                    "than store a partial member list as if it "
                                    "were complete" % MAX_MEMBERS)
            if not body.get("has_more"):
                return members
            after = str(body.get("last_id") or "")
            if not after:
                # has_more with no cursor would loop on page one forever.
                return members
    raise SyncError("the Anthropic API kept paginating past %d members"
                    % MAX_MEMBERS)


_FIREFLIES_QUERY = ("{ users { name email is_admin num_transcripts "
                    "minutes_consumed } }")


async def sync_fireflies(api_key: str) -> list[dict]:
    """The team's users via the Fireflies GraphQL API, usage included."""
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        try:
            r = await client.post(
                FIREFLIES_URL, json={"query": _FIREFLIES_QUERY},
                headers={"Authorization": "Bearer " + api_key})
        except httpx.HTTPError as e:
            raise SyncError("could not reach the Fireflies API (%s)"
                            % type(e).__name__)
    if r.status_code != 200:
        raise _refusal(r.status_code, "the Fireflies API")
    try:
        body = r.json()
    except json.JSONDecodeError:
        raise SyncError("the Fireflies API answered 200, but not with JSON")
    if body.get("errors"):
        # GraphQL reports refusals in-band. The first message is the story
        # ("Invalid API key", "not authorized"); the rest repeat it.
        msg = str((body["errors"][0] or {}).get("message") or "error")[:200]
        raise SyncError("the Fireflies API refused the query: %s" % msg)
    users = (body.get("data") or {}).get("users") or []
    if len(users) > MAX_MEMBERS:
        raise SyncError("more than %d members: refusing rather than store "
                        "a partial member list as if it were complete"
                        % MAX_MEMBERS)
    members = []
    for u in users:
        email = str(u.get("email") or "").strip().lower()
        if not email:
            continue
        usage = {}
        if u.get("num_transcripts") is not None:
            usage["transcripts"] = int(u["num_transcripts"] or 0)
        if u.get("minutes_consumed") is not None:
            usage["minutes"] = round(float(u["minutes_consumed"] or 0))
        members.append({
            "email": email,
            "name": str(u.get("name") or "")[:200],
            "role": "admin" if u.get("is_admin") else "member",
            "seat_tier": "",
            "usage": usage,
        })
    return members


SYNCERS = {"anthropic": sync_anthropic, "fireflies": sync_fireflies}
