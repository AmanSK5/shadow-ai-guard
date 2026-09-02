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
  devin       Cognition, covering Devin and Devin Desktop (the IDE that
              was Codeium, then Windsurf). GET the org's members with a
              service-user key. Teams reaches this too, not just
              Enterprise - one of the few vendors here where that is
              true - so the wizard does not send a Teams admin to Import.

ChatGPT Business is the named absence: OpenAI exposes no admin API on
that plan (SCIM and the Compliance API are Enterprise-only), so it is a
guided CSV import in the portal, and the wizard says so rather than
pretending a connector could exist.
"""

import json
import re
import time

import httpx

# One bound for every provider: a member list bigger than this is either the
# wrong key (a reseller org?) or an API looping; both deserve a refusal
# that names the cap rather than an unbounded crawl.
MAX_MEMBERS = 5000
_TIMEOUT = 15.0

ANTHROPIC_URL = "https://api.anthropic.com/v1/organizations/users"
FIREFLIES_URL = "https://api.fireflies.ai/graphql"
OPENAI_URL = "https://api.openai.com/v1/organization/users"
CURSOR_URL = "https://api.cursor.com/teams/members"
CHATGPT_SCIM_URL = "https://api.openai.com/scim/v2"
NOTION_SCIM_URL = "https://api.notion.com/scim/v2"
GRAMMARLY_SCIM_URL = "https://app.grammarly.com/scim/v2"
# The only vendor here needing an id in the path. %s is filled from the
# operator's stored key, never from a request, and only after _DEVIN_ORG
# has passed it - so the host and path are as fixed as every other URL.
DEVIN_URL = "https://api.devin.ai/v3beta1/organizations/%s/members/users"
_DEVIN_ORG = re.compile(r"^org-[A-Za-z0-9_-]{1,64}$")

# What the portal needs to offer the wizard: which providers exist, what
# each one's key looks like and where an admin creates it. Data, not
# secrets - served as-is by /admin/budget.
PROVIDERS = {
    "anthropic": {
        "label": "Anthropic (Claude Enterprise / Console)",
        # What plan the admin API needs. Stated only where it is actually
        # known: Anthropic documents that Team has no admin keys, so that
        # one is a fact. Fireflies below does not get a guess.
        "plan": "Enterprise, or a Console org. Team plans have no admin "
                "API at all.",
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
    "chatgpt": {
        "label": "ChatGPT workspace (Enterprise or Edu)",
        "plan": "Enterprise or Edu. Business - the plan renamed from Team in "
                "2025 - has SSO but no SCIM, so it uses Import.",
        "key_hint": "SCIM API token from the workspace admin console, "
                    "Settings > Security > SCIM Provisioning. It is issued by "
                    "OpenAI rather than by your identity provider, and this "
                    "reads the same endpoint your IdP writes to - no IdP is "
                    "needed to use it. Codex CLI has no member list of its "
                    "own: tick it under \"also covers\".",
        "syncs": "members and whether the account is active. SCIM carries no "
                 "seat tier or usage - record tiers on the subscription.",
        "unverified": True,
    },
    "notion": {
        "label": "Notion (Enterprise)",
        "plan": "Enterprise only - Free, Plus and Business cannot mint a "
                "SCIM token at all.",
        "key_hint": "SCIM API token created by an organisation owner under "
                    "Manage organization. Notion issues it, not your identity "
                    "provider, and this reads the same endpoint an IdP would "
                    "write to.",
        "syncs": "members and whether the account is active. No seat tier or "
                 "usage - record tiers on the subscription.",
        "unverified": True,
    },
    "grammarly": {
        "label": "Grammarly (Pro or Enterprise)",
        "plan": "Pro or Enterprise, and SAML SSO has to be configured first - "
                "Grammarly will not issue the token before it is.",
        "key_hint": "SCIM token from the Admin Panel, Settings > SSO & "
                    "Provisioning.",
        "syncs": "members and whether the account is active.",
        "unverified": True,
    },
    "openai": {
        "label": "OpenAI (API platform organisation)",
        "plan": "Any organisation, with an Admin API key. This is the API "
                "platform org - a ChatGPT workspace is SCIM-only and uses "
                "Import.",
        "key_hint": "Admin API key, created at platform.openai.com > "
                    "Settings > Organization > Admin keys by an owner. An "
                    "ordinary project API key will not work: admin keys are "
                    "the only ones the organization endpoints accept.",
        "syncs": "members and their org role. Seat tiers are not in the "
                 "API - record them on the subscription.",
        # Written from OpenAI's documented endpoint and NOT yet run against a
        # real organisation. The first operator to point it at one is the
        # test; a refusal here names the vendor and the status rather than
        # failing silently.
        "unverified": True,
    },
    "cursor": {
        "label": "Cursor (Team or Enterprise)",
        "plan": "Team or Enterprise - both expose it, unusually.",
        "key_hint": "Team API key from cursor.com > Settings > Cursor "
                    "Admin API. Sent as HTTP Basic with the key as the "
                    "username and no password, which is what their curl "
                    "example shows.",
        "syncs": "members and their team role. Removed members are dropped "
                 "rather than counted as seats.",
        "unverified": True,
    },
    "fireflies": {
        "label": "Fireflies.ai",
        # Fireflies' own knowledge base says API access is available on every
        # plan level, and neither the `users` query nor the API-key article
        # names a tier or an admin role. The "Business or higher" gate people
        # quote is on the separate `analytics` query, which this connector
        # does not use: the per-user counters it reports are fields on
        # `users` itself.
        "plan": "Any plan. Fireflies documents API access at every plan "
                "level, and the team-users query names no tier.",
        "key_hint": "API key from fireflies.ai > Integrations > Fireflies "
                    "API. A team admin's key lists the whole team.",
        "syncs": "members, admin flag, and per-user usage (transcripts, "
                 "minutes).",
    },
    "devin": {
        "label": "Devin / Devin Desktop (Cognition)",
        # Teams genuinely reaches this - the docs give Teams its own API
        # quick start, and a Teams org admin can mint a service user. That
        # is worth stating plainly, because the assumption in this file
        # everywhere else is that a member list means Enterprise.
        "plan": "Teams or Enterprise. Both can create a service user and "
                "read their own org's members; Enterprise additionally "
                "reaches the cross-org endpoints this sync does not use.",
        "key_hint": "Service user API key (starts with cog_), plus the "
                    "organisation id, entered as one value: "
                    "org-xxxx:cog_xxxx. An org admin creates both in the "
                    "same place - Settings > Service Users - where the "
                    "org id is shown and Create service user issues the "
                    "key. The key is shown once. Member role is enough: "
                    "this sync only reads. Windsurf licences live here "
                    "too, since Cognition folded Windsurf into Devin.",
        "syncs": "members and their role names. Seat tiers and usage are "
                 "not on this endpoint - record tiers on the "
                 "subscription.",
    },
}


# What each SHIPPED registry tool's vendor can tell an administrator about who
# holds a seat. PROVIDERS above is the subset this receiver has actually
# implemented; this is the wider map, so the portal can answer the operator's
# real question - "why is my tool not in the Automatic list?" - with either
# "its vendor offers nothing" or "its vendor does, and we have not built it
# yet", which is a far more useful thing to open an issue about.
#
# `api` is what the VENDOR offers, not what we support:
#   rest      a REST/GraphQL admin endpoint that lists members
#   scim      SCIM 2.0 only, which means provisioning through an IdP
#   none      no organisation or seat list exists to read
#   unknown   not documented publicly, or not established
#
# `plan` records the tier, and says so honestly where a tier is not documented.
# Checked against vendor documentation in August 2026. Vendors move these gates
# often - anything here that starts costing an operator a wasted afternoon
# should be re-checked rather than trusted because it is written down.
MEMBER_APIS = {
    "claude": {
        "api": "rest", "connector": "anthropic",
        "plan": "Enterprise, or a Console org. Team plans have no admin API.",
        "how": "Admin API, GET /v1/organizations/users.",
    },
    "claude-code": {
        "api": "rest", "connector": "anthropic",
        "plan": "Enterprise, or a Console org.",
        "how": "Same Anthropic org as Claude - one licence, one member list.",
    },
    "chatgpt": {
        "api": "scim", "connector": "chatgpt",
        "plan": "Enterprise or Edu only. Business (renamed from Team in 2025) "
                "has SSO but not SCIM.",
        "how": "SCIM 2.0 at api.openai.com/scim/v2. The token comes from "
               "OpenAI's own admin console, so no IdP is involved.",
    },
    "codex-cli": {
        "api": "rest", "connector": "chatgpt",
        "plan": "Whatever pays for it.",
        "how": "No member list of its own - it rides the ChatGPT workspace or "
               "the API platform org. Tick it under \"also covers\".",
    },
    "openai-api-platform": {
        "api": "rest", "connector": "openai",
        "plan": "Any organisation, with an Admin API key.",
        "how": "GET /v1/organization/users.",
    },
    "gemini": {
        "api": "rest",
        "plan": "Google Workspace, Business Standard or higher for Gemini.",
        "how": "Licences are assigned in Workspace; the Admin SDK Directory "
               "and Enterprise License Manager APIs list who holds one.",
    },
    "gemini-cli": {
        "api": "rest",
        "plan": "Google Workspace, or a Google Cloud project for Code Assist.",
        "how": "Same Workspace licence assignment as Gemini.",
    },
    "github-copilot": {
        "api": "rest",
        "plan": "Copilot Business or Copilot Enterprise.",
        "how": "GET /orgs/{org}/copilot/billing/seats. Org owner, with a token "
               "carrying manage_billing:copilot and read:org.",
    },
    "cursor": {
        "api": "rest", "connector": "cursor",
        "plan": "Team or Enterprise - both, unusually.",
        "how": "Admin API, GET /teams/members with a Team API key.",
    },
    "codeium": {
        "api": "rest", "connector": "devin",
        # This entry used to say Enterprise-only, which was true of the old
        # Windsurf analytics API and stopped being true when Cognition moved
        # the product onto Devin's platform: Teams has its own API quick
        # start and can mint a service user. An operator on Teams was being
        # told to go and do a CSV import they did not need.
        "plan": "Teams or Enterprise, via Cognition's Devin API - the "
                "licence is one and the same since the Windsurf "
                "acquisition.",
        "how": "GET /v3beta1/organizations/{org}/members/users with a "
               "service-user key.",
    },
    "tabnine": {
        "api": "rest",
        "plan": "Enterprise, SaaS console or self-hosted.",
        "how": "Admin APIs for teams and users, plus SCIM IdP sync.",
    },
    "warp": {
        "api": "unknown", "plan": "",
        "how": "Warp Teams and Enterprise manage members in the Warp "
               "dashboard; no public members endpoint is documented. "
               "Unknown rather than none - nobody has looked properly.",
    },
    "cline": {
        "api": "unknown",
        "plan": "Enterprise.",
        "how": "Cline Enterprise manages members in its own dashboard; a "
               "public members API is not documented.",
    },
    "roo-code": {
        "api": "none", "plan": "",
        "how": "An open-source extension on your own model keys. There is no "
               "vendor account, so there is no seat list to read.",
    },
    "continue": {
        "api": "none", "plan": "",
        "how": "An open-source extension on your own model keys. No vendor "
               "seat list.",
    },
    "otter": {
        "api": "rest",
        "plan": "Enterprise. SCIM Directory Sync additionally needs 100+ seats.",
        "how": "The public API is Enterprise-only, bearer authenticated.",
    },
    "grammarly": {
        "api": "scim", "connector": "grammarly",
        "plan": "Pro or Enterprise, and SAML SSO has to be on first.",
        "how": "SCIM 2.0 at app.grammarly.com/scim/v2.",
    },
    "wispr-flow": {
        "api": "scim",
        "plan": "Enterprise.",
        "how": "Admin portal at admin.wisprflow.ai with SCIM provisioning; the "
               "enterprise API covers audit logs rather than a member list.",
    },
    "perplexity": {
        "api": "scim",
        "plan": "Enterprise Pro at 50+ seats, or Enterprise Max at any size.",
        "how": "SCIM through your IdP only - there is no admin REST API, and "
               "the SCIM token is issued during onboarding, not self-served.",
    },
    "mistral": {
        "api": "rest",
        "plan": "Enterprise. The Admin API is in preview.",
        "how": "console.mistral.ai/api/admin, x-api-key.",
    },
    "grok": {
        "api": "rest",
        "plan": "Grok Business, or an xAI organisation.",
        "how": "Management API at management-api.x.ai with a management key.",
    },
    "microsoft-copilot": {
        "api": "rest",
        "plan": "Any tenant with a Microsoft 365 admin.",
        "how": "Microsoft Graph: subscribedSkus and per-user licenseDetails "
               "say who holds the add-on.",
    },
    "microsoft-365-copilot": {
        "api": "rest",
        "plan": "An add-on to M365 E3/E5 or Business Standard/Premium.",
        "how": "Microsoft Graph, the same licence assignment as any other "
               "M365 service.",
    },
    "atlassian-rovo": {
        "api": "rest",
        "plan": "Not documented. An organisation API key is what it needs; "
                "which plans can mint one is not stated publicly.",
        "how": "Organizations REST API, GET /v2/orgs/{orgId}/directories/"
               "{directoryId}/users.",
    },
    "notion-ai": {
        "api": "scim", "connector": "notion",
        "plan": "Enterprise only - Free, Plus and Business cannot use SCIM.",
        "how": "SCIM for provisioning; the ordinary Notion API's /v1/users "
               "also lists workspace members with an integration token.",
    },
    "fireflies": {
        "api": "rest", "connector": "fireflies",
        "plan": "Any plan - API access is documented at every plan level.",
        "how": "One GraphQL query for the team's users, with per-user usage. "
               "The separate analytics query needs Business or higher; this "
               "does not use it.",
    },
    "hugging-face": {
        "api": "rest",
        "plan": "Any organisation for the members list; SCIM needs Enterprise "
                "Hub with SSO enabled.",
        "how": "GET /api/organizations/{org}/members.",
    },
    "deepseek": {
        "api": "unknown", "plan": "",
        "how": "The open platform issues API keys; no organisation member "
               "endpoint is documented publicly.",
    },
    "midjourney": {
        "api": "none", "plan": "",
        "how": "Individual subscriptions. There is no organisation, so there "
               "is no seat list.",
    },
    "ollama": {
        "api": "none", "plan": "",
        "how": "Runs locally with no account at all - there is nobody to list.",
    },
    "lm-studio": {
        "api": "none", "plan": "",
        "how": "A local desktop app with no account.",
    },
}


class SyncError(Exception):
    """A failed sync, carrying what the operator should hear. Never the
    key, and never a raw vendor body - those are logged nowhere and
    echoed nowhere.

    The message lives in .detail, assigned from this module's own
    templates at each raise site. The route reads that field rather than
    str()-ing the caught exception, so nothing exception-shaped flows
    into a response body - the property CodeQL's stack-trace-exposure
    query checks for, held structurally instead of by convention."""

    def __init__(self, detail: str):
        self.detail = detail
        super().__init__(detail)


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


async def sync_openai(api_key: str) -> list[dict]:
    """The organisation's members via the OpenAI Admin API, all pages.

    This is the API PLATFORM organisation - the one that owns API keys and
    projects - not a ChatGPT workspace. ChatGPT's member list is SCIM-only
    and Enterprise-only, which is an identity-provider integration rather
    than a vendor endpoint this could call, so it stays on the Import path.

    Pagination is cursor-based: page with `after` until has_more is false.
    """
    members: list[dict] = []
    after = ""
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        for _ in range(MAX_MEMBERS // 100 + 1):
            params = {"limit": "100"}
            if after:
                params["after"] = after
            try:
                r = await client.get(
                    OPENAI_URL, params=params,
                    headers={"Authorization": "Bearer " + api_key})
            except httpx.HTTPError as e:
                raise SyncError("could not reach the OpenAI API (%s)"
                                % type(e).__name__)
            if r.status_code != 200:
                raise _refusal(r.status_code, "the OpenAI API")
            try:
                body = r.json()
            except json.JSONDecodeError:
                raise SyncError("the OpenAI API answered 200, but not with "
                                "JSON")
            page = body.get("data") or []
            for u in page:
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
                                    "than store a partial member list as if "
                                    "it were complete" % MAX_MEMBERS)
            if not body.get("has_more"):
                return members
            after = str(body.get("last_id") or "")
            if not after and page:
                after = str(page[-1].get("id") or "")
            if not after:
                # has_more with no cursor would loop on page one forever.
                return members
    raise SyncError("the OpenAI API kept paginating past %d members"
                    % MAX_MEMBERS)


async def sync_cursor(api_key: str) -> list[dict]:
    """The team's members via the Cursor Admin API.

    One unpaginated call. Authentication is HTTP Basic with the API key as
    the USERNAME and an empty password - the shape their docs show as
    `curl -u YOUR_API_KEY:` - not a bearer token.

    Removed members keep appearing with isRemoved set; they are dropped
    here, because a seat that has been taken away is not a seat somebody
    holds and counting it would overstate what the licence is paying for.
    """
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        try:
            r = await client.get(CURSOR_URL, auth=(api_key, ""))
        except httpx.HTTPError as e:
            raise SyncError("could not reach the Cursor API (%s)"
                            % type(e).__name__)
    if r.status_code != 200:
        raise _refusal(r.status_code, "the Cursor API")
    try:
        body = r.json()
    except json.JSONDecodeError:
        raise SyncError("the Cursor API answered 200, but not with JSON")
    # Their docs show a bare array; a wrapped object would be a kindness to
    # accept too rather than a reason to fail the whole sync.
    rows = body if isinstance(body, list) else (body.get("teamMembers")
                                                or body.get("members") or [])
    if not isinstance(rows, list):
        raise SyncError("the Cursor API answered with JSON this does not "
                        "recognise as a member list")
    if len(rows) > MAX_MEMBERS:
        raise SyncError("more than %d members: refusing rather than store a "
                        "partial member list as if it were complete"
                        % MAX_MEMBERS)
    members = []
    for u in rows:
        if not isinstance(u, dict) or u.get("isRemoved"):
            continue
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
    return members

async def _scim_users(base_url: str, token: str, vendor: str) -> list[dict]:
    """Members from any SCIM 2.0 /Users endpoint.

    SCIM was ruled out here at first as "an identity-provider integration
    rather than a vendor API". That is wrong wherever the VENDOR issues the
    token from its own admin console and the endpoint answers a plain GET -
    which is a bearer key like any other, and no IdP is involved. What stays
    ruled out is a vendor whose token is issued by its support team during
    onboarding, because there is nothing an operator can paste.

    Pagination is SCIM's own: 1-based startIndex, and totalResults says when
    to stop. Written once because the three vendors that qualify differ only
    in their base URL.
    """
    members: list[dict] = []
    start = 1
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        for _ in range(MAX_MEMBERS // 100 + 1):
            try:
                r = await client.get(
                    base_url.rstrip("/") + "/Users",
                    params={"startIndex": str(start), "count": "100"},
                    headers={"Authorization": "Bearer " + token,
                             "Accept": "application/scim+json"})
            except httpx.HTTPError as e:
                raise SyncError("could not reach %s (%s)"
                                % (vendor, type(e).__name__))
            if r.status_code != 200:
                raise _refusal(r.status_code, vendor)
            try:
                body = r.json()
            except json.JSONDecodeError:
                raise SyncError("%s answered 200, but not with JSON" % vendor)
            page = body.get("Resources")
            if page is None:
                raise SyncError("%s answered without a SCIM Resources list - "
                                "check the base URL is the SCIM one" % vendor)
            for u in page:
                if not isinstance(u, dict):
                    continue
                # userName is the email on every vendor here, but the emails
                # array is the spec's own answer, so prefer it and fall back.
                email = ""
                for e in (u.get("emails") or []):
                    if isinstance(e, dict) and e.get("value"):
                        email = str(e["value"])
                        if e.get("primary"):
                            break
                email = (email or str(u.get("userName") or "")).strip().lower()
                if not email or "@" not in email:
                    continue
                nm = u.get("name") or {}
                name = str(nm.get("formatted") or
                           " ".join(x for x in [nm.get("givenName"),
                                                nm.get("familyName")] if x) or
                           u.get("displayName") or "")
                # A deactivated SCIM user is not holding a seat. Counting one
                # would overstate what the licence pays for, the same way a
                # removed Cursor member would.
                if u.get("active") is False:
                    continue
                members.append({
                    "email": email,
                    "name": name[:200],
                    "role": "",
                    "seat_tier": "",
                    "usage": {},
                })
                if len(members) > MAX_MEMBERS:
                    raise SyncError("more than %d members: refusing rather "
                                    "than store a partial member list as if "
                                    "it were complete" % MAX_MEMBERS)
            total = body.get("totalResults")
            got = start - 1 + len(page)
            if not page or (isinstance(total, int) and got >= total):
                return members
            start = got + 1
    raise SyncError("%s kept paginating past %d members"
                    % (vendor, MAX_MEMBERS))


async def sync_chatgpt(api_key: str) -> list[dict]:
    """The ChatGPT workspace's members, via its SCIM 2.0 endpoint.

    Enterprise and Edu only - Business (renamed from Team in 2025) has SSO
    but no SCIM, and so stays on the Import path. The token comes from the
    workspace's own admin console, Settings > Security > SCIM Provisioning,
    not from an identity provider.

    Codex CLI has no member list of its own: it rides whichever workspace
    pays for it, so tick it under "also covers" rather than looking for a
    connector of its own.
    """
    return await _scim_users(CHATGPT_SCIM_URL, api_key, "the ChatGPT SCIM API")


async def sync_notion(api_key: str) -> list[dict]:
    """The workspace's members via Notion's SCIM endpoint.

    Enterprise only - Free, Plus and Business cannot mint a SCIM token at
    all. An organisation owner creates it under Manage organization, so it
    is a vendor-issued key even though an IdP is the usual consumer.
    """
    return await _scim_users(NOTION_SCIM_URL, api_key, "the Notion SCIM API")


async def sync_grammarly(api_key: str) -> list[dict]:
    """The account's members via Grammarly's SCIM endpoint.

    Pro and Enterprise, and SAML SSO has to be configured first - Grammarly
    will not issue the token before it is. The token comes from the Admin
    Panel, Settings > SSO & Provisioning.
    """
    return await _scim_users(GRAMMARLY_SCIM_URL, api_key,
                             "the Grammarly SCIM API")


async def sync_devin(api_key: str) -> list[dict]:
    """The organisation's members via Cognition's Devin API, all pages.

    Covers Devin and Devin Desktop - the IDE that shipped as Codeium, then
    as Windsurf - because Cognition folded them onto one platform and one
    licence. That is why the registry keeps them as one tool, and why this
    is the connector the `codeium` id links to.

    Teams reaches this, not only Enterprise: an org admin creates a service
    user under Settings > Service Users and generates a `cog_` key. Member
    role is enough, since this only reads.

    The stored key is "org-xxxx:cog_xxxx" - the org id and the key, both
    shown on that same settings page. Devin has no endpoint that resolves a
    key to its own organisation, so the id has to be carried; it is checked
    against _DEVIN_ORG before it goes anywhere near a URL.

    Pagination is cursor-based: page with `after` until has_next_page is
    false. Seat tiers and usage are not on this endpoint, so both stay
    blank and tiers are recorded on the subscription.
    """
    org, _, key = api_key.partition(":")
    org, key = org.strip(), key.strip()
    if not key:
        raise SyncError("the Devin key needs the organisation id with it, as "
                        "org-xxxx:cog_xxxx - both are on Settings > Service "
                        "Users")
    if not _DEVIN_ORG.match(org):
        raise SyncError("%r is not a Devin organisation id: it should look "
                        "like org-xxxx, from Settings > Service Users"
                        % org[:40])

    members: list[dict] = []
    after = ""
    url = DEVIN_URL % org
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        for _ in range(MAX_MEMBERS // 100 + 1):
            params = {"first": "100"}
            if after:
                params["after"] = after
            try:
                r = await client.get(
                    url, params=params,
                    headers={"Authorization": "Bearer " + key})
            except httpx.HTTPError as e:
                raise SyncError("could not reach the Devin API (%s)"
                                % type(e).__name__)
            if r.status_code == 403:
                # The generic 403 names an Anthropic scope, which would send
                # a Devin operator looking in the wrong console.
                raise SyncError("the Devin API answered 403: the service "
                                "user needs the ViewOrgMembership permission "
                                "on this organisation")
            if r.status_code == 404:
                raise SyncError("the Devin API answered 404: no organisation "
                                "%s - check the id on Settings > Service "
                                "Users" % org)
            if r.status_code != 200:
                raise _refusal(r.status_code, "the Devin API")
            try:
                body = r.json()
            except json.JSONDecodeError:
                raise SyncError("the Devin API answered 200, but not with "
                                "JSON")
            page = body.get("items") or []
            for u in page:
                email = str(u.get("email") or "").strip().lower()
                if not email:
                    # Service users are members of the org and have no
                    # address. They hold no paid seat, so skipping them
                    # keeps the count to people.
                    continue
                # Roles are assignments, not a field: a member can hold more
                # than one. Join them so the portal shows what the vendor
                # actually says rather than an arbitrary first pick.
                roles = []
                for a in u.get("role_assignments") or []:
                    nm = str(((a or {}).get("role") or {}).get("role_name")
                             or "").strip()
                    if nm and nm not in roles:
                        roles.append(nm)
                members.append({
                    "email": email,
                    "name": str(u.get("name") or "")[:200],
                    "role": ", ".join(roles)[:64],
                    "seat_tier": "",
                    "usage": {},
                })
                if len(members) > MAX_MEMBERS:
                    raise SyncError("more than %d members: refusing rather "
                                    "than store a partial member list as if "
                                    "it were complete" % MAX_MEMBERS)
            if not page or not body.get("has_next_page"):
                return members
            after = str(body.get("end_cursor") or "")
            if not after:
                # has_next_page with no cursor would loop on page one.
                return members
    raise SyncError("the Devin API kept paginating past %d members"
                    % MAX_MEMBERS)

SYNCERS = {"anthropic": sync_anthropic, "fireflies": sync_fireflies,
           "openai": sync_openai, "cursor": sync_cursor,
           "chatgpt": sync_chatgpt, "notion": sync_notion,
           "grammarly": sync_grammarly, "devin": sync_devin}


# ----------------------------------------------------------------- fx --
# Daily ECB reference rates via the Frankfurter API: keyless, free, one
# fixed host - the same no-request-supplied-URL rule as the vendor syncs.
# The portal uses them to show the Budget headline in the preferred
# currency, always naming the rate's date inline, and falls back to
# per-currency figures when this cannot answer. ECB publishes once per
# working day around 16:00 CET, so a half-day cache never serves a rate
# the source itself has moved past.

FRANKFURTER_URL = "https://api.frankfurter.dev/v1/latest"
_FX_TTL = 12 * 3600
_fx_cache: dict = {}


async def fx_rates(base: str) -> dict:
    """{"base", "date", "rates"} - units of each currency per one `base`,
    per the ECB's latest daily reference fixing. Cached per base."""
    now = time.time()
    hit = _fx_cache.get(base)
    if hit and now - hit[0] < _FX_TTL:
        return hit[1]
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            r = await client.get(FRANKFURTER_URL, params={"base": base})
        except httpx.HTTPError as e:
            raise SyncError("could not reach the exchange-rate source (%s)"
                            % type(e).__name__)
    if r.status_code == 404:
        # Frankfurter answers 404 for a currency the ECB does not fix.
        raise SyncError("the ECB publishes no reference rate for %s" % base)
    if r.status_code != 200:
        raise _refusal(r.status_code, "the exchange-rate source")
    try:
        body = r.json()
    except json.JSONDecodeError:
        raise SyncError("the exchange-rate source answered 200, but not "
                        "with JSON")
    rates = {}
    for k, v in (body.get("rates") or {}).items():
        if isinstance(k, str) and len(k) == 3 and isinstance(v, (int, float)) \
                and v > 0 and len(rates) < 64:
            rates[k.upper()] = float(v)
    out = {"base": base, "date": str(body.get("date") or "")[:10],
           "rates": rates}
    _fx_cache[base] = (now, out)
    return out
