# Budget: paid seats against observed use

The detection pipeline answers *who uses which AI tools*. The Budget view
adds the other half of the question: *which of those does the organisation
pay for, and do the two lists agree*. Link a tool, record what its seats
cost, give the portal the member list the plan covers, and each tool's
card shows:

- **paid seats never observed** - users on the vendor's member list that no
  detection surface has matched to activity. Downgrade candidates, with
  the caveat the card itself carries: a coverage gap looks identical to
  absence, so check the Sources view before acting.
- **observed users not matched to a seat** - identities the estate has
  seen on the tool that match nobody on the member list.
- **personal-account use alongside the paid plan** - the same rows the
  Personal accounts view holds, surfaced under the seats being paid for,
  because that is where the spend question lives.
- the per-tier arithmetic: seats paid versus seats assigned to users, price per seat, monthly total, and the renewal date with a
  warning inside 30 days.

Budget is managed-mode only. The subscriptions, user lists and connections
are receiver state, every write is role-gated (viewers read, admins
write) and lands in the audit trail, and the portal remains a page over
data others hold.

## Where the user list comes from

Three sources, per tool, and each card names which one its rows came from:

| Source | How | Good for |
| --- | --- | --- |
| Automatic | The vendor's admin API, synced on demand with a stored key | Anthropic (Claude Enterprise / Console), Fireflies |
| Import | Paste the member export from the vendor's admin page | ChatGPT Business, and any vendor without an admin API |
| Manual | Add members by hand on the card | Small teams, one-off seats |

The three coexist: an API sync replaces the previous sync, a re-import
replaces the previous import, and neither touches rows added by hand.

Automatic setup currently supports **Anthropic** and **Fireflies**. More
vendors will be added for automatic configuration - if you want a
particular tool supported, [raise an issue on
GitHub](https://github.com/AmanSK5/shadow-ai-guard/issues).

**ChatGPT Business is import-only, and that is OpenAI's boundary, not
this project's**: the Business (formerly Team) plan exposes no admin API,
and SCIM and the Compliance API are Enterprise-only. The workspace member
list exports from Workspace settings → Members, and the import understands
its `email,role,seat type` shape directly.

### The Anthropic connection

The sync needs a scoped Admin API key with the `read:members` scope. The
organisation's **primary owner** creates it:

- Claude Enterprise orgs (claude.ai): Organization settings → API → Keys
- Claude Console (platform.claude.com) orgs: Settings → Admin keys

**Claude Team plans do not offer admin keys** - the API section is
simply absent from a Team workspace's organization settings, even for
the primary owner. A Team workspace uses the Import path instead: copy
the list from Organization settings → Members and paste it into the
card's import. Everything downstream behaves identically.

Select **read-only scopes** when creating it. The sync only ever lists
members; a key that can also write members is more credential than this
feature needs, and the receiver will happily use less.

### The Fireflies connection

An API key from fireflies.ai → Integrations → Fireflies API. A team
admin's key lists the whole team, and the sync also records the per-user
usage the API reports (transcripts, minutes), which shows up in the
users table.

## Where the key lives, exactly

The vendor API key is stored by the receiver in its state database,
alongside the log-store credential and under the same documented trade
(SECURITY.md): recoverable by design, because the receiver must present
it outward to sync. It is written by one admin request and never read
back out by any route - the portal masks it, `/admin/budget` reports only
that one is set, and a sync spends it server-side. Replacing the key
resets the sync history, since what the old key last did says nothing
about the new one.

## How matching works, and what it will not claim

Findings deliberately carry account **domains** and identity hints, never
full addresses - that is a privacy property of the platform, and Budget
does not weaken it. A user's email is matched against observed identities
(cloud sign-in names, and people attached to devices through the identity
map) by normalising both sides to bare letters and digits, the same trick
the identity-map suggestions use.

That makes the matching honest but fuzzy, and the cards phrase it
accordingly: an unmatched member is *"never observed"*, not *"not using
it"*; an unmatched observed user is *"not matched to a seat"*, not
*"unlicensed"*. Devices running the tool with no person attached are
counted separately and excluded from both lists - an identity map (Sources
view) is what turns those into names.

## Seat tiers

Vendors sell mixed plans (Claude Team and ChatGPT Business both split
standard from premium seats), so a subscription holds up to ten named
tiers, each with a seat count and a per-seat monthly price. Tier names
matter: a user row whose seat tier matches a tier's name counts against
that tier's seats, which is how "8 premium seats paid, 3 assigned" falls
out. The vendor APIs do not expose per-user tiers, so tier assignment
comes from the CSV import or the card either way.
