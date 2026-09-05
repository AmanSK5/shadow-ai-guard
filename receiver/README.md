# Receiver

The receiver is the one service in the platform. Every source POSTs findings
to it, it validates them, logs them as JSON lines on stdout, and optionally
pushes them straight to Loki and raises Alertmanager alerts. One container,
no database: the findings live in your log pipeline, not in the receiver.

It also serves the compiled registry, so collectors fetch their identifier
lists at runtime instead of carrying hardcoded copies.

## Endpoints

| method | path | auth | what |
|--------|------|------|------|
| GET  | `/healthz` | none | liveness, and the version the image was built from |
| GET  | `/metrics` | none | Prometheus metrics |
| GET  | `/registry` | bearer | the full compiled registry |
| GET  | `/registry/collector` | bearer | the collector view of the registry |
| POST | `/report` | bearer | submit a finding |
| POST | `/flag` | bearer | same as `/report`, kept for older browser extension versions |

Auth is a bearer token. It is a write-mostly credential: it can submit
findings and read the registry, nothing else. Classically that is one shared
token for the whole estate; in managed mode a per-device credential works in
the same places (and the shared token keeps working alongside, which is the
migration path).

### Managed mode

`MANAGED_MODE=true` adds device enrollment on top: an operator mints an
enrollment token (`aige_...`), puts it where the shared token goes - the MDM
script parameters, the browser extension's managed policy, the scanner's
Secret - and each endpoint collector, browser profile and scanner exchanges
it once at `/enroll` for its own credential (`aigd_...`). One of them can
then be revoked without touching any other, and the inventory knows who
exists rather than inferring it from silence. Revoking is final in the
direction that matters: the enrollment token is still sitting in the MDM
artifact on the machine you just cut off, so a revoked serial is refused at
`/enroll` rather than re-minted, and an admin has to allow it back for a
genuine reimage or replacement. Platforms are `macos`, `linux`,
`windows`, `browser` (one row per managed browser profile: serial is the MDM
device id plus a per-profile install id) and `scanner` (serial is the
scanner's configured id). Every authenticated request with a device
credential - a report or a registry read - stamps the device's `last_seen`,
and its agent version when the request carries `X-AiGuard-Agent-Version`.
When every surface has enrolled, `REQUIRE_DEVICE_CREDENTIALS=true` turns the
shared token off for ingest (see the configuration table).

| method | path | auth | what |
|--------|------|------|------|
| POST | `/enroll` | enrollment token | exchange for this device's own credential; a same-serial re-enroll reissues a silent device's credential in place (same id, old credential dead, `reenrolled_at` and `enrollments` say it happened - the reimaged laptop, or a stateless scanner enrolling every run) and 409s a device seen within the hour. Platform `scanner` is exempt from that guard: it enrolls every run by design. A serial whose every row is **revoked** 409s too, until an admin allows it back |
| POST | `/admin/enrollment-tokens` | admin | mint (`note`, `ttl_days`, default 180) |
| GET  | `/admin/enrollment-tokens` | admin | list - ids, notes and expiry, never token material |
| POST | `/admin/enrollment-tokens/{id}/revoke` | admin | |
| GET  | `/admin/devices` | admin | the fleet: platform, serial, hostname, enrolled / re-enrolled, last seen, agent version |
| POST | `/admin/devices/{id}/revoke` | admin | that machine's credential stops working on its next request, and its serial is refused at `/enroll` from then on |
| POST | `/admin/devices/{id}/allow-reenrollment` | admin | lift that refusal for one enrollment - the reimage, the replacement machine |
| GET  | `/admin/setup` | none | what the sign-in screen needs before anybody has authenticated: does an admin account need creating, is single sign-on on and enforced, and the estate's `org_name`. Nothing about the estate itself |
| POST | `/admin/setup` | setup code | claim the boot-printed code, create the admin account, leave with a session |
| POST | `/admin/login` | none | username + password for a session token (`aigt_...`). Throttled: past a per-username or global failure cap in a five-minute window, attempts get a cheap 429 before any password work, and the audit log records a bounded number of failures plus one throttle event |
| POST | `/admin/logout` | admin | revoke the presented session |
| GET  | `/admin/session` | admin | who this session is, its role, and until when; the portal's validity probe |
| POST | `/admin/password` | admin | change your own password (`current` + `new`) - a viewer owns theirs too. With the `ADMIN_TOKEN` credential, `current` is not required and the reset targets the oldest admin: the break-glass path. Every other session dies with the old password |
| GET  | `/admin/users` | admin | the accounts: username, email, role, created, last sign-in |
| POST | `/admin/users` | admin (write) | create an account (`username`, `password`, `role`: `owner`, `admin` or `viewer`, and an optional `email`). Subject to the rank rule below. With an address and a mail server configured it also sends the invite, and the outcome rides back on the response as `invited` and `invite_error` - the account is created either way, so a dead relay never costs somebody their account, and the page can say plainly that nobody was emailed. The portal asks for an address on every account it creates, because it is what a federated sign-in matches on |
| POST | `/admin/users/invite` | admin (write) | tell people their account exists. `user_id` resends to one; empty means everybody who has never been told, so configuring a relay after the fact closes the gap rather than leaving it permanent. Synchronous, and reports `sent`, `considered` and a `failed` list. The mail carries no token, no password and no link that grants anything |
| POST | `/admin/test/mail` | admin (write) | send one test message to `to` and report what the relay said. The lesson the sign-on wizard taught: configuration that looks right and silently does not send is how an invite vanishes and the person who never got it is blamed for not checking their inbox |
| POST | `/admin/users/{id}/delete` | admin (write) | remove an account and kill its sessions. The last owner cannot be deleted |
| POST | `/admin/users/{id}/password` | admin (write) | set someone else's password - the forgotten-password path. Their old sessions die with it |
| POST | `/admin/users/{id}/role` | admin (write) | move an account between `owner`, `admin` and `viewer`. Takes effect on that account's next request, not its next sign-in - the role is read off the account row per request, so a demotion refuses the next write immediately and a promotion costs a page reload. Sessions and passwords are untouched. The last owner cannot be demoted, for the same reason it cannot be deleted |
| POST | `/admin/users/{id}/email` | admin (write) | set or clear (empty string) the address an identity provider would map onto this account. Normalised to lowercase and unique across accounts; **not** the login identifier, which stays `username` - so a local account keeps working whatever happens to a provider. Admin-gated: an account able to rewrite its own mapping could point somebody else's federated sign-in at itself |
| GET  | `/admin/preferences` | admin or viewer | the signed-in account's own display state - layout, chart choices, what it has already been walked through. Scoped to the session, so there is no id to pass and no route to another account's |
| PUT  | `/admin/preferences` | admin or viewer | merge keys into the account's own preferences; a `null` value deletes one. The single authenticated write a viewer owns - these change what one person sees, never what a page reports. Bounded at 50 keys and 4096 characters a value |

**Federated sign-in (Microsoft Entra).** Owner-gated, off until proven.
Configured through a five-step wizard in the portal rather than a settings
panel, because each step has something to check: the tenant is resolved
against its own OpenID configuration document, the application id and
secret are proved with a client-credentials grant, and the last step is a
real sign-in. Nothing is enabled until that sign-in succeeds - an enabled
provider that does not work is a deployment nobody can sign in to.

| Method | Path | Who | What |
|---|---|---|---|
| POST | `/admin/sso/probe` | owner (write) | check a tenant, and optionally an application id and secret, before anything is saved |
| GET  | `/admin/sso/start` | open | begin a sign-in; 404 until federated sign-in is fully configured, so an estate that has not set it up does not advertise the endpoint |
| POST | `/admin/sso/callback` | open | redeem the code the provider handed the browser, and mint a session |

The two open endpoints are open for the reason `/admin/login` is: nobody
has a session yet. What protects the callback is the `state` it must
quote - minted by `/start` minutes earlier, single-use, and paired with a
PKCE verifier the browser never held.

**How an account is matched.** On an account's first federated sign-in the
email address finds it; the account's `oid` and `tid` are written at that
moment, and every sign-in after that matches on those alone. Microsoft's
guidance is explicit that an address "isn't guaranteed to be correct and
is mutable over time. Never use it for authorization" - addresses get
reassigned, and a joiner inheriting a leaver's address would otherwise
inherit their account and their role. The address is an invitation, spent
once.

**No sign-in ever creates an account.** Somebody who can set an address in
a tenant cannot mint themselves a way in; an owner or admin has to create
the account first. Local passwords keep working whether or not federated
sign-in is on, so an account with no address remains reachable only by
password - which is what makes one usable as a shared break-glass
credential.

**How recently they signed in.** The authorization request carries
`prompt=select_account`, so the provider always shows the chooser and
signing in is something a person did rather than something that happened to
them silently in a browser that was already logged into the tenant. It also
carries `max_age`, and the callback **verifies the answer**: `auth_time`
must be present and within `sso_max_age_hours` plus 120 seconds of skew.
Requesting `max_age` without checking `auth_time` is the whole weakness -
a provider is permitted to mint a fresh token off an old session, and the
token's own expiry says the token is fresh while saying nothing about the
person. A token that comes back with no `auth_time` is refused rather than
trusted. Default 12 hours; `0` means every time.

**Requiring it.** `sso_enforce` makes a correct password insufficient for
every account except one: the account the setup code created, marked
`break_glass` at creation rather than nominated later, because an escape
hatch somebody has to remember to set up is the one that is missing on the
day it is needed. While enforcement is on that account can be neither
deleted nor demoted, and its sign-ins carry their own audit line.

Two preconditions, both checked by the receiver rather than the page:
federated sign-in is working, and an owner has **completed** a sign-in
through it. An address on an account is an intention; a completed binding
is the provider having answered for somebody who can still turn this off.

The refusal happens **after** the password verifies. Refusing earlier is
the tempting order and it leaks: an unauthenticated caller could walk a
list of usernames and read off which one is exempt, because only that one
would answer differently. A wrong password answers exactly as it did before
the feature existed.

**On the ID token signature.** It is not verified, deliberately. The token
is fetched by the receiver over TLS directly from the token endpoint named
by the tenant's own discovery document, and OpenID Connect Core 3.1.3.7
permits exactly that: "If the ID Token is received via direct
communication between the Client and the Token Endpoint... the TLS server
validation MAY be used to validate the issuer in place of checking the
token signature." Issuer, audience, expiry, nonce and tenant are all
checked. The alternative is a JWT library and the native cryptography
stack it brings, on an image this project keeps small, for a guarantee the
transport already gives in this flow. Revisit it the day a token arrives
by any other route.

**Roles and the rank rule.** Three roles: `owner`, `admin`, `viewer`. An
owner decides who may sign in and can appoint another owner; an admin runs
the platform - fleet, governance, budget, settings and the accounts below
their own level; a viewer reads every page and writes nothing but its own
password and display preferences.

Every account action above is subject to one rule: **you cannot act on an
account that outranks you, and you cannot grant a role above your own.**
Without it the owner tier exists in name only, because an admin reaches an
owner through any of three doors - reset their password and sign in as
them, set the address a federated sign-in matches on, or simply change
their role. Equal rank is not above it, so two owners manage each other and
an admin still resets a colleague-admin's password. Kubernetes RBAC calls
this escalation prevention; Entra enforces the same shape by refusing a
password reset against a higher-privileged role.

The `ADMIN_TOKEN` credential is outside the rule. It is break-glass, held
by whoever can set the receiver's environment - who already owns the box -
and rank-limiting it would only lock an operator out of their own recovery
path.

The account created by the setup code is the deployment's owner. On a
deployment that predates the role, the earliest account is promoted on
first start (`create_admin` refuses once any account exists, so "earliest"
identifies it exactly) and the promotion lands in the audit trail.

An account with no email address cannot be matched by a federated sign-in
at all, which is what makes one usable as a shared break-glass credential:
a password in a password manager, reachable by nobody through the identity
provider.

| GET  | `/admin/settings` | admin | each central setting with its effective value and its source (`db`, `env`, `unset`), so a saved value shadowing an environment one is visible as such. The log-store password is reported as `{set, source}` only, never its value |
| PUT  | `/admin/settings` | admin | partial upsert; a saved value wins over the matching env var, an explicit `null` (or empty) deletes the row and falls back to it. Unknown keys are 422. Keys: `org_name` (what the estate is called - the portal's estate control, its narrow top bar and the sign-in screen all say it, so it is served unauthenticated by `GET /admin/setup` and must be nothing more than a name), `corp_domains`, `extension_id`, `onboarding_done`, `receiver_public_url`, `log_store_url` (base - the push endpoint is **derived** as `<base>/loki/api/v1/push`), `log_store_push_url` (explicit override for gateways), `log_store_username`, `log_store_password`, `alertmanager_url`, `grafana_url`, `grafana_panels`, `grafana_dashboard_uid`, `overview_widgets`, `extension_update_url`, `extension_crx_url`, `extension_xpi_url`, `paste_guard_mode`, `firefox_extension_id`, `classification_markings`, `budget_currency` (the currency the Budget headline reports in and the default for a newly linked tool - a display preference, the receiver never converts between currencies), `sso_tenant_id`, `sso_client_id`, `sso_client_secret`, `sso_redirect_uri`, `smtp_host`, `smtp_port`, `smtp_username`, `smtp_password`, `smtp_from`, `smtp_security` (`starttls`, `tls` or `none`), `invite_subject` and `invite_body` (the whole invite, yours to rewrite; `{username}` and `{portal_url}` are substituted, and leaving them empty falls back to the built-in wording), `portal_public_url` (the address the invite points at; saved here only, there is no environment fallback for it). Those are the outbound-mail settings, used to tell somebody an account has been made for them. Each also reads from `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM` and `SMTP_SECURITY` when nothing is saved here, so a cluster can mount the relay credential from the Secret it already has rather than have somebody paste it into a form. The whole lot is optional: with none of it set, accounts are created exactly as before and the response says plainly that nobody was emailed. An invite carries no token, no password and no link that grants anything, `sso_enabled` (Microsoft Entra sign-in for the portal; `sso_enabled` is deliberately last to matter - nothing else here takes effect until it is `1`, and the portal will not set it until a real sign-in has completed against the rest; an address is matched once and then the account is bound to the tenant and subject permanently, so no sign-in ever creates an account and a rebind is refused), `sso_enforce` (require it: a correct password stops being enough for every account except the one the setup code created, which keeps its password as the break-glass path and can be neither deleted nor demoted while this is on. Refused unless single sign-on is working AND an owner has completed a sign-in through it, and the check runs after the password verifies so an unauthenticated caller cannot walk usernames to find the exempt one), `sso_max_age_hours` (how recently the person must have authenticated at the provider, a whole number of hours from 0 to 720; default 12, `0` means every time. Sent as `max_age` and then **verified** against the `auth_time` claim on the way back, with 120 seconds of skew; a token that comes back without that claim is refused rather than trusted), `webhook_url` (Slack-compatible; the receiver posts to it when discovery queues a NEW tool or MCP server - once per candidate lifetime, from a thread, so a webhook outage can never bounce ingest. Masked like the log-store password and the SSO client secret: a webhook URL is a bearer capability) |
| POST | `/admin/cli/authorize` | none | `aiguardctl` asks to be approved: a device code for the command, a user code for the person, both expiring in ten minutes. Throttled like login. See SECURITY.md, *Upgrading* |
| GET  | `/admin/cli/grants/{code}` | owner | what the approval page shows: purpose, when, which client. Never the device code |
| POST | `/admin/cli/approve` | owner | approve or deny a pending request; both are audit events naming the owner |
| POST | `/admin/cli/token` | none | the command's poll: 428 pending, 429 slow down, 403 denied, 410 expired, 200 once with an `aigu_` upgrade token (45 minutes, one run, upgrade routes only) |
| GET  | `/admin/upgrade/plan` | upgrade token or admin | the receiver's version and who approved |
| POST | `/admin/upgrade/runs` | upgrade token | open the one run this token may open |
| POST | `/admin/upgrade/runs/{id}/steps` | upgrade token | a step: name, running/done/failed/skipped, short detail. Capped in number and length |
| POST | `/admin/upgrade/runs/{id}/finish` | upgrade token | the outcome; retires the token |
| GET  | `/admin/upgrade/runs/current` | admin (any role) | the latest run with its steps, for the portal's tracker |
| GET  | `/admin/settings/secrets` | admin (write) | the stored log-store configuration with the password in plaintext - for the portal's server-side reads via its service credential; the portal exposes no route that relays it. Admin-only, because the credential is typically write-capable and a read-only account must not be a path to it. See SECURITY.md |
| POST | `/admin/test/log-store-push` | admin | push one synthetic `kind:"test"` line with the effective configuration and report what happened, hints included - catches the write-only-token trap at setup time instead of on the first quiet dashboard |
| GET  | `/admin/registry-entries` | admin | the portal-defined registry entries, each flagged `shadowed` if a later release ships the same id (shipped wins at serve time; a shadowed local copy is a row to delete) |
| PUT  | `/admin/registry-entries` | admin | upsert (`entries`) and delete (`delete`) portal-defined tools - the same shape as a shipped registry entry, validated against the registry's own schema and rules (lowercase domains, no domain claimed twice, no shipped id redefined; `added_by`/`approved` are forced, approval lives in governance). The whole batch validates before anything writes; the merged registry serves immediately, so collectors detect a defined tool on their next check-in |
| POST | `/candidates` | shared token or device credential | suggest observed-but-undefined tools (the discovery service's classified DNS residue). Re-validated here field by field - a reporting credential can suggest a tool but never define one; candidates wait in the portal's review queue |
| GET  | `/admin/candidates` | admin | the candidates queue, each flagged `resolved` once the merged registry answers it (a claimed domain, or for MCP-server candidates an entry whose id is the server's slug). MCP-server candidates arrive on their own: the endpoint MCP scan reports raw server names as evidence, and unknown ones join the queue at ingest with a distinct-device count |
| POST | `/admin/candidates/{key}/dismiss` | admin | record a dismissal; the same candidate resurfacing on a later run stays dismissed |
| GET  | `/admin/finding-status` | admin | the recorded answers to derived findings (acknowledged, or accepted with a reason), keyed on an opaque string the portal composes. The findings themselves stay in the log store; only the human's answer is state |
| PUT  | `/admin/finding-status` | admin (write) | set one (`key`, `status`, `reason`) |
| POST | `/admin/finding-status/clear` | admin (write) | back to open |
| GET  | `/admin/events` | admin | the audit trail: every admin write above, newest first, with who did it |
| GET  | `/admin/governance` | admin | the portal-recorded governance decisions |
| PUT  | `/admin/governance` | admin | upsert (`decisions`) and delete (`delete`) decisions, validated to the governance file's own rules - an approval needs a `review_due` date. The whole batch validates before anything is written |

**Admin auth** is either of two things: a session from `/admin/login`, or
the optional `ADMIN_TOKEN` API credential. Humans get the first; automation
and break-glass recovery get the second (the API credential always counts
as an admin - both of its jobs are operator acts). Accounts carry a role:
an **admin** passes everything, a **viewer** passes every read and is
refused by every write with a 403 that says the account is read-only,
rather than a generic 401 to someone who is authenticated. The rows marked
"(write)" above are the gated ones. On a fresh managed deployment no
admin account exists yet, and until one does, **every boot prints a one-time
setup code** to the receiver's log as a JSON line with `"kind":
"setup_code"`. Enter it in the portal (or POST it to `/admin/setup`) to
create the account; the code is consumed on use, never stored, and once an
account exists boots print nothing.

Only SHA-256 hashes of fleet credentials are stored (passwords: scrypt): a
copied database file cannot impersonate a device or an admin. The one
exception, since 0.9.8, is an *integration* secret - a log store password
saved in the portal is stored recoverable because the receiver must present
it to push; SECURITY.md states the trade and the env/Secret path remains
for anyone who declines it. Enrollment tokens default to a 180-day life
because they sit inside MDM artifacts, where a short TTL means the
deployment silently breaks for new machines - their safety comes from what
they cannot do (only create auditable device records) and from instant
revocation, not from a short life.

## Configuration

Everything is environment variables. Only the token is required.

| variable | default | what it does |
|----------|---------|--------------|
| `AUTH_TOKEN` | required | the one bearer token every source authenticates with |
| `LOKI_PUSH_URL` | unset | if set, findings are POSTed straight to Loki as well; stdout logging happens regardless. The **full push endpoint**, `/loki/api/v1/push`, not the base URL. In managed mode a log store saved in the portal wins over this (its push endpoint is derived from the base, and it brings its own credentials) |
| `LOKI_USERNAME` | unset | basic auth for the push, if your log store needs it. Hosted Loki usually does; a self-hosted one usually does not |
| `LOKI_PASSWORD` | unset | with the above. Sent only when a username is set, because an empty credential pair is not the same as sending none |
| `ALERTMANAGER_URL` | unset | if set, `warn` findings raise Alertmanager alerts; unset means findings are logged and dashboarded but nothing pages. In managed mode a URL saved in the portal wins over this |
| `ALERT_TTL_MINUTES` | `120` | how long a warn finding counts as already alerted, so a device reporting the same thing repeatedly does not page repeatedly |
| `REGISTRY_PATH` | `/etc/ai-guard/registry.json` | where the compiled registry is mounted |
| `COLLECTOR_REGISTRY_PATH` | `/etc/ai-guard/collector.json` | where the collector view is mounted |
| `DISPLAY_TZ` | `UTC` | timezone for the human-readable timestamp on alerts only; machine timestamps are always UTC |
| `CORP_DOMAINS` | unset | corporate domains, comma-separated. When set, served to the endpoint collectors inside `/registry/collector` as `config.corp_domains`; collectors prefer that list to their locally configured one, so a change here reaches the fleet on its next check-in with no MDM re-push. Unset means collectors keep using their local configuration. In managed mode a list saved in the portal (`/admin/settings`) wins over this, and clearing it there falls back here |
| `MANAGED_MODE` | unset | `true` enables device enrollment, per-device credentials, revocation and a fleet inventory (see below). Unset means byte-for-byte the classic receiver: no state file, `/enroll` and `/admin/*` answer 404 |
| `ADMIN_TOKEN` | unset | optional API credential for `/admin/*` - automation, and break-glass recovery when the portal password is lost. Humans use an account and a session instead (see managed mode above). Deliberately a separate secret from `AUTH_TOKEN`, which sits on every machine in the fleet - which is exactly why it must not be able to mint credentials |
| `STATE_DB_PATH` | `/var/lib/ai-guard/state.db` | where the managed-mode SQLite file lives. The one non-disposable thing: it holds the device registry and its credential hashes |
| `SESSION_TTL_HOURS` | `24` | how long a portal login lasts before it asks again |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_SECURITY` | unset | the outbound relay used to tell somebody an account has been made for them. `SMTP_SECURITY` is `starttls`, `tls` or `none`. Each is a fallback for the matching saved setting, so a cluster can mount the credential from the Secret it already has rather than have somebody paste it into a form: the chart takes `managed.smtp.password.existingSecret` and mounts it as `SMTP_PASSWORD`, and on Compose `SMTP_PASSWORD_FILE` is honoured like the other secrets here. All optional: with none of it set, accounts are created exactly as before and the portal says plainly that nobody was emailed |
| `SSO_AUTHORITY_URL` | `https://login.microsoftonline.com` | **demo stack only.** Points federated sign-in at a different identity provider. This is the trust root for who gets signed in, so there is no autodetection and no heuristic: a deployment either names a host here or talks to Microsoft. When it is set, the receiver prints a warning naming the host on every boot. The local demo sets it to its own stand-in provider so the sign-on wizard can be walked without a tenant; nothing else should |
| `REQUIRE_DEVICE_CREDENTIALS` | unset | managed mode only: `true` turns the shared token off for ingest. `/report` and `/registry` accept device credentials only; the shared token gets a 401 that says "enroll". The final step of the migration once every surface has enrolled, not a mode - unset it and unenrolled machines report again. Refuses to start without `MANAGED_MODE` |

Any of these can be given as `NAME_FILE` pointing at a file instead:
`AUTH_TOKEN_FILE=/run/secrets/auth_token` rather than `AUTH_TOKEN`. That
exists because Docker Compose has no real secret story - an environment
variable is visible in `docker inspect`, in `/proc`, and in every child
process's environment, while a file is confined to the filesystem. **That is
better and it is not encryption:** it is still plaintext on the same disk.
Kubernetes has Secrets and does not need it.

The value is stripped, which matters: almost every way of writing a file
leaves a trailing newline, and a token differing by one fails authentication
with no indication why. A missing or unreadable file is fatal rather than a
silent fallback, because falling back would start the receiver with an empty
token.

`/healthz` reports the version the image was built from: the release on a tag
build, `main-<sha>` on a build off main, `dev` on a local one. It is set at
build time, so it cannot drift from what is running.

The registry is read per request, and the kubelet syncs ConfigMap changes
into the pod, so a registry update is a rebuild and a `kubectl apply` with
no receiver restart.

## When findings stop arriving

When a push target is configured, a failed push is a **503** back to the
reporting source, and collectors keep the finding and retry on their next
run - a 200 means the finding actually reached the store. It used to be a
200 either way, which made a broken token produce a clean-looking dashboard
while collectors discarded findings the store never received. With no push
target configured, stdout is the contract and /report answers 200 as ever.
The retry costs a duplicate stdout line; duplicate evidence beats silently
missing evidence.

Push failures log at error with the URL and, for the codes that account for
almost every misconfiguration, the likely cause: a 404 usually means
`LOKI_PUSH_URL` is the base URL rather than the push endpoint; a 401 or 403
means the credentials are needed or wrong.

On `/metrics`:

- `aiguard_loki_push_failures_total` counts failures by reason
- `aiguard_loki_push_last_success_timestamp` is the one to alert on. Findings
  arrive irregularly, so a failure counter alone cannot tell "nothing is
  happening" from "everything is failing"; `time()` minus this answers it.

## Deploying

`deploy/receiver.yaml` is a working example: Deployment, Service and
Ingress, adapted from a real deployment. Change the Loki URL and the
ingress host, create the Secret and the registry ConfigMap, and apply it.

Two things worth knowing before the first apply:

- The pod mounts the registry ConfigMap. If you apply the Deployment before
  the ConfigMap exists, the pod sits in ContainerCreating with a
  FailedMount event until it does. It recovers on its own; nothing needs
  restarting.
- The ingress needs to be HTTPS and reachable from every endpoint that
  reports. The browser extension in particular will not POST to a plain
  HTTP endpoint.

The receiver listens on 8080 and runs as a non-root user.