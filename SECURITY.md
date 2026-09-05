# Security model

This document sets out the trust model, so you can decide what it means in
your environment. It's upfront about what it doesn't do.

## Data handled

Findings contain usernames, device serials, tool names, account domains and
evidence paths. They deliberately exclude message content, file content and 
credentials. Even so, the aggregate is a map of who uses what on which 
machine: treat the receiver's log store (e.g. your Loki
tenant) as sensitive, and scope dashboard access accordingly.

For privacy and DPIA guidance, see docs/deployment-privacy.md.

Alert labels include the username, because it is part of the alert's
dedup identity; scope Alertmanager UI access accordingly.

The portal derives more than any single finding contains. A finding says one
tool was seen on one device; the portal joins them into "this person uses these
six tools across these three machines, two of them on personal accounts". That
is a materially more sensitive artifact than the inputs, which is why it
authenticates and why the identity map deserves the same care as the log store.

The identity map is the sharpest example. It associates named people with the
machines they use, it is supplied by the deployer rather than derived, and it
should live wherever deployment configuration lives rather than in a
repository. It is not in this one, and `.gitignore` says so.

## Authentication

Reporting sources authenticate to the receiver with a single shared bearer
token. This is a deliberate simplicity trade-off: the token is distributed
through MDM (Jamf script parameters, Intune script content, managed browser
storage), and rotating it means updating those places. Consequences you
should accept before deploying:

- Any holder of the token can submit findings, including false ones. The
  receiver validates shape, not truth.
- Any holder can read the registry via `/registry/collector`. The registry
  is not secret (it describes public products), but it does reveal what you
  detect.
- **A standard local user on any enrolled machine can read the token.** No
  compromise required: it sits in a Jamf script parameter, an Intune script
  body, or managed browser storage (a world-readable plist on macOS, HKLM
  on Windows), all of which are readable without elevation on a default
  install. Because it is the same token fleet-wide, any employee who looks
  can then author findings about any colleague's machine - the register is
  only as trustworthy as the least curious person in the fleet.
- Historically the collectors also passed the token to `curl` as a
  command-line argument, which publishes it to every local user via `ps`
  for the duration of each request. Since 0.9.9 the collectors send the
  `Authorization` header on curl's stdin (`-H @-`) so it never appears in
  process arguments; the Windows collector uses `Invoke-RestMethod`, which
  keeps it in-process. This narrows the exposure, but the storage locations
  above still apply - argv hygiene does not make a shared secret per-device.

If that is unacceptable in your threat model, use managed mode (the
default since 0.9.9): the
endpoint collectors then enroll for per-device credentials, and one machine
can be revoked without touching any other. An enrollment token in an MDM
artifact cannot submit findings itself, but it is a credential-minting
credential and what it mints does report - so treat it as one. Since 0.16.8
it cannot be used to undo a revocation: a revoked serial is refused at
`/enroll` until an admin explicitly allows it back, which is what separates
a reimaged machine from the machine you just cut off. The
shared token remains valid alongside (the browser extension and scanners
still use it), so the consequences above shrink to those surfaces rather
than disappearing - and `REQUIRE_DEVICE_CREDENTIALS=true` closes even that:
the receiver then rejects the shared token on `/report` entirely, so a
token read off a colleague's machine submits nothing. See the receiver
README for the mechanics, including the separate `ADMIN_TOKEN` that mints
credentials - separate precisely because the shared token is on every
machine in the fleet.

### The portal

The portal authenticates separately, and what that is depends on the mode.
In managed mode it is a real login: accounts in the receiver's state DB
(scrypt-hashed passwords; the first is created on first boot with a one-time
setup code the receiver prints to its log, further ones by an admin from
inside), a session carried as an HttpOnly SameSite=Strict cookie, validated
against the receiver per request.

Accounts carry one of three roles. An **owner** is what the setup code
creates; an **admin** runs the platform; a **viewer** reads every page and
is refused by every write route - the shape for an auditor, who gets the
visibility without becoming a way in. The roles are ranked, and two rules
follow from that rank: you cannot act on an account that outranks you, and
you cannot grant a role above your own. Without them the tier above admin
would exist in name only, because an admin reaches an owner through any of
three doors - reset their password and sign in as them, set their email and
sign in through the identity provider, or simply change their role. This is
the escalation prevention Kubernetes RBAC names, and the same shape Entra
enforces by refusing a password reset against a higher-privileged role.

**The last owner cannot be removed or demoted.** This replaced a floor
under the last admin, and is stricter than that floor ever was: an admin
cannot make an owner, so losing the last one could not be undone from
inside at all. Password resets revoke the sessions the old password minted,
and every account action lands in the receiver's event log with who did it.

Sign-in can also be federated to **Microsoft Entra**. Still beta - it has
been run end to end against one real tenant, which is not the same as
proven. It authenticates, it does not provision. An account must already
exist with the matching email address; the first successful sign-in binds
that account to the tenant and subject GUID permanently, and a later attempt
to bind it to a different federated identity is refused - rebinding is how
an address change would otherwise hand somebody else's account away.
Unbinding is deliberate, separate, and subject to the same rank rule. The
account's password keeps working unless enforcement is on.

**Freshness, not just validity.** The authorization request carries
`prompt=select_account` so the provider always shows the chooser, and
`max_age` so it is asked how recently the person authenticated. The callback
then **verifies `auth_time`** rather than trusting that the request was
honoured, within 120 seconds of skew, and refuses a token that arrives
without the claim at all. This is the difference between a fresh token and a
fresh person: a provider may mint a new ID token off a months-old browser
session, and the token's expiry attests to the token. Without the check, a
link into the portal opened on a machine already signed into the tenant
would admit whoever is sitting at it, silently. Twelve hours by default,
`0` for every time, and up to 720 (the portal's dropdown stops at seven
days). A shorter sign-in frequency in your
conditional access still wins; this is a floor.

**Enforcement and the break-glass account.** `sso_enforce` makes a correct
password insufficient for every account but one, which is how a tenant's
MFA and conditional access end up in front of this portal rather than beside
it. The exception is the account the setup code created, marked at creation
rather than nominated later, and neither deletable nor demotable while
enforcement is on: its password is the way back in when the identity
provider is unreachable, so it belongs in a password manager and nowhere
else. Turning enforcement on requires that an owner has **completed** a
federated sign-in first, so the switch cannot be thrown from a configuration
that has never actually worked.

The enforcement check runs **after** the password verifies. The other order
is the tempting one and it leaks: an unauthenticated caller could walk a
list of usernames and read off which one is exempt, because only that one
would answer differently. A wrong password answers exactly as it did before
the feature existed, and break-glass sign-ins get their own line in the
audit trail.

**Invite mail.** With a relay configured, creating an account emails the
person to say it exists. The message deliberately carries nothing worth
intercepting: no token, no password, no link that grants anything - so
intercepting one gains the reader the knowledge that an account exists and
nothing else. The relay credential is stored like the other integration
secrets described below: recoverable, because the receiver must present it
outward, masked in the UI and in the settings API. Prefer setting it from a
Kubernetes Secret (`managed.smtp.password.existingSecret`) so it never
enters the database at all. The invite body is editable, and the portal
warns when it links somewhere other than your own portal - mail from a
security tool telling staff to go and sign in is already the shape of a
phishing message, and a link elsewhere is what would make a real invite
indistinguishable from a forged one.

A word on what the state DB holds, because it changed in 0.9.8. **Fleet
credentials** - enrollment tokens, device credentials, sessions, the admin
password - are stored as hashes only; a copied database file cannot
impersonate anything. **Integration secrets** are different: a log store
password saved in the portal, a notification webhook URL (itself a
bearer capability - whoever holds it can post to the channel), and a
vendor admin API key saved for a Budget user sync, are stored
recoverable, because the receiver must present them outward. Both are
masked everywhere in the UI and in the ordinary settings API. The log-store
plaintext exists on exactly one admin-only route the portal uses
server-side, and the role gate there is load-bearing: the stored credential
is typically write-capable (hosted log stores hand out one token for both
directions), so a read-only viewer recovering it would be a path to
injecting findings past the receiver's validation - viewers are refused,
and the portal reads with its own service credential instead. An admin who
can set a secret can read it back, and a copied database file contains
them. If that trade is unacceptable, leave the log store configured by
environment/Secret as before; the wizard step is optional and the env path
is unchanged.

Where your log store can mint separate tokens, give the receiver a
write-only one and the portal a read-only one (`portal.loki.*` in the
chart): a compromised portal then never holds anything that can write.
The portal's service credential is the receiver's full admin credential
for now; a purpose-built read-scoped service role is on the list, so a
compromised portal would hold less than it needs to today.

The login route is throttled at the application level, because it is
necessarily unauthenticated and scrypt is deliberately expensive: past a
per-username or global failure cap inside a five-minute window, attempts
are refused with a 429 before any password work or database write happens,
scrypt runs are bounded in parallel, and a sustained attack earns a bounded
number of audit rows plus one throttle event rather than a row per attempt.
Ingress rate limiting in front remains worth having; the application no
longer depends on it.

Admin-configurable outbound destinations - the log store, Alertmanager, the
webhook - mean an admin can point the receiver's HTTP client at arbitrary
http(s) locations, including internal ones, and the log-store test button
makes that an authenticated network probe. That is the price of supporting
private, self-hosted stores; it is an *admin* capability, gated like every
other write, and worth knowing when deciding who gets an admin account.
The Budget user sync is deliberately narrower: its outbound
destinations are the vendors' API hosts plus the keyless ECB
exchange-rate source, all hardcoded in the receiver, so a stored key can
only ever be presented to the vendor it belongs to.

The chart's public receiver ingress carries only the reporting surfaces
(/report, /flag, /enroll, /registry, /candidates, /healthz) by default;
/admin and /metrics stay cluster-internal, where the portal reaches them
over the Service. `ingress.exposeAdminApi: true` restores the old
behaviour for a deployment that drives the admin API from outside.
Classically it is HTTP basic auth: one shared credential, no per-user trail,
and plaintext without TLS in front of it. That is a floor, not a ceiling.

It refuses to start without auth configured, so it can't come up open just
because a variable was missed. `PORTAL_AUTH=none` exists for localhost and
for running behind a proxy that authenticates instead, and it logs a warning
on every start so an unauthenticated deployment is always a visible choice.

If you already run a reverse proxy, authenticate there. It can do OIDC, mTLS
or an allowlist against whatever you already have, which is better than what
the portal can offer on its own.

`/healthz` is unauthenticated on purpose: liveness probes shouldn't need
credentials, and it reveals nothing about the estate.

## Rotating the bearer token

Rotation touches every place the token was distributed: the receiver's
Kubernetes Secret, the Jamf script parameters, the Intune platform script
content, managed browser storage for the extension, and the scanner's
secret store (Kubernetes Secret or vault entry). Update the receiver last
so old submitters fail closed (rejected by the new token) rather than new
ones failing open (submitting with the new token to a receiver that still
expects the old one). Expect endpoints to return errors until their next
MDM sync delivers the new value; the collectors treat a rejected POST as
a non-fatal error and will succeed on the following run.

## Exposure

The ingest endpoint must be reachable by endpoints off your network, which
usually means a public ingress. Terminate TLS with a real certificate.

The receiver defends itself first. The bearer token is checked in middleware
before the request body is read, so an unauthenticated caller cannot make it
parse anything, and bodies over `MAX_BODY_BYTES` (64KB by default, which is
generous for a finding) are refused before they are read. Every externally
supplied field is length-bounded. That holds regardless of what you put in
front of it.

Add rate limiting and body size limits at the ingress as well. The receiver's
own limits stop it doing work; the ingress stops the traffic arriving in the
first place, which is the part that protects everything else sharing the
cluster. The annotations are controller-specific, so the chart takes them
through `ingress.annotations` rather than shipping one example that is wrong
for most people.

For ingress-nginx:

```yaml
ingress:
  annotations:
    nginx.ingress.kubernetes.io/proxy-body-size: "64k"
    nginx.ingress.kubernetes.io/limit-rps: "10"
    nginx.ingress.kubernetes.io/limit-connections: "20"
```

For Traefik, the limits live in middleware objects that the ingress then
references:

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: ai-guard-limits
spec:
  buffering:
    maxRequestBodyBytes: 65536
  rateLimit:
    average: 10
    burst: 20
```

```yaml
ingress:
  annotations:
    traefik.ingress.kubernetes.io/router.middlewares: default-ai-guard-limits@kubernetescrd
```

Sizing: a finding is a few hundred bytes, and a collector run posts one
request per detection, so a busy machine sends a handful. Ten requests per
second per source is already generous. If you raise `MAX_BODY_BYTES` for a
source that legitimately sends more, raise the ingress limit to match, or the
ingress will reject what the receiver would have accepted.

## Endpoint collectors

The collectors run as root (Jamf) or SYSTEM (Intune) because MDM-delivered
scripts do, and they read files in user home directories. Review them the
way you review anything you push through MDM. They make exactly one kind of
outbound request (POST findings, GET registry, both to the receiver), spawn
no persistent processes, and write state only under their own directory.

## Upgrading

The portal tells you a newer release exists; it never applies one. That
sentence is the whole design, and everything below exists to keep it true.

### What holds what

Nothing in the cluster or on the compose host gains a right it did not have.
The portal keeps no kubeconfig, no Docker socket, no ServiceAccount beyond
the one every pod has, and no code path that runs `helm`, `kubectl` or
`docker`. The receiver is the same. An upgrade is performed by a small
command, `aiguardctl upgrade`, run on the operator's own machine with the
operator's own credentials - the kubeconfig context or Docker context they
already use to administer the deployment. The platform supplies three
things to that command: proof that an owner asked for this upgrade, the plan
(what is running, what the target is, which route), and a place to write
progress so the portal can show it live. The privilege stays with the
person who already has it.

This is a deliberate rejection of the obvious design, an in-cluster updater
with rights to patch Deployments. Kubernetes RBAC can scope that down a long
way - a namespaced Role, `resourceNames` on the exact objects - but a Helm
upgrade cannot be scoped that way, because Helm manages every object in the
release, and a workload holding write rights in a namespace shared with
other teams is a reasonable thing to refuse. There is no in-cluster
updater, no `ClusterRole`, no socket mount, and none is planned as a
default. If one is ever offered it will be opt-in, image-only, scoped by
`resourceNames`, and documented here first.

### The command's authorisation

`aiguardctl` never handles a password and never learns whether sign-in is
federated. It borrows the portal's sign-in, the way `gh auth login` borrows
GitHub's:

1. The command asks the receiver, through the portal, for a grant. It
   sends the SHA-256 of a verifier it generated and keeps in memory. The
   receiver answers with a device code (returned only to the command) and
   a short user code (shown in the terminal), both expiring in ten
   minutes.
2. The command opens the portal's approval page in the browser, at
   `#cli-approve/<user code>`. The person signs in exactly as they always
   do - the password form, or Microsoft Entra with the tenant's MFA and
   conditional access, whichever the deployment enforces. The portal
   already owns both paths; the command adds no third.
3. The approval page is shown to an **owner** only. It names what is being
   granted (one upgrade), when the request was made, and the user code, and
   asks the owner to compare that code with the terminal before approving.
   An admin reaching the page is told an owner has to approve. Approval and
   denial are audit events naming the owner.
4. The command has been polling with its device code at the interval the
   receiver set. Once approved, it presents the verifier; the receiver
   checks it against the stored hash and issues an upgrade token.

The upgrade token is a distinct credential, prefix `aigu_`, not a session:

- **Scope.** Accepted only by the upgrade routes - read the plan, open a
  run, post steps, finish it, read the verification view. `_admin_auth`
  does not recognise the prefix, so the token opens nothing else on the
  receiver, and the portal forwards it only to those routes.
- **Life.** Forty-five minutes, enough for a rollout to settle. One run per
  token: opening a run consumes the grant, a second attempt is refused.
- **At rest.** Hashed in the receiver's state database, like sessions; the
  plaintext exists in the command's memory and nowhere else. It is never
  written to a file, never printed, never included in progress reports.
- **Binding.** The token is tied to its grant, the grant to the owner who
  approved it and to the verifier hash, and the run to the token. A device
  code without its verifier is worth nothing; a verifier without an
  approved grant is worth nothing.

The two unauthenticated routes, requesting a grant and polling for the
token, sit behind the same kind of throttle the login route uses: a
per-address and global budget of failed or premature polls in a window,
`slow_down` when the interval is ignored, and one aggregated audit event
when the budget is exceeded rather than a row per attempt. User codes are
drawn from a 32-symbol alphabet, eight symbols, expire in ten minutes, and
approval requires an authenticated owner, so guessing a code buys an
attacker nothing they can use.

### What the command may touch

The command applies the plan with the operator's credentials, and it limits
itself further than those credentials would allow:

- On Kubernetes it acts only on objects carrying the chart's labels,
  `app.kubernetes.io/name=ai-guard` and the release's
  `app.kubernetes.io/instance`, and on CronJobs whose image repository is
  this project's own. It refuses to guess when it finds more than one
  release and is not told which. On a Helm-managed release it runs
  `helm upgrade --reuse-values` against the published chart at the target
  version; on a release without Helm it sets image tags on those objects
  and nothing else.
- On compose it acts only on services whose running image repository is
  this project's own, pulling and recreating those services by name rather
  than the whole project, in the project directory the containers' own
  labels record.
- It shows the plan and waits for confirmation. `--yes` exists for
  automation, `--dry-run` prints the exact commands and runs none of them.
- Every command it runs is printed before it runs. Progress reports carry
  step names and outcomes, never command output, so nothing the tools print
  - which can include resource names, values or errors with secrets in them
  - leaves the operator's terminal.

A release must be upgradeable with `--reuse-values` and no new mandatory
input. Where a release needs a value it can derive - from the central
settings the receiver already holds, from a Secret or ConfigMap already
present, from the chart's own defaults - the release metadata says where,
and the command derives it and shows it in the plan. The command asks a
question only when the answer does not yet exist anywhere, and says why.

### If something is compromised

- **A portal session, even an owner's.** It can approve a grant, which
  yields a token that speaks only to the upgrade routes of the receiver:
  it can start a run and write progress lines. It cannot upgrade anything,
  because nothing that holds it has cluster or host rights. The worst
  outcome is a misleading progress display, which is visible in the audit
  log with the approving account named.
- **The portal process.** Same ceiling. The portal relays; it holds no
  credential the upgrade routes would accept on their own, and no rights
  over the deployment.
- **The receiver process.** It could mint upgrade tokens to itself. They
  are still only good for talking to itself about upgrades. It holds
  nothing that reaches the cluster.
- **The operator's machine.** This is the trust boundary, as it already
  was: whoever holds the kubeconfig can do anything the kubeconfig allows,
  with or without this command. The command adds no new secret to that
  machine - the token lives in memory for the length of one run - and no
  new standing capability.
- **A stolen upgrade token.** Forty-five minutes of ability to post fake
  progress, and a run already opened by the legitimate command cannot be
  opened twice. It grants no read of estate data.
- **The release feed.** The portal reads
  `api.github.com/.../releases/latest` and shows what it says. A tampered
  feed could name a wrong version; the command still pulls only from
  `ghcr.io/amansk5/shadow-ai-guard` and the published chart, and shows the
  plan before running. `UPDATE_CHECK=off` removes the read entirely.

### The command itself

`aiguardctl` is Python with no third-party dependencies, installed from a
tagged release of this repository, so what runs is what the tag contains
and can be read before it is installed. It is never fetched from the
portal at run time, and there is no `curl | sh`. It shells out to the
operator's own `helm`, `kubectl` and `docker`, found on their PATH, rather
than embedding any of them.

## What this is not

Detection is visibility, not enforcement: it observes, and a user with local
admin can remove a collector or fake its output. The browser paste guard is
the one part that intervenes, and it is a seatbelt rather than a barrier: it
stops an accidental paste, and someone determined can use a browser it is not
deployed to. The value is making the common case visible and the careless
case difficult, not defeating a determined insider.

## How this repo is checked

Trivy runs on every push and weekly, scanning Python dependencies, OS
packages inside the published images, Dockerfiles and Kubernetes manifests
for misconfiguration, and the tree for committed secrets. It fails the build
on HIGH or CRITICAL with a fix available. The weekly run is the one that
matters: it catches CVEs published against code that has not changed.

Alongside it: CodeQL on Python and JavaScript, Dependabot alerts and updates,
and secret scanning with push protection. Every GitHub Action is pinned to a
full commit SHA, and Python installs are hash-verified against committed
lockfiles.

Configuration is in `.github/workflows/`, `trivy-secret.yaml` and
`.trivyignore`. Accepted findings are recorded in `.trivyignore` with a
reason and an expiry rather than silently suppressed.

## Reporting a vulnerability

Open a private security advisory on GitHub rather than a public issue.