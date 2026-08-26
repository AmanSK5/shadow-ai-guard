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
endpoint collectors then enroll for per-device credentials, one machine can
be revoked without touching any other, and an enrollment token in an MDM
artifact can create auditable device records but never submit findings. The
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
against the receiver per request. Accounts carry a role: an admin runs the
platform, a viewer reads every page and is refused by every write route -
the shape for an auditor, who gets the visibility without becoming a way
in. The last admin cannot be deleted, password resets revoke the sessions
the old password minted, and every admin action lands in the receiver's
event log with who did it.

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
destinations are the vendors' API hosts, hardcoded in the receiver, so a
stored key can only ever be presented to the vendor it belongs to.

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