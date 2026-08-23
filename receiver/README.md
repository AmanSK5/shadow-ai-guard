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
exists rather than inferring it from silence. Platforms are `macos`, `linux`,
`windows`, `browser` (one row per managed browser profile: serial is the MDM
device id plus a per-profile install id) and `scanner` (serial is the
scanner's configured id). Every authenticated request with a device
credential - a report or a registry read - stamps the device's `last_seen`,
and its agent version when the request carries `X-AiGuard-Agent-Version`.
When every surface has enrolled, `REQUIRE_DEVICE_CREDENTIALS=true` turns the
shared token off for ingest (see the configuration table).

| method | path | auth | what |
|--------|------|------|------|
| POST | `/enroll` | enrollment token | exchange for this device's own credential; a same-serial re-enroll reissues a silent device's credential in place (same id, old credential dead, `reenrolled_at` and `enrollments` say it happened - the reimaged laptop, or a stateless scanner enrolling every run) and 409s a device seen within the hour. Platform `scanner` is exempt from that guard: it enrolls every run by design |
| POST | `/admin/enrollment-tokens` | admin | mint (`note`, `ttl_days`, default 180) |
| GET  | `/admin/enrollment-tokens` | admin | list - ids, notes and expiry, never token material |
| POST | `/admin/enrollment-tokens/{id}/revoke` | admin | |
| GET  | `/admin/devices` | admin | the fleet: platform, serial, hostname, enrolled / re-enrolled, last seen, agent version |
| POST | `/admin/devices/{id}/revoke` | admin | that machine's credential stops working on its next request |
| GET  | `/admin/setup` | none | one bit: does an admin account need creating? The portal chooses its first screen with it |
| POST | `/admin/setup` | setup code | claim the boot-printed code, create the admin account, leave with a session |
| POST | `/admin/login` | none | username + password for a session token (`aigt_...`) |
| POST | `/admin/logout` | admin | revoke the presented session |
| GET  | `/admin/session` | admin | who this session is and until when; the portal's validity probe |
| POST | `/admin/password` | admin | change the password (`current` + `new`). With the `ADMIN_TOKEN` credential, `current` is not required - the break-glass reset. Every other session dies with the old password |
| GET  | `/admin/settings` | admin | each central setting with its effective value and its source (`db`, `env`, `unset`), so a saved value shadowing an environment one is visible as such. The log-store password is reported as `{set, source}` only, never its value |
| PUT  | `/admin/settings` | admin | partial upsert; a saved value wins over the matching env var, an explicit `null` (or empty) deletes the row and falls back to it. Unknown keys are 422. Keys: `corp_domains`, `extension_id`, `onboarding_done`, `receiver_public_url`, `log_store_url` (base - the push endpoint is **derived** as `<base>/loki/api/v1/push`), `log_store_push_url` (explicit override for gateways), `log_store_username`, `log_store_password`, `alertmanager_url`, `grafana_url`, `grafana_panels`, `grafana_dashboard_uid`, `overview_widgets` |
| GET  | `/admin/settings/secrets` | admin | the stored log-store configuration with the password in plaintext - for the portal's server-side reads; the portal exposes no route that relays it. See SECURITY.md on integration secrets vs fleet credentials |
| POST | `/admin/test/log-store-push` | admin | push one synthetic `kind:"test"` line with the effective configuration and report what happened, hints included - catches the write-only-token trap at setup time instead of on the first quiet dashboard |
| GET  | `/admin/registry-entries` | admin | the portal-defined registry entries, each flagged `shadowed` if a later release ships the same id (shipped wins at serve time; a shadowed local copy is a row to delete) |
| PUT  | `/admin/registry-entries` | admin | upsert (`entries`) and delete (`delete`) portal-defined tools - the same shape as a shipped registry entry, validated against the registry's own schema and rules (lowercase domains, no domain claimed twice, no shipped id redefined; `added_by`/`approved` are forced, approval lives in governance). The whole batch validates before anything writes; the merged registry serves immediately, so collectors detect a defined tool on their next check-in |
| GET  | `/admin/governance` | admin | the portal-recorded governance decisions |
| PUT  | `/admin/governance` | admin | upsert (`decisions`) and delete (`delete`) decisions, validated to the governance file's own rules - an approval needs a `review_due` date. The whole batch validates before anything is written |

**Admin auth** is either of two things: a session from `/admin/login`, or
the optional `ADMIN_TOKEN` API credential. Humans get the first; automation
and break-glass recovery get the second. On a fresh managed deployment no
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

The receiver answers 200 to a reporting source even when the push to the log
store fails. That is deliberate - a log store being down should not lose a
collector's finding, which is on stdout regardless - but it means a
misconfigured push is invisible from the collector's side.

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