# Troubleshooting

Organised by what you can see, not by what is wrong, because when something
fails you have a symptom and not a diagnosis. Search this page for the string
your terminal or your dashboard is showing you.

Every failure here is one somebody has actually hit.

---

## The collector printed nothing and exited 0

This is usually success. The collectors are quiet when they work, because a
script that chatters on every scheduled run trains people to ignore its output.

Check what it did:

```bash
# macOS
sudo cat "/Library/Application Support/ai-guard/last_scan.txt"
# Linux
sudo cat /var/lib/ai-guard/last_scan.txt
```

```
claude-code(example.com);codeium [posted=2 suppressed=0] (2026-08-08T21:40:38Z)
```

- `posted=N` findings were sent to the receiver.
- `suppressed=N` findings were found but not sent, because the same finding
  was already reported inside the throttle window. Info findings repeat daily,
  warn findings hourly. This is not an error.
- `none` the scan ran and found no AI tooling the registry knows about.

**`posted=0 suppressed=2` on a second run is correct behaviour**, not a
failure. To force a full report while testing, move the state directory aside
and run again:

```bash
sudo mv "/Library/Application Support/ai-guard" /tmp/ai-guard-state.bak
```

Put it back afterwards, or the next scheduled run reports everything as new.

---

## `Refusing to scan: an empty scan looks like a clean machine`

The collector could not find its configuration, so it stopped rather than
producing a scan with no findings. A machine that reports nothing and a machine
with nothing to report look identical on a dashboard, and across a fleet that
is false confidence.

**macOS and Windows take positional parameters, not environment variables**,
because that is how Jamf and Intune pass them. Parameters 1 to 3 are Jamf's
own, so running by hand means passing three empty strings first:

```bash
sudo ./ai-guard-collector.sh "" "" "" \
  https://receiver.example.com <token> example.com
```

**Linux takes environment variables**, because RMM agents and cron set those:

```bash
AIGUARD_RECEIVER_BASE=https://receiver.example.com \
AIGUARD_TOKEN=<token> \
AIGUARD_CORP_DOMAINS=example.com \
  sudo -E ./ai-guard-collector.sh
```

---

## `refusing to scan without an identifier list`

The collector fetched `/registry/collector` from the receiver and did not get
it. It refuses to continue for the same reason as above: without the list of
what to look for, every machine looks clean.

Check the receiver is reachable from the machine, with the token:

```bash
curl -s -o /dev/null -w "%{http_code}\n" \
  -H "Authorization: Bearer <token>" \
  https://receiver.example.com/registry/collector
```

- `200` the receiver is fine, so the problem is the URL the collector was
  given. A trailing slash or a missing scheme is the usual cause.
- `401` wrong token.
- `000` DNS, TLS or network. The collector runs as root, so check root's view
  of the network rather than yours: a proxy set in a user profile does not
  apply.

---

## `POST failed: HTTP 401`

The token the collector holds is not the token the receiver was deployed with.

```bash
# Kubernetes
kubectl -n <ns> get secret ai-guard-receiver -o jsonpath='{.data.authToken}' | base64 -d; echo
# Compose
cat deploy/compose/secrets/auth_token
```

Watch for a trailing newline. `echo "token" > secrets/auth_token` writes one and
`printf` does not, and a token with a newline on the end fails against one
without.

---

## Findings are accepted but nothing appears in Grafana or the portal

**This is the most misleading failure in the system, so check it first when
data is missing.**

Since 0.11.3 a failed push answers the collector with a `503`, so collectors
keep the finding and retry - on current versions this failure shows up as
`POST-FAILED` in collector logs rather than silence. On 0.11.2 and earlier
the receiver returned `200` even when it could not write to Loki: every
collector was satisfied, the finding existed in the receiver's stdout, and
nothing reached either view. Either way, the receiver's own metrics name
the cause:

Check the receiver's own metrics:

```bash
curl -s http://<receiver>/metrics | grep aiguard_loki_push
```

```
aiguard_loki_push_total 1432
aiguard_loki_push_failures_total{reason="HTTPStatusError"} 1432
aiguard_loki_push_last_success_timestamp 0
```

`last_success_timestamp` at `0` means it has never successfully written. Then
read the logs, where the reason is stated:

```bash
kubectl -n <ns> logs -l app.kubernetes.io/name=ai-guard --tail=50 | grep -i loki
docker compose logs receiver | grep -i loki
```

```
loki push rejected with HTTP 404: this looks like a base URL rather than the
push endpoint, which is /loki/api/v1/push
```

**`LOKI_PUSH_URL` and `LOKI_URL` are different values on purpose.**

| Variable | Component | Value |
|---|---|---|
| `LOKI_PUSH_URL` | receiver | the full push endpoint, ending `/loki/api/v1/push` |
| `LOKI_URL` | portal | the base URL, no path |

Posting to the base returns 404. Querying the push endpoint returns nothing.

**All the receiver's counters are in memory and reset when the pod restarts.**
So zeros immediately after a deploy mean nothing at all. `last_success_timestamp`
is the one to read, because it distinguishes "restarted a minute ago" from
"has never worked".

---

## The portal will not start

```
refusing to start without authentication
```

The portal names who runs what on which machine, so it will not come up
unauthenticated by accident. Either set a password, let the chart generate one,
or set `PORTAL_AUTH_MODE=none` deliberately when something in front of it is
doing the authenticating.

```bash
kubectl -n <ns> get secret ai-guard-portal -o jsonpath='{.data.password}' | base64 -d; echo
```

---

## The portal starts but every page is empty

```
LOKI_URL is not set
```

The portal has no findings to read. If it is set, check it is the **base** URL
and not the push endpoint, and that it is reachable from inside the cluster or
compose network rather than from your laptop.

If `LOKI_URL` is right and pages are still empty, the findings are not in Loki.
Go to the section above about accepted findings that never arrive.

---

## A source shows `not reporting` but I definitely deployed it

The setup page derives what is reporting from findings that carry that
`source` value, not from configuration existing. A source with no findings
bearing its name is listed as silent.

Two different causes:

1. **It genuinely has not reported.** Nothing was scheduled, credentials are
   missing, or it has run and found nothing.
2. **It is reporting without setting `source`.** The findings arrive and are
   counted everywhere else, but they cannot be attributed to a detector, so the
   source looks silent while the data is present.

Tell them apart by looking for findings that match the source's surface but
carry no source:

```logql
sum by (surface) (count_over_time({app="ai-guard-receiver", kind="finding"}
  | json source="source" | source = `` [24h]))
```

A large count on a surface whose source says `not reporting` is cause 2.

---

## `helm install` fails with an ownership error

```
Error: rendered manifests contain a resource that already exists ...
invalid ownership metadata
```

Something in the namespace has the name the chart wants and was not created by
Helm. This is common when adopting the chart alongside an existing hand-rolled
deployment: the registry ConfigMap is the usual one.

Point the chart at what already exists rather than letting it create its own:

```yaml
registry:
  create: false
  existingConfigMap: ai-guard-registry
auth:
  existingSecret: ai-guard-receiver
```

Reusing the existing secret also means every collector, extension and scanner
keeps its current token, so nothing has to be redeployed.

---

## The receiver crash-loops on `unable to open database file`

```
sqlite3.OperationalError: unable to open database file
```

Managed mode keeps its state DB on a PVC, and the PVC arrived owned by root.
Most StorageClasses hand volumes over that way; it is `fsGroup` in the pod
security context that makes the kubelet chown the mount to the pod's group.
The chart runs the receiver as uid 65532, so without `fsGroup` that uid cannot
create `/var/lib/ai-guard/state.db` and the pod dies before serving anything.

Chart 0.10.5 sets `fsGroup: 65532` by default. On an older chart, or with a
values file that replaces `podSecurityContext` wholesale, add it back:

```yaml
podSecurityContext:
  fsGroup: 65532
```

and `helm upgrade`. The pod recovers on the next start; nothing on the volume
needs repair.

---

## `ImagePullBackOff`

```bash
kubectl -n <ns> describe pod <pod> | tail -20
```

- **`manifest unknown`** the tag does not exist. The chart defaults the tag to
  its `appVersion`, so a chart version ahead of the published images asks for
  one that was never built.
- **`unauthorized`** a private registry with no pull secret. The published
  images are public, so this usually means the values were pointed at a private
  mirror.

---

## The same machine appears twice

The `device` field changed, so the two halves of its history do not join.

The collectors report the most stable identifier available: a hardware serial,
then a machine id, then the hostname. If a machine used to report a hostname and
now reports a serial, or the reverse, it becomes two devices.

macOS says so when it happens:

```
[ai-guard] serial lookup failed via ioreg, falling back to hostname for device
```

Old findings age out of the portal's lookback window on their own. There is
nothing to repair, but the count is wrong until they do.

## The invite email never arrived

Three different failures wear the same symptom, and the portal tells them
apart if you look in the right place.

**The portal said nobody was emailed.** Then nothing was sent, and it is not
a delivery problem. Either no relay is configured, or the account was made
without an address. Settings > Account has the relay wizard; once it is
configured, the button that resends to everybody who was missed closes the
gap for accounts created before it.

**The portal reported an error from the relay.** That string is what the
relay said, passed through. `535` or `Authentication unsuccessful` is the
credential. `550` or `Relay access denied` means the relay took the
connection and refused to carry mail for that sender - the usual cause is
`From` not being an address that relay is willing to send as. A timeout
usually means egress: cluster network policy, or a provider that blocks
outbound 25.

**The relay accepted it and it still is not there.** Then it left this
platform and the trail continues in your mail infrastructure. `250 Queued
mail for delivery` is an acceptance, not a delivery. Two things account for
most of it: the message went to junk, and the recipient's tenant filtered it
as a spoof because it claims to come from a domain that tenant owns while
arriving from a relay it does not recognise. Send the test to an address on
a different domain to tell those apart quickly - if that one arrives, the
problem is your own tenant's anti-spoof handling, not this platform.

Use the test send in the relay wizard rather than creating accounts to
experiment. It reports exactly what the relay said, and it makes no account.

## `Sign in with Microsoft` is not on the login screen

It appears once federated sign-in is switched on, and not before, because a
button that looks live and is not makes people doubt their own password. If
you have configured it and the button is missing, the last wizard step - a
real sign-in - has not been completed: nothing takes effect until it has.

## A federated sign-in is refused

The refusal page says which check failed. The common ones:

- **No account carries that address.** Expected: it authenticates, it does
  not provision. Create the account first, with that address on it.
- **That sign-in is too old.** The provider answered with the time the
  person last actually authenticated, and it is outside the window this
  deployment asks for. Signing in again fixes it. Widen the window under
  Settings > Account if twelve hours is wrong for you.
- **The provider did not say when this person last signed in.** The token
  came back with no `auth_time` claim, so freshness cannot be established
  and is not assumed. Setting the window to "every time" is not a
  workaround; the claim is what the check reads.
- **This account is bound to a different identity.** Binding is permanent
  by design, because an address can be reassigned and rebinding would hand
  somebody else's account away. Unbind it deliberately from Settings >
  Account.

## Locked out after requiring single sign-on

Sign in as the account the setup code created. It keeps its password
precisely for this, it cannot be deleted or demoted while enforcement is on,
and once you are in you can turn enforcement off from Settings > Account.

If that password is lost too, the receiver's `ADMIN_TOKEN` credential resets
it: `POST /admin/password` with that token and a `new` password targets the
oldest admin account, no `current` required. See the endpoint table in
[receiver/README.md](receiver/README.md). It needs access to the receiver's
environment, which is the point - recovery belongs to whoever owns the box
and to nobody else. `ADMIN_TOKEN` is optional and unset by default, so this
path exists only if you set one up in advance.

---

## Something else

Open an issue with what you can see: the symptom, the component, and the output
of the relevant check above. A symptom plus the failing string is enough to work
with; a description of what you expected instead is not.