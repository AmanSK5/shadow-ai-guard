# Deploying with Docker Compose

Two stateless containers: the receiver accepts findings and writes them as JSON
lines, the portal reads those lines back and derives relationships. Neither
needs an orchestrator, and this route exists because requiring Kubernetes for
two stateless containers is a barrier rather than a design.

The Kubernetes route is `charts/ai-guard`. Both deploy the same images.

## What this does not include

Loki and Grafana. Production points at whatever you already run, because most
people deploying this already have a log store and adding a second one is not a
favour.

If you have neither, the `with-logs` profile starts both:

    docker compose --profile with-logs up -d

Set `GRAFANA_ADMIN_PASSWORD` first, and in `.env`:

    LOKI_PUSH_URL=http://loki:3100/loki/api/v1/push
    LOKI_URL=http://loki:3100

Those two differ on purpose. `LOKI_PUSH_URL` is the full push endpoint the
receiver POSTs to verbatim, and posting to the base URL returns 404. `LOKI_URL`
is the base the portal appends its own query path to.

A wrong `LOKI_PUSH_URL` is quiet in a way worth knowing about: the receiver
still returns 200 to the reporting source, because a log-store failure should
not lose a collector's finding, and the failure is logged rather than raised.
So the collector is satisfied, the finding exists in the receiver's stdout, and
nothing reaches the portal. If the portal shows nothing after a finding was
accepted, check `docker compose logs receiver` for a Loki error before anything
else.

## Setup

    cd deploy/compose
    cp .env.example .env

    mkdir -p secrets
    openssl rand -hex 32 > secrets/auth_token
    chmod 700 secrets
    chmod 640 secrets/*
    sudo chown :65532 secrets/*

Edit `.env`: pin `IMAGE_TAG` to a released version rather than leaving it at
`latest`. Everything else can wait for the portal.

    docker compose up -d
    docker compose logs receiver | grep setup_code

The receiver is on `127.0.0.1:8080` and the portal on `127.0.0.1:8091`. Open
the portal, enter the setup code, create the admin account, and the first-run
wizard configures the rest - the log store included.

**Classic mode instead** (file-and-env config, basic auth, no server-side
state): create `secrets/portal_password` too, set `LOKI_URL` and
`LOKI_PUSH_URL` in `.env`, and layer the overlay:

    openssl rand -hex 24 > secrets/portal_password
    docker compose -f docker-compose.yml -f docker-compose.classic.yml up -d

### A hosted log store

`LOKI_USERNAME` and `LOKI_PASSWORD` are used by BOTH containers: the receiver to
write and the portal to read. Setting them for one and not the other produces a
deployment where findings are stored and cannot be read back, and neither
container reports an error you would attribute to the right cause.

Three things about Grafana Cloud specifically, because each of them fails in a
way that points somewhere else:

The username is a numeric instance id, not an email. It is on the Loki details
page for your stack.

`LOKI_PUSH_URL` is the full endpoint ending `/loki/api/v1/push`, while `LOKI_URL`
is the base URL without it, because the portal appends its own query path. Same
host, two different values.

The access policy needs both `logs:write` and `logs:read`. A read-only token
produces a 401 on every push that the receiver counts and logs, while still
answering 200 to the collector, so findings look accepted and are not stored.
Check before you assume it worked:

    curl -s localhost:8080/metrics | grep -E 'loki_push_total|failures_total'

A `push_total` that stays at zero while findings arrive is that failure.

## Secrets

Secrets are read from files, not from the environment. An environment variable
is visible in `docker inspect`, in `/proc`, and in every child process's
environment. A file is confined to the filesystem.

**That is better and it is not encryption.** It is still plaintext on the same
disk, and the mode on `secrets/` is what protects it. If you want more, the
receiver and portal read whatever is at those paths, so a tmpfs populated by
your configuration management, or a Vault agent sidecar writing the file, both
work without changing anything here.

Both containers fail to start if a secret file is missing or unreadable. That
is deliberate: falling back would start the receiver with an empty token, or the
portal with an empty password that an empty input would match.

### Permissions

Both images run as uid 65532, and a Linux bind mount preserves ownership, so a
secret file that only its owner can read is a file the container cannot read.
The container then exits at startup rather than running with an empty
credential, which is correct but looks like nothing happening.

Hence the group ownership above: `640` with group `65532` means the container
can read it and other users on the host cannot. `chmod 700 secrets` stops
anyone listing the directory.

If you would rather not use `sudo`, `chmod 644` works and is what most
container images end up needing, but it means any local user can read the
token. The directory mode does not save you there, because the container needs
to traverse it.

Docker Desktop on macOS papers over this: its file-sharing layer maps ownership,
so `600` works there and fails on a Linux host. Worth knowing if you develop on
a Mac and deploy on Linux.

`secrets/` and `.env` are gitignored.

## When findings stop arriving

The receiver answers 200 to a reporting source even when the push to the log
store fails, and that is deliberate: a log store being down should not lose a
collector's finding, which is on stdout regardless. It does mean a
misconfigured push is invisible from the collector's side.

Three things make it visible:

    docker compose logs receiver | grep '"kind": "error"'

Push failures are logged at error with the URL and, for the two codes that
account for almost every misconfiguration, the likely cause. A 404 means
`LOKI_PUSH_URL` is the base URL rather than `/loki/api/v1/push`; a 401 or 403
means `LOKI_USERNAME` and `LOKI_PASSWORD` are needed or wrong.

`aiguard_loki_push_failures_total` counts them by reason on `/metrics`.

`aiguard_loki_push_last_success_timestamp` is the one to alert on. Findings
arrive irregularly, so a failure count alone cannot tell "nothing is being
pushed because nothing is happening" from "everything is failing". Alert when
`time() - aiguard_loki_push_last_success_timestamp` exceeds however long your
estate can plausibly be silent.

For failures outside this file, including collectors that report nothing,
sources the portal lists as silent while they are sending, and the same
machine appearing twice, see [Troubleshooting](../../TROUBLESHOOTING.md).

## Exposure and TLS

Ports bind to loopback. That is not the finished state - the receiver has to be
reachable by endpoints off your network - but exposure is a decision you make,
not one a compose file makes for you.

Put a reverse proxy in front that terminates TLS. Which one is yours to pick;
the compose file does not choose and neither does this document beyond one
worked example.

With Caddy, a `Caddyfile` alongside this directory:

    ai-guard.example.com {
        reverse_proxy 127.0.0.1:8080
    }

    portal.example.com {
        reverse_proxy 127.0.0.1:8091
    }

Caddy obtains and renews the certificate itself. nginx, Traefik and a cloud load
balancer all work equally well; the only requirement is TLS in front, because
the bearer token and the portal password are both sent in plaintext without it.

### One hostname

Two names assumes public DNS you control, which a VM on an internal network
often is not. With one name, split by port rather than by path: both containers
answer `/healthz`, and a path split would make the collector's base URL a
subpath rather than a host.

    host.example.com:8443 {
        tls /path/cert.crt /path/cert.key
        reverse_proxy 127.0.0.1:8080
    }

    host.example.com:443 {
        tls /path/cert.crt /path/cert.key
        reverse_proxy 127.0.0.1:8091
    }

Collectors then take `https://host.example.com:8443` as their receiver base.

A private network needs a certificate from somewhere, and a self-signed one
means every collector has to be told to trust it, which is a worse thing to
document than to avoid. A mesh network that issues real certificates for its own
names solves it in one command and needs nothing exposed publicly:
`tailscale cert <name>` writes a `.crt` and `.key` that Caddy reads directly.
Whatever issues them, the proxy config above is the same.

Whichever you use, the certificate has to be readable by the proxy: Caddy runs
as its own user, and a key left at `0600 root:root` produces a proxy that starts
and then fails every connection.

Rate limiting belongs here too. The receiver refuses oversized bodies and checks
the token before reading a request body, so it defends itself, but stopping
traffic before it arrives is what protects everything else on the host.

## Authentication

The receiver authenticates reporting sources with a shared bearer token, the one
in `secrets/auth_token`. That token goes into your MDM script parameters, your
managed browser configuration, and your scanner environment. In managed mode -
the default - an enrollment token minted in the portal goes in those same
places instead (the pre-configured downloads carry one already), and each
collector, browser profile and scanner exchanges it once for a credential of
its own; `REQUIRE_DEVICE_CREDENTIALS=true` in `.env` then turns the shared
token off for ingest once everything has enrolled.

The portal authenticates separately, and **refuses to start without it**. It
names who runs what on which machine, so coming up open because a variable
was missed is the failure that matters.

In managed mode - the default - the portal has a real login: the receiver
prints a one-time setup code to its log on first boot (`docker compose logs
receiver | grep setup_code`), and the portal's first screen turns it into
the admin account. With the classic overlay
(`docker-compose.classic.yml`) it is HTTP basic auth - one shared
credential with no per-user trail. If you already run a reverse proxy,
authenticate there instead - it can do OIDC, mTLS or an allowlist against
whatever you already have - and run the portal with `PORTAL_AUTH=none`
behind it. That opt-out logs a warning on every start, so an
unauthenticated deployment is never something nobody noticed.

## The registry

`registry-builder` compiles `registry.yaml` into the two views the receiver
serves, then exits. It is a one-shot container on a stock Python image, not a
build, and it reads the repository you cloned.

The registry is not baked into the receiver image on purpose: it is the thing a
deployer edits most - approving a tool, adding a domain - and baking it in would
mean a new image for a one-line YAML change.

After editing `registry/registry.yaml`:

    docker compose up -d --force-recreate registry-builder receiver portal

## Updating

    docker compose pull
    docker compose up -d

If `IMAGE_TAG` is pinned, that is a no-op until you change it, which is the
point of pinning it.

## Checking it works

    curl -s localhost:8080/healthz

Then sign into the portal and open Setup (in classic mode:
`curl -s -u admin:"$(cat secrets/portal_password)" localhost:8091/api/status`).

Then open the portal. It lands on a setup view showing which sources are
reporting and which are silent, derived from the findings themselves rather than
from configuration being present. Immediately after install everything is
silent, which is the honest picture rather than a broken one: roll one collector
and it appears.

## Logs

    docker compose logs -f receiver
    docker compose logs -f portal

Every finding the receiver accepts is a JSON line on stdout, whether or not
`LOKI_PUSH_URL` is set. If you already run a log agent, scraping these containers
is a valid alternative to configuring the push.