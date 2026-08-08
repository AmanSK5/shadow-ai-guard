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
    openssl rand -hex 24 > secrets/portal_password
    chmod 600 secrets/*

Edit `.env`. At minimum, set `LOKI_URL` if you are running the portal, and pin
`IMAGE_TAG` to a released version rather than leaving it at `latest`.

    docker compose up -d
    docker compose ps

The receiver is on `127.0.0.1:8080` and the portal on `127.0.0.1:8091`.

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

`secrets/` and `.env` are gitignored.

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

Rate limiting belongs here too. The receiver refuses oversized bodies and checks
the token before reading a request body, so it defends itself, but stopping
traffic before it arrives is what protects everything else on the host.

## Authentication

The receiver authenticates reporting sources with a shared bearer token, the one
in `secrets/auth_token`. That token goes into your MDM script parameters, your
managed browser configuration, and your scanner environment.

The portal authenticates separately with HTTP basic auth, and **refuses to start
without it**. It names who runs what on which machine, so coming up open because
a variable was missed is the failure that matters.

Basic auth is one shared credential with no per-user trail. If you already run a
reverse proxy, authenticate there instead - it can do OIDC, mTLS or an
allowlist against whatever you already have - and run the portal with
`PORTAL_AUTH=none` behind it. That opt-out logs a warning on every start, so an
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
    curl -s -u admin:"$(cat secrets/portal_password)" localhost:8091/api/status

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