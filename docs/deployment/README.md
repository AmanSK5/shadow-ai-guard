# Deployment

Two routes. Both deploy the same images, take the same configuration, and
produce the same findings. Pick whichever matches what you already run.

| | [Docker Compose](../../deploy/compose/README.md) | [Kubernetes](kubernetes.md) |
|---|---|---|
| what it is | two containers on a host | a Deployment, a Secret and a ConfigMap |
| the portal | included | included, enabled by default |
| TLS and exposure | a reverse proxy you run | an ingress controller |
| secrets | files on disk, mode-protected | Kubernetes Secrets, or your secret store |
| best when | you have a VM and no cluster, or want the smallest thing that works | you already run a cluster |

**The receiver does not need an orchestrator.** It is one stateless container,
and so is the portal. Kubernetes is a fine place to run them and it is not a
requirement, which is the whole reason the compose route exists
([#49](https://github.com/AmanSK5/shadow-ai-guard/issues/49)).

## What is the same either way

**The registry.** Compiled from `registry.yaml` and served by the receiver, so
collectors fetch their identifier lists at runtime. Adding a tool is a merge
request rather than a change pushed to every endpoint. How it reaches the
receiver differs - a mounted volume on one route, a ConfigMap on the other -
but nothing downstream can tell.

**The bearer token.** One shared token that every collector, scanner and the
browser extension authenticate with. Where it lives differs; what it does does
not. In managed mode each of them can instead carry an enrollment token and
exchange it once for a credential of its own, which is what makes one machine,
one browser profile or one scanner revocable on its own.

**The log store.** Neither route bundles one for production. The receiver
writes JSON lines to stdout regardless, and pushes to Loki when
`LOKI_PUSH_URL` is set, so an existing log agent scraping the container is as
valid as configuring the push.

**Everything after the receiver.** Collectors, scanners, the extension, the
dashboard and the portal are identical. Only the first step differs.

## Neither, for now

The demo in [`demo/`](../../demo/README.md) needs no cluster, no real data and
no credentials. `docker compose up` brings up the receiver, Loki, Grafana, the
portal and a seeder, populated in a few minutes. It is the fastest way to see
what any of this looks like before deciding where to put it.

## Then

[Getting started](../getting-started.md) picks up after the receiver is
running: rolling out a collector, seeing the first finding, the dashboard, and
the portal.

Before deploying for real, read [privacy and DPIA
guidance](../deployment-privacy.md). This is workplace monitoring and usually
warrants a DPIA.