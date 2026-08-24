# Trying it, and telling me what broke

This is an alpha. It runs in one environment, mine, and the useful thing
someone else can do is follow the documentation without knowing any of the
history behind it and say where it stops making sense.

Three routes below. Pick the one that matches what you have. None of them
needs a company tenant, a fleet, or an MDM.

Findings are useful whichever route you take, and "I got stuck at step 3 and
gave up" is a better report than a clean run.

## Before you start

The endpoint collectors read files in a user's home directory and run as root
on macOS and Linux, or SYSTEM on Windows, because that is how MDM-delivered
scripts run. Read the script before you run it. They are a few hundred lines
of shell or PowerShell and the whole point of this project is that you can.

For a first run, use a machine you do not mind experimenting on, and a test
profile rather than your main one if that is easy. The collectors read
configuration files and report which account domain each AI tool is signed
into. They do not read message content, file content or credentials, and
`docs/deployment-privacy.md` sets out exactly what is collected and what is
deliberately not.

## Route 1: the demo, 15 minutes

Nothing touches your machine's configuration. Everything is synthetic.

```bash
git clone https://github.com/AmanSK5/shadow-ai-guard.git
cd shadow-ai-guard/demo
docker compose up
```

Then:

- open http://localhost:8091. The demo runs managed mode like a real
  deployment, so it asks for the one-time setup code the receiver printed
  (`docker compose logs receiver | grep setup_code`). Create the throwaway
  admin account, click through the wizard, and explore - the seeded
  findings are already in there
- open http://localhost:3000 and find the "AI Guard - Shadow AI Visibility"
  dashboard. It should already have data in it
- open http://localhost:8090/demo/ and paste one of the test values on the
  page into the box. The paste guard should stop it
- stop and wipe with `docker compose down -v`

What this tells me: whether a clean clone works, whether the first-boot flow
makes sense cold, and whether the portal makes sense to somebody who has not
seen it before.

Worth reporting: any container that failed, an empty dashboard, a panel that
says No data, or anything on the dashboard you could not interpret.

## Route 2: a collector against your own machine, 30 minutes

This is a real test rather than a demo: the collector reads your actual
machine and sends real findings through the platform. It just sends them to a
receiver running on your laptop.

Start the demo as above and leave it running, then run the collector for your
platform against it. The per-platform README has the exact command:

- macOS: `endpoint/macos/README.md`
- Windows: `endpoint/windows/README.md`
- Linux: `endpoint/linux/README.md`

Point it at `http://localhost:8080`, use the token `demo-token`, and set the
corporate domains to something that is not your own, so your real accounts
show up as personal findings and you can see what the tool actually reports.

What this tells me: whether detection works on a machine that is not mine,
and whether what it collects matches what the privacy documentation says it
collects.

Worth reporting: a tool you have installed that was not detected, a finding
that named the wrong tool, an account domain that was wrong, and anything
collected that surprised you. That last one matters most.

## Route 3: a local Kubernetes deployment, 45 minutes

For anyone with Minikube, k3s, kind, Docker Desktop Kubernetes or a homelab
cluster.

`docs/getting-started.md` takes you from a clone to a first finding. There is
a Helm chart if you want the short version:

```bash
helm install ai-guard charts/ai-guard \
  --set ingress.enabled=true --set ingress.host=<something you can reach> \
  --set portal.ingress.enabled=true --set portal.ingress.host=<another one>
```

Then create the admin account with the setup code from the receiver's log,
follow the wizard, download a collector from it, and run that on your own
machine. The download carries its own enrollment token, so there is no token
to copy around.

What this tells me: whether the deployment instructions work on a cluster
that is not mine. This is the route with the most assumptions baked in and
the one most likely to have gaps.

Worth reporting: any step that needed knowledge the documentation did not
give you.

## Breaking it on purpose

If you have time, point a collector at a receiver that does not exist, or use
a wrong token. It should say so clearly rather than reporting nothing and
exiting quietly. A collector that silently reports nothing looks exactly like
a clean machine, which is the failure this project cares most about avoiding.

## Reporting

Open an issue: https://github.com/AmanSK5/shadow-ai-guard/issues/new/choose

There are templates for installation problems, wrong or missing detections,
privacy concerns and unclear documentation. If none fits, a plain issue is
fine.

Useful to include:

- your OS and architecture, and Docker or Kubernetes versions if relevant
- which route you took and how far you got
- what you expected and what happened
- the command that failed, and its output

If something looks like a security problem, please use a private security
advisory rather than an issue:
https://github.com/AmanSK5/shadow-ai-guard/security/advisories/new

## What happens to your feedback

Everything gets tracked in the open, including the parts where the answer is
that I got it wrong. The issue list already carries several of those. If you
report something and it turns out to be a real bug, you will be able to read
the fix.