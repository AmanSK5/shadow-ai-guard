# Security model

This document states the trust model plainly so you can decide what it means
in your environment. It errs on the side of admitting limitations.

## Data handled

Findings contain usernames, device serials, tool names, account domains and
evidence paths. They deliberately exclude mailbox local parts, message
content, file content and credentials. Even so, the aggregate is a map of who
uses what on which machine: treat the receiver's log store (e.g. your Loki
tenant) as sensitive, and scope dashboard access accordingly.

For privacy and DPIA guidance, see docs/deployment-privacy.md.

Alert labels include the username, because it is part of the alert's
dedup identity; scope Alertmanager UI access accordingly.

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
- Compromise of one endpoint reveals the same token every endpoint uses.

If that is unacceptable in your threat model, front the receiver with your
own per-source authentication.

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
usually means a public ingress. Deploy it with rate limiting and body size
limits at the ingress layer, and TLS terminated with a real certificate. The
receiver performs no lookups or writes on unauthenticated requests.

## Endpoint collectors

The collectors run as root (Jamf) or SYSTEM (Intune) because MDM-delivered
scripts do, and they read files in user home directories. Review them the
way you review anything you push through MDM. They make exactly one kind of
outbound request (POST findings, GET registry, both to the receiver), spawn
no persistent processes, and write state only under their own directory.

## What this is not

This is a visibility tool, not a control. It does not block anything, and a
user with local admin can remove the collector or fake its output. Its value
is making the common case visible, not defeating a determined insider.

## Reporting a vulnerability

Open a private security advisory on GitHub rather than a public issue.