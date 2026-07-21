# Writing a scanner

A scanner is anything that detects AI tool usage and reports it to the
receiver. This is the project's extension point: the receiver does not care
whether a finding came from a bundled scanner, a new cloud integration, or a
shell one-liner, as long as it is the finding shape. This page is the
contract.

## The contract

Emit findings in this shape and POST them to the receiver. That is the whole
interface:

```json
{
  "tool": "some-ai-tool",
  "surface": "cloud",
  "os": "unknown",
  "account_domain": "gmail.com",
  "device": "",
  "user": "",
  "evidence": "entra-signin",
  "severity": "warn",
  "reported_at": "2026-01-01T09:00:00Z",
  "source": "scanner-yourthing"
}
```

Field rules:

- **tool** should match a registry entry where possible, so it lines up with
  other sources on the dashboard. If your source discovers something not yet
  in the registry, add it to the registry too.
- **surface** is one of browser, cli, ide, desktop, network, cloud. Pick the
  one that describes how you observed it.
- **os** is the device OS if you know it, else `unknown`. Cloud and network
  findings usually have no single device, so `unknown` and an empty
  `device` is correct.
- **account_domain** is the domain only. If your source gives you a full
  address, strip the local part before putting it here. The `account_domain`
  field must never contain a local part or full email.
- **user** carries the account identity for follow-up. For approved corporate
  domains this may be the email's local part; it must be left empty for
  personal-domain accounts. Never put a personal email's local part in any
  field.
- **severity**: send `warn` if the account is not a corporate account,
  `info` otherwise. If your source cannot tell (presence only, no account),
  send `info` and leave `account_domain` empty.
- **source** is a stable identifier for your scanner, for provenance.

## Posting a finding

POST to the receiver's report endpoint with the bearer token:

```bash
curl -X POST https://your-receiver-host/report \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  --data '{ ...finding... }'
```

A 200 means accepted. That is all a source has to do. Everything else, the
logging, the dashboard, the alerting, is handled by the receiver.

## Two kinds of scanner

**A cloud/fleet scanner** queries an API (an identity provider, an EDR, an
MDM) and reports findings for many users at once. The bundled scanners work
this way. If you are adding one, the natural home is a module under
`scanner/ai_guard/scanners/`, following the shape of the existing modules:
each is self-contained, reads its own credentials from environment, and
returns findings the runner posts. Look at one of the existing modules as a
template; they all implement the same small interface.

**An endpoint collector** runs on one machine and reports what that machine
has. The three OS collectors work this way. A new one (a different RMM, a
different OS) is a script that reads the local AI tool config files and
posts findings. The existing collectors fetch the registry from the
receiver's `/registry/collector` endpoint at runtime, so they do not
hardcode tool identifiers; a new collector should do the same.

## Adding a tool to the registry

If your scanner detects a tool not already known, add it to
`registry/registry.yaml`. At minimum a tool needs a name, vendor, category,
and the identifiers your surface matches on (a domain, an app name, an
extension ID, a config path). The registry schema documents every field, and
`python registry/build.py --check` validates your addition.

The more identifiers you add, the more surfaces can match the same tool, so
it shows up as one tool on the dashboard rather than several unrelated rows.

## What not to do

- Do not add tool-specific logic to the receiver. The receiver is
  deliberately generic; a source that requires the receiver to know about it
  is designed wrong.
- Do not send a full email address, message content, file content, or
  credentials. A corporate email's local part may be sent in the `user`
  field where attribution is required, but a personal account's local part
  must not be. The finding is intentionally minimal; keep it that way.
- Do not make the account domain a corporate/personal decision in your
  scanner beyond the simple domain check. What counts as corporate is the
  deployer's configuration, computed downstream.

## Testing your scanner

Point it at a receiver running locally or in a test namespace, post a
finding, and confirm it appears in the receiver logs and on the dashboard.
If it shows up correctly attributed with the right surface and severity,
your scanner is done: there is no other integration to write.
