# Browser extension (browser surface)

The browser surface reports visits to known AI tool domains and, where
detectable, the account domain of the signed-in session. Findings arrive at
the receiver with `surface: browser` and the site as the tool
(e.g. `chatgpt.com`), which is why browser findings look slightly different
from collector findings: the extension sees domains, not product names.

## Deployment model

The extension is deployed as a force-installed managed extension through
enterprise browser policy, not from a store listing:

- **Chrome and Edge on Windows**: force-install via Intune administrative
  templates or registry policy (`ExtensionInstallForcelist`), with managed
  storage supplying the receiver URL and token.
- **Chrome and Edge on macOS via Jamf**: each browser needs two
  configuration profile payloads: one for the install domain
  (force-install list) and one for the per-extension managed storage domain
  that carries the receiver URL and token. One payload without the other
  installs an unconfigured extension that reports nothing.

Managed storage keys:

```json
{
  "receiver_url": "https://ai-guard.example.com",
  "token": "the receiver bearer token"
}
```

## Reporting behaviour

The extension flags visits to domains present in the registry's browser
list. It does not capture page content, keystrokes or history; it reports
that a known AI domain was visited on a managed browser profile and, where
the session exposes it, the account domain in use. Domain only, never the
mailbox.

## Note on source

The extension source is not yet included in this repository. Until it is,
the browser surface requires building the extension from the companion
repository or omitting the surface; the rest of the platform functions
without it, minus browser findings.