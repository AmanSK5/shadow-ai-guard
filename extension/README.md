# Browser extension (browser surface)

The browser surface does two jobs on the pages of known AI tools:

- **Account detection**: resolves the signed-in account, discards the local
  part immediately, and reports the domain if it is not on your corporate
  list. Domain only, never the mailbox.
- **Paste guard**: intercepts paste and drop before the content reaches the
  page, scans it locally for secret patterns and document classification
  markings, and warns or blocks. Reports carry detector ids only; the pasted
  content never leaves the machine.

Findings arrive at the receiver with `surface: browser` and the operating
system the browser is running on. Two sources, because they answer different
questions:

- `browser_extension` - which account is signed into an AI tool. Account flags
  use the site as the tool (e.g. `chatgpt.com`); the receiver resolves that to
  the registry id, so it lands as `chatgpt` alongside every other source.
- `paste_guard` - pastes stopped or flagged, with an `evidence` field of the
  form `paste <warned|blocked|overridden>: <detector ids>`, plus a daily
  heartbeat. The pasted content never leaves the machine.

Both map onto the standard finding schema, so no receiver change is needed.

**Delivery.** The receiver returns 503 when a finding could not be stored,
so a caller can tell "sent" from "kept". Since 1.5.0 the extension acts on
that. An account flag's six-hour dedupe window opens when the report lands,
not when it is attempted, so a refused one is picked up by the next
five-minute check instead of being silenced for the rest of the window. A
paste finding cannot be re-derived - the paste happened once - so a refused
one goes to a bounded queue in `storage.local` (100 events, seven days,
oldest dropped first) and is retried on a ten-minute alarm, at browser
startup and alongside the daily heartbeat, oldest first and stopping at the
first failure. The queue holds the same content-free fields that would have
been POSTed: tool, surface, source, severity, detector ids and the time it
happened. The pasted text is never sent to the service worker, so it cannot
reach the queue either. Protection is unaffected either way - the guard warns
and blocks locally whether or not anything is recorded.

Before 1.2.0, account flags carried no `source` and nothing carried `os`. The
receiver defaulted the missing fields, so the findings looked correct while
being untraceable to a detector: on one fleet that was thousands a week. If
you are running an older build, expect those two fields to start appearing
rather than to change.

## What the paste guard detects

Secret formats (AWS keys, private keys, GitLab/GitHub/Anthropic/OpenAI/
Slack/Google tokens, Azure storage secrets, JWTs), marketing platform
credentials (Stripe live keys, Mailchimp, HubSpot, SendGrid, Meta tokens),
password assignments (`password: ...`), payment card numbers (Luhn
validated), UK National Insurance numbers, IBANs, bulk email lists (10+
distinct addresses in one paste), and document classification markings.

Markings are the interesting one for ISO 27001/42001 shops: the labels come
from managed configuration, so your document classification policy becomes
machine-enforced at the paste boundary. Compound labels ("Client
Confidential") match case-insensitively; bare CONFIDENTIAL only in caps, so
email disclaimer footers stay silent.

Deliberately excluded, because the false-positive rate would teach people to
ignore the overlay: UK sort codes (indistinguishable from dd-mm-yy dates),
dates of birth, passport and driving licence numbers, single email
addresses. The exclusions are documented in `src/guard.js` next to the
detector table.

Detection runs entirely on-device. In `warn` mode the person can proceed
via a "Paste anyway" button (which is itself reported, as `overridden`); in
`block` mode they cannot. The mode is managed configuration, so moving from
warn to block is a policy push, not a release.

## Setup

The extension is not on a web store - you pack it and deploy it yourself
through enterprise browser policy.

**Start in the portal.** The extension setup guide (from the wizard's
extension step, or Settings) walks the whole flow one page at a time, serves
the source pre-configured, generates every policy file, and probes your
hosting. This README is the same material for reading offline, and the
reference for classic mode.

The one-time work, whichever way you drive it:

1. Point the source at your receiver (a one-line manifest edit; the
   portal's download has it done).
2. Pack it, which gives you the extension's id and signing key.
3. Host the packed file and its update manifest anywhere on HTTPS.
   (Firefox: also submit to Mozilla for signing - covered below.)
4. Deploy the policies through your MDM/GPO. The portal generates these
   pre-configured; classic mode uses the templates in `deploy/`.
5. Verify on one machine.

After that, everything day-to-day (mode changes, domain changes, new
enrollment tokens) is a policy push, and releases are pack-upload-done.

In detail, the guided setup serves the source pre-configured
(this repo's `src/`, with the receiver origin already in the manifest - so
none of it needs a checkout), carries the packing instructions from this
README, generates `updates.xml` and `firefox-updates.json` from what you
save, and probes the hosted URLs - including whether the .xpi you hosted
is actually the Mozilla-signed one. The portal also generates the whole
policy matrix pre-configured: the Chromium managed-storage plist for
macOS, the Windows deploy scripts for Chromium and Firefox, and the
Firefox install-and-configure plist for macOS - receiver URL, a fresh
enrollment token per download, your corporate domains, and the paste
guard settings (mode and classification markings, both editable in the
portal) baked in. What the portal cannot derive for you it asks for: the
Chromium id from packing (step 2 below), the Firefox gecko id from the
manifest, and the hosting URLs. Because this extension reads no central
config, changing any of those means regenerating and re-pushing the
policies.

### 1. Customise the source

In `src/manifest.json`, replace `https://ai-guard.example.com/*` in
`host_permissions` with your receiver's origin (keep the `/*`). Without it
the report POST is subject to CORS. Optionally trim the tool list to the
sites you care about (edit `host_permissions` and both `content_scripts`
match lists together), and adjust the fallback allowed domain in
`src/content.js`.

### 2. Pack and derive the identity

In Chrome: `chrome://extensions` -> Developer mode -> Pack extension ->
root directory = `src/`, private key blank on the first pack. You get a
`.crx` and a `.pem`. **The .pem is the signing key: store it in your
password manager and never commit it. Losing it changes the extension id
and forces a full redeployment.**

Derive the id and the public key:

```bash
# the 32-char extension id:
openssl rsa -in src.pem -pubout -outform DER 2>/dev/null \
  | shasum -a 256 | cut -c1-32 | tr '0-9a-f' 'a-p'

# the manifest "key" value:
openssl rsa -in src.pem -pubout -outform DER 2>/dev/null | openssl base64 -A; echo
```

Add a top-level `"key": "<base64 value>"` to `src/manifest.json` and pack
again, this time supplying the .pem. Pinning the key keeps the id stable
across dev loads and repacks. Rename the output to a versioned name, e.g.
`ai-guard-1.0.0.crx`.

### 3. Host the artifacts

Put the versioned .crx and updates.xml (from `updates.xml.template`, with
your id and URLs filled in) on public HTTPS. An S3 bucket works; grant
public read with a wildcard resource (`arn:aws:s3:::your-bucket/*`), not
per-object, or every new release starts life private. Verify both URLs
return 200 before deploying policy.

For Firefox, the signed .xpi and `firefox-updates.json` (from
`firefox-updates.json.template`) go in the same place. Firefox and Chromium
use different update formats and do not share one, so a release that touches
both browsers updates two manifests. Use the right content types:
`application/x-chrome-extension` for the .crx and `application/x-xpinstall`
for the .xpi.

### 4. Deploy on macOS (MDM)

`deploy/macos/<browser>/` has two plists per Chromium browser. Both are
needed; one without the other installs an unconfigured extension that reports
nothing. Firefox is one plist, covered separately below.

- `install.plist` under the browser's preference domain (`com.google.Chrome`,
  `com.brave.Browser`, `com.microsoft.Edge`): the forcelist entry pointing
  at your updates.xml, plus an `ExtensionSettings` entry with
  `override_update_url`. Both are needed: the forcelist installs, but on
  its own it does not reliably update self-hosted extensions afterwards;
  the `ExtensionSettings` entry is what makes the browser keep polling
  your updates.xml for new versions.
- `managed-storage.plist` under the per-extension domain
  (`<browser domain>.extensions.<your id>`): the runtime configuration.

On Jamf these are two "Application & Custom Settings" payloads in one
configuration profile per browser. `$SERIALNUMBER` in the config plist is
substituted per machine by Jamf; other MDMs have equivalents.

Verify delivery on a test machine before opening the browser:

```bash
defaults read "/Library/Managed Preferences/com.google.Chrome.extensions.<id>"
```

#### Firefox

Firefox needs the extension signed by Mozilla and takes a different shape of
policy, so it is a separate path rather than a fourth browser domain.

**Signing.** Firefox refuses unsigned extensions on release builds, and there
is no enterprise policy that changes that. Disabling `xpinstall.signatures.
required` only works on ESR, Developer Edition and Nightly, and it turns off
integrity checking for every extension a user installs, not just yours.
Instead, submit to addons.mozilla.org as a **self-distributed** add-on: pick
"On your own site" at submission. Mozilla signs it and it never appears in the
public directory. Signing is automated and usually takes minutes.

```bash
cd extension/src
zip -r -FS ../ai-guard-1.0.0.xpi \
  manifest.json background.js content.js guard.js managed-schema.json
```

Name the files explicitly rather than using `*`: an .xpi is a zip of the files
themselves, not of the `src` folder, and `README.md` should not ship in it.

The file you deploy is the **signed** one AMO returns, not the one you built.
A signed .xpi contains `META-INF/mozilla.rsa`:

```bash
unzip -l ai-guard-1.0.0.xpi | grep META-INF
```

**Policy.** `deploy/macos/firefox/managed-storage.plist` is one payload under
`org.mozilla.firefox`, because Firefox reads the install policy and the managed
config from the same domain. Two things differ from the Chromium payloads:
it uses `install_url` rather than `update_url`, since Firefox installs from the
.xpi and then polls the manifest's own `update_url`; and managed storage lives
under `3rdparty` > `Extensions` > the **gecko id**, not the Chrome 32-character
id.

Verify with `about:policies` on the target machine, which shows the resolved
values including whatever your MDM substituted for the device identifier.

### 5. Deploy on Windows

Two Intune platform scripts, for the same reason macOS needs two shapes of
payload. `deploy/windows/Deploy-AiGuardExtension.ps1` covers Chrome, Edge and
Brave: forcelist, `ExtensionSettings` with `override_update_url`, and the
managed config. `Deploy-AiGuardExtensionFirefox.ps1` covers Firefox, which
shares almost nothing with them: it installs the Mozilla-signed `.xpi` from
`install_url` rather than polling an update manifest, keys managed storage on
the gecko id rather than the 32 character Chrome id, and stores its whole
policy as JSON in single registry values rather than as individual ones. The
Firefox script reads those values before writing, because one value holds every
extension's configuration and overwriting it would silently remove somebody
else's.

The `.reg` files alongside are the Chromium policy in registry form, for GPO or
an RMM.

A script rather than an Intune ADMX policy, for two reasons. The managed
config lives under `3rdparty\extensions\<id>\policy`, which is arbitrary
registry defined by the extension's own managed schema rather than a Chrome
policy, so no ADMX setting covers it. And the device identifier has to be read
from the machine: `%COMPUTERNAME%` in a `.reg` file is a literal string to
Chrome, and even expanded it would be the hostname, where every other source
keys a device on its hardware serial.

The script reads the BIOS serial and rejects the placeholder values OEMs ship
in that field. That matters more than it sounds: a hostname splits one machine
into two on a view that groups by device, but fifty machines all reporting
`To Be Filled By O.E.M.` collapse into one and the other forty nine vanish
from every count.

In Intune, set **Run this script using the logged on credentials** to No,
because every key is under HKLM, and **Run script in 64 bit PowerShell Host**
to Yes.



`deploy/windows/<browser>/` has the equivalent registry blueprints:
`install.reg` (forcelist) and `managed-storage.reg` (the
`3rdparty\extensions\<id>\policy` key; list values are JSON strings).
Deliver via GPO, Intune, or your RMM. `%COMPUTERNAME%` in the blueprint is
a placeholder: substitute your device identifier at deployment time, since
.reg files do not expand environment variables.

### 6. Verify end to end

`chrome://policy` on a deployed machine shows the managed values once the
extension is installed (it only lists keys the installed version's schema
declares). Then paste a harmless test vector on a covered site, e.g.
Amazon's documented example key `AKIAIOSFODNN7EXAMPLE`: expect the overlay,
and a finding at your receiver with `source: paste_guard` and no pasted
content anywhere in it.

## Managed storage keys

| Key | Type | Purpose |
| --- | --- | --- |
| `allowedDomains` | array | Account domains not flagged (your corporate domains) |
| `reportEndpoint` | string | Receiver URL for finding POSTs |
| `authToken` | string | Bearer token (write-mostly credential: it can submit findings and read the registry, nothing else). The receiver's shared `AUTH_TOKEN`, or an enrollment token (`aige_...`) from a managed-mode receiver - see below |
| `deviceIdentifier` | string | Device attribution value stamped by the MDM |
| `pasteGuardMode` | string | `off`, `warn`, or `block`; unset behaves as `warn` |
| `classificationMarkings` | array | Labels from your document classification policy |

## Enrolling with a managed-mode receiver

With a receiver running in managed mode, `authToken` can carry an
**enrollment token** (`aige_...`, minted in the portal or via `/admin`)
instead of the shared token. The prefix is the switch - no other key
changes, and the same policy value works for both. Each browser profile then:

1. On its first report, POSTs `/enroll` (derived from `reportEndpoint` by
   dropping the trailing `/report`) with `platform: browser` and a serial of
   `<deviceIdentifier>/<install id>` - the install id is eight hex characters
   made once per profile, because one machine legitimately runs several
   managed profiles (Chrome and Edge, two Chrome profiles) and they must not
   displace each other on the receiver.
2. Keeps the credential it receives in the extension's `storage.local` and
   reports with it from then on, sending its version in
   `X-AiGuard-Agent-Version`. The profile appears in the portal's Fleet view
   as platform `browser`.
3. If the receiver refuses that credential (revoked in the Fleet view), the
   profile goes quiet and says so in the service worker console; the hourly
   heartbeat retry keeps checking. It re-enrolls **only when the policy
   carries a different enrollment token** than the one its credential last
   reported under (a rotation while the credential still worked is recorded
   as such, so only a rotation *after* the revoke counts). Revoking a profile
   therefore sticks until you rotate the token - the browser analogue of
   deleting a collector's `device.cred` - and rotating it is also how an
   accidental revoke is undone.

A profile whose extension storage is wiped (reinstall, profile reset) makes
a new install id and appears as a new row; the old row stays, with its last
seen time, until you revoke it. The receiver knows the two belong to one
machine only by the shared device identifier prefix.

The shared token keeps working alongside, which is the migration path: flip
the policy value per browser, per platform, at your own pace.

## Rollout advice

Ship in `warn` mode for a couple of weeks and watch two numbers: false
positives (should be near zero with this detector set; the password and
bulk-email detectors are the likeliest sources) and the `overridden` count,
which is a policy conversation, not a config value. Flipping to `block` is
then a managed-storage change. Tell people before it activates: what it
detects, that detection is on-device, and that content never leaves the
machine. A control people understand gets accepted; one they discover gets
resented.

## Releasing updates

Bump the version in `src/manifest.json`, pack with the same .pem, upload
the new versioned .crx, update `codebase` and `version` in the hosted
updates.xml. Keep the previous .crx in the bucket: re-pointing updates.xml
at it is your rollback.

Two things make updates actually arrive, and both are already in the
blueprints. First, the `ExtensionSettings` policy entry with
`override_update_url`: without it, browsers install from the forcelist and
then never reliably poll a self-hosted updates.xml again. This is
long-standing browser behaviour, not a configuration mistake, and it costs
an evening to discover the hard way. Second, the extension's daily
heartbeat calls `chrome.runtime.requestUpdateCheck()`, so running browsers
ask for their own update within a day of a release instead of waiting for
a restart. With both in place, a release is: pack, upload, update the xml,
and watch it propagate.

## Known limitations

Clipboard images and file uploads are out of scope for the text guard.
Typed (not pasted) secrets are not scanned. A determined person can evade
a client-side control; this is a seatbelt against accidents, which is what
nearly all real incidents are, and the findings pipeline is what catches
deliberate patterns. Account resolvers hit vendor DOM/endpoints that change
without notice; each resolver in `src/content.js` documents what to
re-verify.