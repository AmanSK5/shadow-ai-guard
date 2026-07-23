# Browser extension (browser surface)

The browser surface does two jobs on the pages of known AI tools:

- **Account detection**: resolves the signed-in account, discards the local
  part immediately, and reports the domain if it is not on your corporate
  list. Domain only, never the mailbox.
- **Paste guard**: intercepts paste and drop before the content reaches the
  page, scans it locally for secret patterns and document classification
  markings, and warns or blocks. Reports carry detector ids only; the pasted
  content never leaves the machine.

Findings arrive at the receiver with `surface: browser`. Account flags use
the site as the tool (e.g. `chatgpt.com`); paste-guard events additionally
carry `source: paste_guard` and an `evidence` field of the form
`paste <warned|blocked|overridden>: <detector ids>`. No receiver change is
needed: both map onto the standard finding schema.

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

The extension is deployed as a force-installed managed extension through
enterprise browser policy, not from a store listing. The moving parts:
packed extension (.crx) and an update manifest (updates.xml) on public
HTTPS, plus two policies per browser delivered by your MDM or GPO: an
install policy (forcelist) and a managed-storage config.

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

### 4. Deploy on macOS (MDM)

`deploy/macos/<browser>/` has two plists per browser. Both are needed; one
without the other installs an unconfigured extension that reports nothing.

- `install.plist` under the browser's preference domain (`com.google.Chrome`,
  `com.brave.Browser`, `com.microsoft.Edge`): the forcelist entry pointing
  at your updates.xml.
- `managed-storage.plist` under the per-extension domain
  (`<browser domain>.extensions.<your id>`): the runtime configuration.

On Jamf these are two "Application & Custom Settings" payloads in one
configuration profile per browser. `$SERIALNUMBER` in the config plist is
substituted per machine by Jamf; other MDMs have equivalents.

Verify delivery on a test machine before opening the browser:

```bash
defaults read "/Library/Managed Preferences/com.google.Chrome.extensions.<id>"
```

### 5. Deploy on Windows

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
| `authToken` | string | Bearer token (write-only credential: it can submit findings, not read them) |
| `deviceIdentifier` | string | Device attribution value stamped by the MDM |
| `pasteGuardMode` | string | `off`, `warn`, or `block`; unset behaves as `warn` |
| `classificationMarkings` | array | Labels from your document classification policy |

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
updates.xml. Browsers pick it up on their update poll. Keep the previous
.crx in the bucket: re-pointing updates.xml at it is your rollback.

## Known limitations

Clipboard images and file uploads are out of scope for the text guard.
Typed (not pasted) secrets are not scanned. A determined person can evade
a client-side control; this is a seatbelt against accidents, which is what
nearly all real incidents are, and the findings pipeline is what catches
deliberate patterns. Account resolvers hit vendor DOM/endpoints that change
without notice; each resolver in `src/content.js` documents what to
re-verify.
