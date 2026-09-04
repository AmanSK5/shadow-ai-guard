# Local demo

See the platform work with synthetic data in about five minutes. No cluster,
no real estate touched. Everything here is fake: demo users are named after
Pokemon, findings are seeded locally. The portal runs managed mode like a
real deployment; the seeder walks the first-boot path for you - owner
account, estate name, single sign-on - so the first visit is a sign-in
screen with the Microsoft button already on it.

The demo shows both halves of the platform: the detection pipeline landing
in a Grafana dashboard, and the browser paste guard intercepting secrets
before they reach an AI tool.

## Run it

Requires Docker with Compose v2 (`docker compose`, not the legacy
`docker-compose`), and these ports free: **8091** (the portal), 8080 (the
receiver), 3000 (Grafana), 3100 (the log store), 8090 (the paste guard
page), 8025 (the mailbox) and 8092 (the stand-in identity provider).

The portal was missing from that list for a while, which is the worst one to
leave out: the address the instructions send you to is the address that
quietly fails.

From the repository root:

```bash
cd demo
docker compose up
```

Stop and wipe everything:

```bash
docker compose down -v
```

## The portal

Open http://localhost:8091 and press **Sign in with Microsoft**. The
stand-in identity provider offers three people; pick **Gengar**, whose
address the seeder put on the owner account, and you are in. The password
form works too: username `gengar`, password `gengar-demo-portal`.

That account is the estate's owner and break-glass account - the one the
setup code created - so it can do everything, including requiring single
sign-on for everyone else. The seeder claimed the setup code for you
(pinned to `demo-setup-code` on the receiver, demo only, and the receiver
says so in its log); a real deployment reads the random one from the
receiver's log instead. Being signed in unlocks the managed half of the
platform: the setup wizard (`#wizard`), central settings, the fleet view and
enrollment tokens. The estate is named "Pallet Town Ltd"; change it under
Settings > Display & alerting.

Those pages are not empty. The seeder also links three plans under Budget
(ChatGPT Business, Claude Team with a premium tier, Copilot Business) with
member lists chosen so every state the page can show appears: seats nobody
uses, people using a tool with no seat, a personal account running beside a
paid one. And it mints one enrollment token and enrolls three devices
through the real exchange, so Fleet has a roll. Re-running the seeder
(`docker compose run --rm seeder`) refreshes all of it without touching
the estate settings.

After login it lands on a sources view showing which detection sources are
reporting and what each silent one would need. In the demo most are not
reporting - that's what a partly-configured deployment looks like, and the
page exists so you can always tell "not set up" apart from "nothing to
report".

The other tabs are the part Grafana cannot do. Findings are a flat stream of
isolated rows; the portal derives the relationships between them, so a device
page shows every tool seen on that machine across every surface, and a tool
page shows how many devices have it in a browser versus a desktop app versus
a CLI. Those are different exposures and are deliberately not merged.

Nobody is attached to a device until you supply an identity map, and the
portal explains how on the setup page. It proposes one and will not apply it:
the proposals are string matches against local usernames, and a mapping this
platform invented and then acted on is how the wrong name ends up on a report.

The Budget tab is worth trying with the seeded data. Link `fireflies`
(or `chatgpt`), skip the API connection, and import these users when the
card offers it:

```csv
email,role,seat type
squirtle@example.com,member,standard
psyduck@example.com,member,standard
misty@example.com,admin,premium
```

Give the standard tier a couple of seats and a price in the wizard and the
card does the join the page exists for: psyduck shows as a paid seat with
observed use, misty as a paid seat never observed, and squirtle's personal
gmail sign-in surfaces right under the seats being paid for. With a real
Anthropic or Fireflies admin key the user list syncs from the vendor's API
instead of the CSV - the demo has no real org behind it, so the import is
the honest path here.

The portal is never in the ingest path. Stop that one service and
collection carries on, which is a property worth seeing for yourself.

## Email and invites, without a mail server

The stack ships a mailbox. **http://localhost:8025** is Mailpit: it accepts
anything and shows it, and nothing leaves the machine.

In **Settings > Display & alerting > Email**, save:

| Field | Value |
| --- | --- |
| Server | `mailpit` |
| Port | `1025` |
| Security | None (trusted network only) |
| From address | `ai-guard@example.com` |
| Portal address | `http://localhost:8091` |

The card also has a picker - **Microsoft 365, Google Workspace, Amazon SES, or something else** - which fills in the host and port and says what kind of credential that provider wants and where it comes from. Worth reading the Microsoft 365 one even if you use it every day: the username-and-password route is being retired.

Press **Send a test**, then open Mailpit and read it. After that, add an
account under **Settings > Account** and the invite lands in the same place.

Email is optional. With none of it configured, accounts are created exactly
as before and the portal says plainly that nobody was emailed, rather than
refusing to create them - and once a server is saved, one button sends the
invites that were missed.

## Single sign-on, without a tenant

The stack ships a stand-in identity provider, so the sign-on wizard can be
walked without a real Entra tenant, an app registration or a client secret.

It is not a fake button. The receiver runs its ordinary code path against
it - discovery, the authorization request with PKCE, the code exchange, and
every claim check afterwards: issuer, audience, nonce, expiry, tenant. Only
the host answering changes. So what you walk here is the real integration.

The seeder has already switched it on, so the sign-in screen offers the
Microsoft button from the first visit. The stand-in provider offers three
people: `gengar@example.com` is on the owner account and signs in;
`snorlax@example.com` works once you have created a second account with
that address (Settings > Account); `nobody@example.com` exists to show the
refusal a sign-in with no matching account gets.

To walk the wizard yourself, switch single sign-on off under **Settings >
Account > Single sign-on** and choose *Set it up* with:

| Step | Value |
| --- | --- |
| Your tenant | `11111111-2222-3333-4444-555555555555` |
| Application (client) ID | `66666666-7777-8888-9999-000000000000` |
| Client secret | anything non-empty |
| Where sign-ins return | leave the prefilled value |

Then **Test sign-in**, pick an account, and the wizard's last step unlocks.

Once it is on you can also try **Require single sign-on**, which stops
passwords working for every account except the break-glass one - the
account the setup code created. That is what puts a tenant's multi-factor
policy in front of the portal in a real deployment. It is safe to try here:
that account still signs in with its password, which is the whole point of
it.

The **sign-in freshness** setting is on the wizard's last step, and the
receiver's half of it runs here: the stand-in provider issues an `auth_time`
claim like Entra does, and the receiver verifies it rather than assuming its
`max_age` request was honoured.

What the demo cannot show you is the refusal. The stand-in holds no session,
so it always shows the account picker and always reports the sign-in as
having happened just now - every window passes. Watching a stale sign-in get
turned away needs a provider that keeps sessions, which means a real
tenant.

### It is a demo provider, and only that

It signs nothing, it believes any secret it is given, and it will issue a
token for whoever is picked off a list. The receiver refuses to talk to
anything but Microsoft unless `SSO_AUTHORITY_URL` says otherwise in so many
words, and prints a warning naming the host on every boot when it has been
told to. That variable is set here, in this compose file, and belongs
nowhere else.

## The dashboard

Open http://localhost:3000 and look at the "Shadow AI" dashboard. It opens
with no login (anonymous access is on for the demo only).

Personal-versus-work colouring works out of the box: the dashboard's
corporate domains variable ships with the demo's domains
(`example[.]com|example[.]co[.]uk`) as its default, so example.com accounts
show as corporate and gmail.com / outlook.com as personal with no steps.
In a real deployment that same variable is what you point at your own
domains.

## The paste guard

Open http://localhost:8090/demo/ for a stand-in AI prompt box running the
extension's real, unmodified `guard.js`. Paste the test vectors on the page
(all fake or documentation values) and watch it warn or block; the panel
underneath shows the exact report the extension would send, which never
contains what you pasted. Deploying the real extension is covered in
[../extension/README.md](../extension/README.md).

## What is running

Eight containers:

- **loki** - the log store, where findings land
- **receiver** - the real receiver, built from `../receiver`, running
  managed mode and pushing every finding straight to Loki (no scraping
  sidecar needed)
- **portal** - the real portal, built from `../portal`, proxying admin
  actions to the receiver exactly as a deployment does
- **grafana** - pre-provisioned with the Loki datasource and the project
  dashboard, so it is populated on load with nothing to import
- **seeder** - posts a spread of synthetic findings once the receiver is
  healthy, then exits
- **extension-demo** - serves the paste-guard demo page and the real
  `guard.js` it loads
- **entra-mock** - a stand-in identity provider, so federated sign-in can be
  tried without a tenant. Demo only; see the note above
- **mailpit** - a mailbox that accepts anything and shows it at
  http://localhost:8025, so invites can be read rather than assumed

The seed data covers all six surfaces and all three endpoint OSes, with a
mix of personal accounts (which show as warnings) and corporate accounts, so
every panel has something to show.

## Re-seed

The seeder runs once at startup. To post the findings again (for example
after `docker compose down -v`), bring the stack back up, or run just the
seeder against a running stack:

```bash
docker compose run --rm seeder
```

## This is a demo, not a deployment

The demo uses a fixed token (`demo-token`), anonymous Grafana, and no TLS.
None of that is suitable for real use. For an actual deployment see
[../docs/getting-started.md](../docs/getting-started.md).