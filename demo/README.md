# Local demo

See the platform work with synthetic data in about five minutes. No cluster,
no real estate touched. Everything here is fake: demo users are named after
Pokemon, findings are seeded locally. The only credential involved is the
one the demo itself mints: the portal runs managed mode like a real
deployment, so the first visit walks the real first-boot path.

The demo shows both halves of the platform: the detection pipeline landing
in a Grafana dashboard, and the browser paste guard intercepting secrets
before they reach an AI tool.

## Run it

Requires Docker with Compose v2 (`docker compose`, not the legacy
`docker-compose`), and ports 3000, 8080, 3100 and 8090 free.

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

Open http://localhost:8091. It asks you to create the admin account - the
receiver printed a one-time setup code to its log when it started:

```bash
docker compose logs receiver | grep setup_code
```

On Windows, swap `grep` for `findstr` - it is built into both PowerShell
and cmd.

Paste the code, pick a username and password, and you are in - the same
first-boot flow as a real deployment, which is why the demo does not skip
it. Being signed in unlocks the managed half of the platform: the setup
wizard (the portal offers it, or go to `#wizard`), central settings, the
fleet view and enrollment tokens.

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

In **Settings > Account > Single sign-on**, choose *Set it up* and use:

| Step | Value |
| --- | --- |
| Your tenant | `11111111-2222-3333-4444-555555555555` |
| Application (client) ID | `66666666-7777-8888-9999-000000000000` |
| Client secret | anything non-empty |
| Where sign-ins return | leave the prefilled value |

Before that, the wizard's first step asks for an email address on your own
account. Use `gengar@example.com` - the stand-in provider offers three
people to sign in as, and that is the one it matches. `snorlax@example.com`
works too if you have created a second account with that address, and
`nobody@example.com` exists to show the refusal a sign-in with no matching
account gets.

Then **Test sign-in**, pick an account, and the wizard's last step unlocks.

Once it is on you can also try **Require single sign-on**, which stops
passwords working for every account except the break-glass one - the
account the setup code created. That is what puts a tenant's multi-factor
policy in front of the portal in a real deployment.

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