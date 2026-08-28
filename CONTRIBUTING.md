# Contributing

Issues are as welcome as pull requests, and often more useful. A report that
says where the documentation stopped making sense is worth more than a patch,
because the person who wrote the documentation cannot see the gap.

If you have not run this yet, [TESTING.md](TESTING.md) has three routes and
what is worth reporting back.

## Reporting something

Use the [issue forms](https://github.com/AmanSK5/shadow-ai-guard/issues/new/choose).
They ask for the things that usually decide whether something is fixable: the
OS, the command, and the actual output rather than a description of it.

Security vulnerabilities go through a
[private advisory](https://github.com/AmanSK5/shadow-ai-guard/security/advisories/new)
instead of an issue.

## Before you write code

For anything more than a typo, open an issue first. Not for process: for the
chance that the thing you are about to build already exists somewhere in the
repo unwired, or was deliberately left out. Several of the detectors have
exclusions with reasoning next to them, and the registry carries identifiers
that nothing reads yet.

## Running the tests

Every one of these runs in CI on each push, so running them locally saves a
round trip.

```bash
# registry: schema, drift, and the path and approval guards
pip install pyyaml jsonschema pytest
python registry/build.py --check
python -m pytest -q registry/

# receiver
pip install --require-hashes -r receiver/requirements.lock
pytest receiver/ -q

# scanner
pip install --require-hashes -r scanner/requirements.lock
pip install -e scanner/ --no-deps
pytest scanner/tests -q

# shell collectors
shellcheck -S warning endpoint/macos/*.sh endpoint/linux/*.sh

# the Windows collector, on Windows
Invoke-ScriptAnalyzer -Path endpoint/windows/ -Recurse -Severity Warning,Error

# the demo, which CI also runs end to end
cd demo && docker compose up
```

On a current Homebrew or Debian Python the pip installs want a virtualenv:
`python3 -m venv .venv && source .venv/bin/activate` first.

CI also runs the demo, renders the Helm chart, checks the registry shipped in
the chart has not drifted, checks every `requirements.lock` still matches its
`requirements.in`, and tests Windows path containment on a real runner. A
green run means all of that passed, not just the tests above.

## Changing a dependency

Each component has a `requirements.in` for what it asks for and a
`requirements.lock` for what it gets, pinned with hashes. Nothing installs
from the `.in`: CI, the Dockerfiles and the Trivy scans all read the lock. So
editing the `.in` on its own changes what the project claims to depend on
without changing anything it ships.

Edit the `.in`, then regenerate:

```bash
cd receiver   # or scanner, or discovery
make lock         # recompile, keeping versions already pinned
make lock-check   # what CI runs: fails if the committed lock is stale
```

Commit both files in the same commit. `make lock` compiles inside the same
base image the component ships on, because pip-compile bakes in environment
markers from the interpreter running it, so Docker needs to be running.
pip-tools is pinned in the Makefile so the lock you generate and the lock CI
checks come from the same version.

`make lock` keeps existing pins and will not clear a CVE in a transitive
dependency on its own. `make upgrade` moves everything it can, which is a
much larger diff and wants the tests run before committing.

## Adding a tool to the registry

`registry/registry.yaml` is the single source of truth. Everything else is
generated from it by `registry/build.py`, including the scanner's bundled
fallback and the copy inside the Helm chart, so run the build and commit what
it produces.

Two things the schema will reject, both for reasons worth knowing:

- paths that are not relative to the user's home. The collectors run as root
  or SYSTEM and join these to a home directory, so an absolute path or a `..`
  is refused before it can reach a fleet.
- `approved: true`. Sanctioning a tool is a decision for whoever deploys
  this, not for the registry everyone clones.

## Commits

Present tense, and say why rather than what: the diff already says what. The
existing history is the style guide, particularly the commits that explain a
decision that could have gone the other way.

The best of them cite what was actually observed - the finding count that
exposed a throttling bug, the export that would not import. Describe the
observation, not the estate it came from: "a live deployment", and an
asset-tag prefix written as `ASSET-<serial>`. Naming a particular
deployment adds nothing to the reasoning and is not yours to publish.

A commit message is the one thing here that cannot be corrected afterwards
without rewriting history, so there is a hook for it:

    git config core.hooksPath .githooks

Copy `.githooks/deny-list.example.txt` to `deny-list.txt` and add any
shorthand you would not want published. That file is untracked on purpose;
CI reads the same patterns from a repository secret. With neither present
the check passes, so a fork needs no setup.

## The bar for changes

This project's argument is that you can read it and decide for yourself
whether to trust it, which puts weight on a few things:

- **A change that hides a failure is worse than the failure.** Several bugs
  fixed here were recoverable errors that were swallowed, so the recovery
  concealed the cause. If something falls back, it should say so.
- **Comments explain decisions, not syntax.** The useful ones record why the
  obvious approach was not taken, so the next person does not undo it.
- **New collection needs documenting before it ships.** If a change makes the
  platform report something new about a person,
  `docs/deployment-privacy.md` says so in the same pull request.

## Licence

Contributions are under Apache-2.0, the same as the rest of the project. See
[TRADEMARKS.md](TRADEMARKS.md) for the separate question of the project name.