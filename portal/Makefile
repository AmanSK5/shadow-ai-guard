.PHONY: lock upgrade lock-check

# Lockfiles are compiled inside the same base image this component ships on.
# pip-compile bakes environment markers from the interpreter running it, so a
# lock generated on a different Python can resolve differently and fail inside
# the Docker build. Bump this alongside the Dockerfile, never on its own.
PY_IMAGE ?= python:3.12-slim

# pip-tools is pinned because CI recompiles the lock and fails if it moves.
# An unpinned pip-tools means the version that generated the committed lock
# and the version CI checks it with can differ, and the job then fails for a
# reason that has nothing to do with the change under review. A check that
# fails at random gets ignored, then disabled. Bump this deliberately and
# regenerate all three components in the same commit.
PIP_TOOLS_VERSION ?= 7.6.0

# Recompile, preserving versions already pinned in requirements.lock.
# Use after editing requirements.in.
lock:
	docker run --rm -v "$$PWD:/w" -w /w $(PY_IMAGE) sh -c \
	  "pip install -q pip-tools==$(PIP_TOOLS_VERSION) && pip-compile --generate-hashes --strip-extras --output-file=requirements.lock requirements.in"

# Recompile, allowing every package to move to its newest compatible version.
# Use when a scan reports a CVE in a transitive dependency: `lock` keeps
# existing pins and will not clear it on its own.
upgrade:
	docker run --rm -v "$$PWD:/w" -w /w $(PY_IMAGE) sh -c \
	  "pip install -q pip-tools==$(PIP_TOOLS_VERSION) && pip-compile --upgrade --generate-hashes --strip-extras --output-file=requirements.lock requirements.in"

# Fail if requirements.lock is not what requirements.in currently compiles to.
# Nothing installs from requirements.in: CI, the Dockerfile and Trivy all read
# the lock. So an edit to the .in alone changes nothing and still goes green.
# This is what CI runs. Run it locally before pushing to save a round trip.
lock-check: lock
	@git diff --exit-code requirements.lock \
	  || { echo ""; echo "requirements.lock is stale. Run 'make lock' in this directory and commit the result."; exit 1; }