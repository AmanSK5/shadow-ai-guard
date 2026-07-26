.PHONY: lock upgrade

# Lockfiles are compiled inside the same base image this component ships on.
# pip-compile bakes environment markers from the interpreter running it, so a
# lock generated on a different Python can resolve differently and fail inside
# the Docker build. Bump this alongside the Dockerfile, never on its own.
PY_IMAGE ?= python:3.12-slim

# Recompile, preserving versions already pinned in requirements.lock.
# Use after editing requirements.in.
lock:
	docker run --rm -v "$$PWD:/w" -w /w $(PY_IMAGE) sh -c \
	  "pip install -q pip-tools && pip-compile --generate-hashes --strip-extras --output-file=requirements.lock requirements.in"

# Recompile, allowing every package to move to its newest compatible version.
# Use when a scan reports a CVE in a transitive dependency: `lock` keeps
# existing pins and will not clear it on its own.
upgrade:
	docker run --rm -v "$$PWD:/w" -w /w $(PY_IMAGE) sh -c \
	  "pip install -q pip-tools && pip-compile --upgrade --generate-hashes --strip-extras --output-file=requirements.lock requirements.in"
