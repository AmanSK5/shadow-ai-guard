.PHONY: lock

# Regenerate requirements.lock with pinned versions and hashes.
# Requires: pip install pip-tools
lock:
	pip-compile --generate-hashes --strip-extras --output-file=requirements.lock requirements.in
