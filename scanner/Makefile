.PHONY: lock install install-dev verify clean

# Generate pinned lockfile with hash verification
# Requires: pip install pip-tools
lock:
	pip-compile \
		--generate-hashes \
		--strip-extras \
		--output-file=requirements.lock \
		requirements.in
	@echo ""
	@echo "requirements.lock generated with pinned versions and hashes."
	@echo "Commit this file to the repo."

# Install from lockfile with hash verification
# This is the secure install path — refuses to install if hashes don't match
install:
	pip install --require-hashes --no-deps -r requirements.lock
	pip install --no-deps -e .
	@echo ""
	@echo "Installed ai-guard with hash-verified dependencies."

# Install for development (includes dev deps, less strict)
install-dev:
	pip install pip-tools
	pip install -e ".[dev]"

# Verify installed packages match lockfile hashes
verify:
	@echo "Checking installed packages against lockfile..."
	@pip install --require-hashes --no-deps -r requirements.lock --dry-run 2>&1 \
		&& echo "All packages match lockfile hashes." \
		|| echo "WARNING: Package mismatch detected!"

# Audit for known vulnerabilities (requires pip-audit)
audit:
	pip-audit -r requirements.lock

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	rm -rf build/ dist/ *.egg-info/
