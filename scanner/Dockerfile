# ai-guard scanner: cloud-side shadow AI discovery, run daily as a CronJob.
#
# The registry is NOT baked in. It is fetched from the receiver's /registry
# endpoint at runtime (AIGUARD_REGISTRY_URL), so merging a discovery MR
# updates this scanner without a rebuild. The bundled ai_services.yaml ships
# only as an offline fallback.
FROM python:3.12-slim

# tzdata so TZ works if a deployer sets it; default is UTC.
#
# upgrade in the same layer for Debian security updates. The base image
# rebuilds on its own schedule and so lags patched packages: CVE-2026-53615 in
# util-linux was fixed in Debian as 2.41.5-0+deb13u1 while python:3.12-slim
# still carried 2.41-5, and the Trivy gate failed on it in all four images.
#
# upgrade rather than pinning the one package, because the next lag will be a
# different package and a hand-maintained CVE list goes stale between the
# release that adds it and the one that needed it.
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && apt-get install -y --no-install-recommends tzdata \
 && rm -rf /var/lib/apt/lists/*
ENV TZ=UTC

WORKDIR /srv

COPY requirements.lock ./
# Hash-verified dependency install first, then the package itself with no
# dependency resolution: the lockfile is the source of truth for what runs.
# This is also what makes the amd64 and arm64 builds work from one lockfile:
# pip-compile --generate-hashes records every distribution for a version, so
# the aarch64 wheels are already covered. Regenerate with `make upgrade`,
# which compiles inside this same base image.
RUN pip install --no-cache-dir --require-hashes -r requirements.lock
COPY pyproject.toml README.md ./
COPY ai_guard/ ./ai_guard/
RUN pip install --no-cache-dir --no-deps .

COPY receiver_reporter.py entrypoint.py policy.yaml ./

# Non-root, matching the receiver's securityContext.
USER 65532:65532

ENTRYPOINT ["python", "-u", "entrypoint.py"]