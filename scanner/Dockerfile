# ai-guard scanner: cloud-side shadow AI discovery, run daily as a CronJob.
#
# The registry is NOT baked in. It is fetched from the receiver's /registry
# endpoint at runtime (AIGUARD_REGISTRY_URL), so merging a discovery MR
# updates this scanner without a rebuild. The bundled ai_services.yaml ships
# only as an offline fallback.
FROM python:3.14-slim

# tzdata so TZ works if a deployer sets it; default is UTC.
RUN apt-get update \
 && apt-get install -y --no-install-recommends tzdata \
 && rm -rf /var/lib/apt/lists/*
ENV TZ=UTC

WORKDIR /srv

COPY requirements.lock ./
# Hash-verified dependency install first, then the package itself with no
# dependency resolution: the lockfile is the source of truth for what runs.
RUN pip install --no-cache-dir --require-hashes -r requirements.lock
COPY pyproject.toml README.md ./
COPY ai_guard/ ./ai_guard/
RUN pip install --no-cache-dir --no-deps .

COPY receiver_reporter.py entrypoint.py policy.yaml ./

# Non-root, matching the receiver's securityContext.
USER 65532:65532

ENTRYPOINT ["python", "-u", "entrypoint.py"]
