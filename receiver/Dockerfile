FROM python:3.12-slim

# Debian security updates on top of the base image. The base rebuilds on its
# own schedule, so it lags patched packages: CVE-2026-53615 in util-linux was
# fixed in Debian as 2.41.5-0+deb13u1 while python:3.12-slim still carried
# 2.41-5, and the Trivy gate failed on it in all four images at once.
#
# upgrade rather than pinning the one package. The next lag will be a different
# package, and a list of CVEs somebody has to maintain by hand is a list that
# goes stale between the release that adds it and the one that needed it.
#
# It costs a layer and some build time, and it means two builds of the same
# commit can differ. That is the trade: reproducible-and-vulnerable is not the
# better half of it, and the image tag plus the digest still say exactly what
# shipped.
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /srv
COPY requirements.lock .
RUN pip install --no-cache-dir --require-hashes -r requirements.lock
COPY app/ app/

# The managed-mode state directory, owned by the uid the process runs as.
# Docker initializes a fresh named volume from the image's directory,
# ownership included, so this is what makes `docker compose up` work with
# managed mode on: without it the volume arrives root-owned and the
# receiver dies at boot with "unable to open database file". Kubernetes
# never sees the problem (fsGroup fixes ownership), which is exactly how
# the compose path stayed broken until it became the default.
RUN mkdir -p /var/lib/ai-guard && chown 65532:65532 /var/lib/ai-guard

# Passed by CI from the release tag, or the commit for a build off main. A
# local build leaves it as "dev", which is honest: a hardcoded version drifts,
# and /healthz is the one place an operator looks to answer "am I running what
# I think I am".
ARG APP_VERSION=dev
ENV APP_VERSION=${APP_VERSION}
EXPOSE 8080
USER 65532:65532
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]