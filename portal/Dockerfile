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
# Verified copies of the endpoint collector scripts, for artifact downloads.
# The build context is portal/, so the endpoint/ tree is out of reach; a test
# asserts these are byte-identical to the sources, the same pattern as the
# chart's bundled registry.
COPY collector-scripts/ collector-scripts/
# Verified copies of extension/src, same reasoning: the extension-source
# download serves these with the receiver origin substituted in.
COPY extension-src/ extension-src/

# Passed by CI from the release tag, or the commit for a build off main. A
# local build leaves it as "dev", which is honest: a hardcoded version drifts,
# and /healthz is the one place an operator looks to answer "am I running what
# I think I am".
ARG APP_VERSION=dev
ENV APP_VERSION=${APP_VERSION}
EXPOSE 8091
USER 65532:65532
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8091"]