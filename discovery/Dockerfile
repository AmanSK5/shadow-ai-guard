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
COPY discover.py schedule.py allowlist.txt ./
USER 65532:65532

# See the scanner's Dockerfile: this reports on the last successful pass, and
# only means anything when AIGUARD_RUN_INTERVAL keeps the container alive. The
# start period is longer here because a first pass pulls seven days of DNS
# events and then classifies the residue.
HEALTHCHECK --interval=60s --timeout=10s --start-period=20m --retries=2 \
  CMD ["python", "discover.py", "--health"]

CMD ["python", "-u", "discover.py"]