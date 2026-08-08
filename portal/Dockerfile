FROM python:3.12-slim
WORKDIR /srv
COPY requirements.lock .
RUN pip install --no-cache-dir --require-hashes -r requirements.lock
COPY app/ app/

# Passed by CI from the release tag, or the commit for a build off main. A
# local build leaves it as "dev", which is honest: a hardcoded version drifts,
# and /healthz is the one place an operator looks to answer "am I running what
# I think I am".
ARG APP_VERSION=dev
ENV APP_VERSION=${APP_VERSION}
EXPOSE 8091
USER 65532:65532
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8091"]
