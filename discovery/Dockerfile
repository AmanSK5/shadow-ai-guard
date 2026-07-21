FROM python:3.12-slim
WORKDIR /srv
COPY requirements.lock .
RUN pip install --no-cache-dir --require-hashes -r requirements.lock
COPY discover.py allowlist.txt ./
USER 65532:65532
CMD ["python", "discover.py"]
