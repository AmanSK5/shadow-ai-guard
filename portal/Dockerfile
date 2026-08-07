FROM python:3.12-slim
WORKDIR /srv
COPY requirements.lock .
RUN pip install --no-cache-dir --require-hashes -r requirements.lock
COPY app/ app/
EXPOSE 8091
USER 65532:65532
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8091"]
