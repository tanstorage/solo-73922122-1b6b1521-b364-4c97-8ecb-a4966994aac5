FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PROBE_CONFIG=/config/probes.json \
    ALERT_DB_PATH=/data/alerts.sqlite3 \
    STAGING_DIR=/tmp/probe-alert-staging

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY config /config
COPY examples ./examples

RUN addgroup --system app \
    && adduser --system --ingroup app --no-create-home app \
    && mkdir -p /data \
    && chown -R app:app /app /data /config /tmp

USER app

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
