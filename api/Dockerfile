FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY api /app/api
COPY agents /app/agents
COPY alerts /app/alerts
COPY ingestion /app/ingestion
COPY storage /app/storage
COPY ml /app/ml

EXPOSE 8088
CMD ["python", "-m", "api.main"]

