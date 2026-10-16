FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

EXPOSE 8000

# Trust forwarded headers only from the configured proxy (Compose pins Caddy).
# Do not use "*" — any client could spoof X-Forwarded-For.
ENV SATSGATE_FORWARDED_ALLOW_IPS=172.28.0.2
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --proxy-headers --forwarded-allow-ips \"${SATSGATE_FORWARDED_ALLOW_IPS}\""]
