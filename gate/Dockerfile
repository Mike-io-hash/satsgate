FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY src/satsgate_gate ./satsgate_gate

EXPOSE 8000

CMD ["uvicorn", "satsgate_gate.app:app", "--host", "0.0.0.0", "--port", "8000"]
