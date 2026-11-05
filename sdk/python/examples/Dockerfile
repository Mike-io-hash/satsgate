FROM python:3.12-slim
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir /app uvicorn
ENV PYTHONPATH=/app/examples
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "receipt_seller:app", "--host", "0.0.0.0", "--port", "8000", "--app-dir", "/app/examples"]
