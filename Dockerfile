FROM python:3.12-slim

# System deps for paramiko (SSH)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl-dev gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./backend/
COPY frontend/ ./frontend/

# Persistent data volume
RUN mkdir -p /data
VOLUME ["/data"]

ENV DB_PATH=/data/homelab.db
ENV PYTHONUNBUFFERED=1

EXPOSE 8080

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8080"]
