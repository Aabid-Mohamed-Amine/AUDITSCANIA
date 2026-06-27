FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates \
    libxml2-dev libxslt-dev \
    build-essential gcc \
    libssl-dev libffi-dev \
    python3-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip config set global.timeout 300 \
    && pip config set global.retries 5
RUN pip install --no-cache-dir --timeout=300 --retries=5 -r requirements.txt
COPY server.py .

EXPOSE 9011
CMD ["python", "server.py"]
