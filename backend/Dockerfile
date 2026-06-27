FROM python:3.11-slim

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (better layer caching)
COPY requirements.txt .
RUN pip config set global.timeout 300 \
    && pip config set global.retries 5
RUN pip install --no-cache-dir --timeout=300 --retries=5 -r requirements.txt

# Copy source (ARG busts cache when code changes without touching apt/pip layers)
ARG CACHEBUST=1
COPY . .

RUN sed -i 's/\r$//' /app/docker-entrypoint.sh && \
    chmod +x /app/docker-entrypoint.sh

# Expose API port
EXPOSE 8000

# Entrypoint runs migrations then starts the process given in CMD
ENTRYPOINT ["/bin/sh", "/app/docker-entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
