# Stage 1: grab the nuclei binary from the official image
FROM projectdiscovery/nuclei:latest AS nuclei-bin

# Stage 2: lightweight Python runtime + our API wrapper
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Copy nuclei binary
COPY --from=nuclei-bin /usr/local/bin/nuclei /usr/local/bin/nuclei

WORKDIR /app

# Install dependencies inline (no separate requirements.txt needed)
RUN pip install --no-cache-dir fastapi==0.115.0 "uvicorn[standard]==0.30.6"

COPY server.py .
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 9001
ENTRYPOINT ["/entrypoint.sh"]
