FROM python:3.11-slim

ARG NUCLEI_VERSION=3.3.8

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates unzip \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fSL --retry 5 --retry-delay 3 \
       "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
       -o /tmp/nuclei.zip \
    && unzip /tmp/nuclei.zip nuclei -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip

WORKDIR /app

RUN pip config set global.timeout 300 \
    && pip config set global.retries 5
RUN pip install --no-cache-dir --timeout=300 --retries=5 \
    fastapi==0.115.0 "uvicorn[standard]==0.30.6" httpx==0.27.0 pydantic==2.10.6

COPY server.py .
COPY entrypoint.sh /entrypoint.sh

RUN sed -i 's/\r$//' /entrypoint.sh && \
    chmod +x /entrypoint.sh

# Download nuclei-templates at build time so CI doesn't need local copies
RUN nuclei -update-templates -silent 2>/dev/null && \
    echo "[nuclei-build] Templates baked: $(find /root/nuclei-templates -name '*.yaml' | wc -l) yaml files" || \
    echo "[nuclei-build] Template download skipped (no network during build)"

EXPOSE 9001

ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
