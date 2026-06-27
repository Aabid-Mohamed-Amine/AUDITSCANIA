# Base: ZAP image from Docker Hub (miroir officiel de ghcr.io/zaproxy/zaproxy:stable)
FROM zaproxy/zap-stable

USER root

# Override base-image ZAP_PORT
# server.py reads ZAP_PORT → we force 8090 so entrypoint.sh and server.py agree.
ENV ZAP_PORT=8090

# Install dependencies inline
# zaproxy/zap-stable (Ubuntu 23.04+, PEP 668 actif) → --break-system-packages requis
RUN pip3 config set global.timeout 300 \
    && pip3 config set global.retries 5
RUN pip3 install --no-cache-dir --break-system-packages --timeout=300 --retries=5 \
    "fastapi==0.110.0" \
    "uvicorn[standard]==0.29.0" \
    "python-owasp-zap-v2.4" \
    "pydantic==2.10.6"

# ZAP baseline always writes reports to /zap/wrk — create it so the mount
# warning disappears and the JSON file is actually written.
RUN mkdir -p /zap/wrk && mkdir -p /home/zap && chmod 777 /home/zap

WORKDIR /app

COPY server.py .
COPY entrypoint.sh .

RUN sed -i 's/\r$//' /app/entrypoint.sh && \
    chmod +x /app/entrypoint.sh

EXPOSE 9002

ENTRYPOINT ["/bin/bash", "/app/entrypoint.sh"]
