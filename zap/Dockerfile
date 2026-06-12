# Base: official ZAP image (Ubuntu + Java + ZAP + Python3)
FROM ghcr.io/zaproxy/zaproxy:stable

USER root

# Override base-image ZAP_PORT (zaproxy:stable sets ZAP_PORT=8080 by default).
# server.py reads ZAP_PORT → we force 8090 so entrypoint.sh and server.py agree.
ENV ZAP_PORT=8090

# Install dependencies inline (no separate requirements.txt needed)
RUN pip install --no-cache-dir --break-system-packages \
    "fastapi==0.110.0" \
    "uvicorn[standard]==0.29.0" \
    "python-owasp-zap-v2.4"

# ZAP baseline always writes reports to /zap/wrk — create it so the mount
# warning disappears and the JSON file is actually written.
RUN mkdir -p /zap/wrk && mkdir -p /home/zap && chmod 777 /home/zap

WORKDIR /app
COPY server.py .
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

EXPOSE 9002
ENTRYPOINT ["/app/entrypoint.sh"]
