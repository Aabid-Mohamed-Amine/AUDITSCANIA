# Base: official ZAP image (Ubuntu + Java + ZAP + Python3)
FROM ghcr.io/zaproxy/zaproxy:stable

USER root

# Install dependencies inline (no separate requirements.txt needed)
RUN pip install --no-cache-dir --break-system-packages fastapi==0.115.0 "uvicorn[standard]==0.30.6"

# ZAP baseline always writes reports to /zap/wrk — create it so the mount
# warning disappears and the JSON file is actually written.
RUN mkdir -p /zap/wrk && mkdir -p /home/zap && chmod 777 /home/zap

WORKDIR /app
COPY server.py .

EXPOSE 9002
ENTRYPOINT ["python", "-m", "uvicorn", "server:app", "--host", "0.0.0.0", "--port", "9002"]
