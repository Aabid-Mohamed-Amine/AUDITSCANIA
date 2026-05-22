FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install dependencies inline (no separate requirements.txt needed)
RUN pip install --no-cache-dir fastapi==0.115.0 "uvicorn[standard]==0.30.6"

COPY server.py .

EXPOSE 9000
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "9000"]
