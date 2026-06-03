# Utilise les images officielles ProjectDiscovery — pas de compilation Go nécessaire
FROM projectdiscovery/subfinder:latest AS subfinder-bin
FROM projectdiscovery/httpx:latest AS httpx-bin

FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

COPY --from=subfinder-bin /usr/local/bin/subfinder /usr/local/bin/subfinder
COPY --from=httpx-bin     /usr/local/bin/httpx     /usr/local/bin/httpx

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

EXPOSE 9003

CMD ["python", "main.py"]
