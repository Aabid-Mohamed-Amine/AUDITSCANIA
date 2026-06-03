FROM aquasec/trivy:latest AS trivy-binary

FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

COPY --from=trivy-binary /usr/local/bin/trivy /usr/local/bin/trivy

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

EXPOSE 9005

# Pre-warm Trivy vulnerability DB
RUN trivy image --download-db-only --no-progress 2>/dev/null || true

CMD ["python", "main.py"]
