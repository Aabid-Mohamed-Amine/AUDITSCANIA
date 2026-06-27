FROM aquasec/trivy:latest AS trivy-binary

FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

COPY --from=trivy-binary /usr/local/bin/trivy /usr/local/bin/trivy

WORKDIR /app

COPY requirements.txt .
RUN pip config set global.timeout 300 \
    && pip config set global.retries 5
RUN pip install --no-cache-dir --timeout=300 --retries=5 -r requirements.txt

COPY main.py .

EXPOSE 9005

CMD ["python", "main.py"]
