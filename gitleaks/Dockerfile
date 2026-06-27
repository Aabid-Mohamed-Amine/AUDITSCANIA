FROM zricethezav/gitleaks:latest AS gitleaks-bin

FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git && \
    rm -rf /var/lib/apt/lists/*

COPY --from=gitleaks-bin /usr/bin/gitleaks /usr/local/bin/gitleaks

WORKDIR /app
COPY requirements.txt .
RUN pip config set global.timeout 300 \
    && pip config set global.retries 5
RUN pip install --no-cache-dir --timeout=300 --retries=5 -r requirements.txt
COPY main.py .

EXPOSE 9008
CMD ["python", "main.py"]
