FROM golang:alpine AS builder
RUN apk add --no-cache git ca-certificates
RUN go install github.com/projectdiscovery/katana/cmd/katana@latest

FROM python:3.12-slim
# chromium for katana headless mode (-hl)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl chromium \
    && rm -rf /var/lib/apt/lists/*

# Tell katana where to find the Chromium binary
ENV CHROME_PATH=/usr/bin/chromium
ENV CHROMIUM_FLAGS="--no-sandbox --disable-dev-shm-usage --disable-gpu"

COPY --from=builder /go/bin/katana /usr/local/bin/katana

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py .

EXPOSE 9009
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:9009/health || exit 1

CMD ["python", "main.py"]
