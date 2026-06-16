FROM golang:1.25-bookworm AS katana-build
RUN go install github.com/projectdiscovery/katana/cmd/katana@latest


FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl chromium \
    && rm -rf /var/lib/apt/lists/*

ENV CHROME_PATH=/usr/bin/chromium
ENV CHROMIUM_FLAGS="--no-sandbox --disable-dev-shm-usage --disable-gpu"

# LA CORRECTION EST ICI : on copie depuis /bin/katana et on le rend exécutable
COPY --from=katana-build /go/bin/katana /usr/local/bin/katana
RUN chmod +x /usr/local/bin/katana

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --timeout=120 -r requirements.txt
COPY main.py .

EXPOSE 9009
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:9009/health || exit 1

CMD ["python", "main.py"]
