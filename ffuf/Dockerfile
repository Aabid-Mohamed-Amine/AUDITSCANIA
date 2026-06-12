FROM golang:1.23-alpine AS builder
RUN apk add --no-cache git ca-certificates
ENV GONOSUMDB=* GOPROXY=direct
RUN go install github.com/ffuf/ffuf/v2@v2.1.0

FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl wget && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /go/bin/ffuf /usr/local/bin/ffuf

RUN mkdir -p /wordlists && \
    wget -q --timeout=30 -O /wordlists/common.txt \
    https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt \
    || echo "Download failed, using built-in wordlist"

COPY wordlist_fallback.txt /wordlists/fallback.txt

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --timeout=120 -r requirements.txt
COPY main.py .

EXPOSE 9006
CMD ["python", "main.py"]
