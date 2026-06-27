FROM golang:1.23-alpine AS builder

RUN apk update && apk add --no-cache git ca-certificates

ENV GOPROXY=https://proxy.golang.org,direct
ENV GOSUMDB=sum.golang.org
ENV CGO_ENABLED=0
ENV GIT_TERMINAL_PROMPT=0

RUN go install github.com/ffuf/ffuf/v2@latest

FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /go/bin/ffuf /usr/local/bin/ffuf

RUN mkdir -p /wordlists

COPY wordlist_fallback.txt /wordlists/fallback.txt

WORKDIR /app

COPY requirements.txt .

RUN pip config set global.timeout 300 \
    && pip config set global.retries 5
RUN pip install --no-cache-dir --timeout=300 --retries=5 -r requirements.txt

COPY main.py .

EXPOSE 9006

CMD ["python", "main.py"]