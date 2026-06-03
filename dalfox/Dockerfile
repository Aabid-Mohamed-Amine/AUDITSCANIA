# Go 1.26 (Feb 2026) — satisfait dalfox v13 qui exige Go >= 1.25.5
FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git ca-certificates
RUN go install github.com/hahwul/dalfox/v2@latest

FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /go/bin/dalfox /usr/local/bin/dalfox

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

EXPOSE 9004

CMD ["python", "main.py"]
