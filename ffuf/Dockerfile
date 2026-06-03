FROM golang:alpine AS builder
RUN apk add --no-cache git ca-certificates
RUN go install github.com/ffuf/ffuf/v2@latest

FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl wget && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /go/bin/ffuf /usr/local/bin/ffuf

# Wordlist: common web paths (SecLists subset)
RUN mkdir -p /wordlists && \
    wget -q -O /wordlists/common.txt \
    https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt \
    || echo "Download failed, using built-in wordlist"

COPY wordlist_fallback.txt /wordlists/fallback.txt

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py .

EXPOSE 9006
CMD ["python", "main.py"]
