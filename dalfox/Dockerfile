FROM hahwul/dalfox:latest AS dalfox-bin

FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

COPY --from=dalfox-bin /app/dalfox /usr/local/bin/dalfox

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --timeout=120 -r requirements.txt

COPY main.py .

EXPOSE 9004

CMD ["python", "main.py"]
