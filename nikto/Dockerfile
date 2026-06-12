FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    perl \
    make \
    gcc \
    libnet-ssleay-perl \
    libio-socket-ssl-perl \
    liburi-perl \
    libjson-perl \
    libxml-writer-perl \
    cpanminus \
    curl \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN cpanm --notest JSON XML::Writer

RUN curl -fsSL https://github.com/sullo/nikto/archive/refs/heads/master.tar.gz \
    -o /tmp/nikto.tar.gz \
    && tar -xzf /tmp/nikto.tar.gz -C /opt \
    && mv /opt/nikto-* /opt/nikto \
    && rm /tmp/nikto.tar.gz \
    && chmod +x /opt/nikto/program/nikto.pl \
    && ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --timeout=120 -r requirements.txt
COPY server.py .
EXPOSE 9010
CMD ["python", "server.py"]