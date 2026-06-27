FROM python:3.12-slim

# 1. Nettoyage et installation des dépendances (On ajoute libjson-perl et libxml-writer-perl ici)
RUN rm -rf /var/lib/apt/lists/* && \
    apt-get clean && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
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

# 2. On force cpanm à utiliser exclusivement HTTPS pour les miroirs restants, au cas où
RUN cpanm --mirror https://cpan.metacpan.org/ --notest JSON XML::Writer

# 3. Téléchargement et installation de Nikto
RUN curl -fsSL https://github.com/sullo/nikto/archive/refs/heads/master.tar.gz \
    -o /tmp/nikto.tar.gz \
    && tar -xzf /tmp/nikto.tar.gz -C /opt \
    && mv /opt/nikto-* /opt/nikto \
    && rm /tmp/nikto.tar.gz \
    && chmod +x /opt/nikto/program/nikto.pl \
    && ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto

WORKDIR /app

# 4. Configuration robuste de pip pour éviter les coupures 4G/5G
COPY requirements.txt .
RUN pip config set global.timeout 300 \
    && pip config set global.retries 5
RUN pip install --no-cache-dir --timeout=300 --retries=5 -r requirements.txt

COPY server.py .

EXPOSE 9010
CMD ["python", "server.py"]