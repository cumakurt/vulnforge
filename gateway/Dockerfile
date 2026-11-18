FROM nginx:1.25-alpine

# Remove default config
RUN rm /etc/nginx/conf.d/default.conf

# Copy configs
COPY gateway/nginx.conf /etc/nginx/nginx.conf
COPY gateway/profiles/  /etc/nginx/profiles/
COPY gateway/tls/       /etc/nginx/tls/

# Generate a self-signed certificate for the default TLS profile
RUN apk add --no-cache openssl bash python3 py3-pip && \
    mkdir -p /etc/nginx/tls/selfsigned && \
    openssl req -x509 -nodes -days 3650 \
        -newkey rsa:2048 \
        -keyout /etc/nginx/tls/selfsigned/key.pem \
        -out    /etc/nginx/tls/selfsigned/cert.pem \
        -subj   "/C=US/ST=Lab/L=Local/O=VulnForge/CN=vulnforge.lab" \
    2>/dev/null

WORKDIR /app/shopforge
COPY services/shopforge/requirements.txt .
RUN python3 -m venv /opt/shopforge && \
    /opt/shopforge/bin/pip install --no-cache-dir -r requirements.txt
COPY services/shopforge/main.py services/shopforge/catalog.json ./
COPY services/shopforge/src/ ./src/
COPY gateway/start.sh /usr/local/bin/start-gateway

ENV PYTHONUNBUFFERED=1

# Placeholder proxy-locations for TLS block
RUN mkdir -p /etc/nginx/conf.d && \
    echo "location / { return 200 '{\"tls\":true}'; add_header Content-Type application/json; }" \
    > /etc/nginx/conf.d/proxy-locations.conf

EXPOSE 8000 8443
STOPSIGNAL SIGTERM

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8000/ || exit 1

CMD ["bash", "/usr/local/bin/start-gateway"]
