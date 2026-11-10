FROM nginx:1.25-alpine

# Remove default config
RUN rm /etc/nginx/conf.d/default.conf

# Copy configs
COPY nginx.conf /etc/nginx/nginx.conf
COPY profiles/  /etc/nginx/profiles/
COPY tls/       /etc/nginx/tls/

# Generate a self-signed certificate for the default TLS profile
RUN apk add --no-cache openssl && \
    mkdir -p /etc/nginx/tls/selfsigned && \
    openssl req -x509 -nodes -days 3650 \
        -newkey rsa:2048 \
        -keyout /etc/nginx/tls/selfsigned/key.pem \
        -out    /etc/nginx/tls/selfsigned/cert.pem \
        -subj   "/C=US/ST=Lab/L=Local/O=VulnForge/CN=vulnforge.lab" \
    2>/dev/null

# Placeholder proxy-locations for TLS block
RUN mkdir -p /etc/nginx/conf.d && \
    echo "location / { return 200 '{\"tls\":true}'; add_header Content-Type application/json; }" \
    > /etc/nginx/conf.d/proxy-locations.conf

EXPOSE 8000 8443

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8000/ || exit 1
