FROM php:8.1-apache

# Install extensions
RUN apt-get update && apt-get install -y \
    curl \
    libpng-dev \
    libzip-dev \
    unzip \
    default-mysql-client \
    && docker-php-ext-install mysqli pdo pdo_mysql zip gd \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Enable Apache mod_rewrite
RUN a2enmod rewrite headers

# Copy source
COPY src/ /var/www/html/
COPY db/ /var/www/db/
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Apache config
RUN echo '<Directory /var/www/html>\n    AllowOverride All\n    Options Indexes FollowSymLinks\n    Require all granted\n</Directory>' \
    > /etc/apache2/conf-available/vulnforge.conf \
    && a2enconf vulnforge

# Expose internal server info (intentional misconfiguration)
RUN echo "ServerTokens Full" >> /etc/apache2/apache2.conf && \
    echo "ServerSignature On" >> /etc/apache2/apache2.conf

EXPOSE 80

HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=5 \
  CMD curl -fs http://127.0.0.1/health.php || exit 1

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["apache2-foreground"]
