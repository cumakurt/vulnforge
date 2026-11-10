#!/bin/bash
set -e

echo "[vulnforge] Waiting for MySQL..."
until mysql --skip-ssl -h"$MYSQL_HOST" -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE" -e "SELECT 1" &>/dev/null; do
  sleep 2
done
echo "[vulnforge] MySQL ready."

# The upload module intentionally writes into the document root.
mkdir -p /var/www/html/uploads
chmod 0777 /var/www/html/uploads

exec "$@"
