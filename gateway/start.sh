#!/usr/bin/env bash
set -eu

/opt/shopforge/bin/uvicorn main:app --host 127.0.0.1 --port 3100 &
portal_pid=$!

nginx -g 'daemon off;' &
nginx_pid=$!

stop_services() {
    kill -QUIT "$nginx_pid" 2>/dev/null || true
    kill -TERM "$portal_pid" 2>/dev/null || true
    wait "$nginx_pid" "$portal_pid" 2>/dev/null || true
}

trap 'stop_services; exit 0' TERM INT

wait -n "$nginx_pid" "$portal_pid" || true
stop_services
exit 1
