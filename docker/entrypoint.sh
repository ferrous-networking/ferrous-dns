#!/bin/sh
# ============================================================================
# Ferrous DNS Docker Entrypoint
# ============================================================================

set -e

SHARE_DIR="/usr/local/share/ferrous-dns"

# Bootstrap default config if not present (first run or fresh volume)
if [ ! -f "/data/config/ferrous-dns.toml" ]; then
    echo "No config found at /data/config/ferrous-dns.toml — copying default..."
    mkdir -p /data/config
    cp "$SHARE_DIR/ferrous-dns.toml" /data/config/ferrous-dns.toml
fi

# Bootstrap migrations if not present (first run or fresh volume)
# The app resolves ./migrations relative to WORKDIR (/data)
if [ ! -d "/data/migrations" ]; then
    echo "No migrations found at /data/migrations — copying bundled migrations..."
    cp -r "$SHARE_DIR/migrations" /data/migrations
fi

# Initialize args array
ARGS=""

# Convert ENVs to CLI arguments
# Only pass --config if file exists
if [ -n "$FERROUS_CONFIG" ] && [ -f "$FERROUS_CONFIG" ]; then
    ARGS="$ARGS --config $FERROUS_CONFIG"
fi

if [ -n "$FERROUS_DNS_PORT" ] && [ "$FERROUS_DNS_PORT" != "53" ]; then
    ARGS="$ARGS --dns-port $FERROUS_DNS_PORT"
fi

if [ -n "$FERROUS_WEB_PORT" ] && [ "$FERROUS_WEB_PORT" != "8080" ]; then
    ARGS="$ARGS --web-port $FERROUS_WEB_PORT"
fi

if [ -n "$FERROUS_BIND_ADDRESS" ] && [ "$FERROUS_BIND_ADDRESS" != "0.0.0.0" ]; then
    ARGS="$ARGS --bind $FERROUS_BIND_ADDRESS"
fi

if [ -n "$FERROUS_DATABASE" ] && [ "$FERROUS_DATABASE" != "/data/db/ferrous.db" ]; then
    ARGS="$ARGS --database $FERROUS_DATABASE"
fi

if [ -n "$FERROUS_LOG_LEVEL" ] && [ "$FERROUS_LOG_LEVEL" != "info" ]; then
    ARGS="$ARGS --log-level $FERROUS_LOG_LEVEL"
fi

# Log the command being executed (for debugging)
if [ "$RUST_LOG" = "debug" ] || [ "$RUST_LOG" = "trace" ]; then
    echo "Starting Ferrous DNS with args: $ARGS $*"
fi

# Execute ferrous-dns with constructed args
exec /usr/local/bin/ferrous-dns $ARGS "$@"
