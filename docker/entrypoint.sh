#!/bin/sh
# ============================================================================
# Ferrous DNS Docker Entrypoint
# ============================================================================

set -e

SHARE_DIR="/usr/local/share/ferrous-dns"
CONFIG_PATH="/data/config/ferrous-dns.toml"
RUN_AS="uid $(id -u), gid $(id -g)"

# Docker creates the source of a bind mount as a root-owned *directory* when the
# host path does not exist yet, so the config path can be a directory that only
# looks like a missing file. Copying into it would land the default at
# .../ferrous-dns.toml/ferrous-dns.toml, or fail outright as the non-root user.
if [ -d "$CONFIG_PATH" ]; then
    echo "ERROR: $CONFIG_PATH is a directory, not a file." >&2
    echo "       Docker created it because the host path of a bind mount did not exist." >&2
    echo "       On the host: stop the container, remove that directory, and either drop the" >&2
    echo "       -v <host-path>:$CONFIG_PATH mount (the image bootstraps its own default into" >&2
    echo "       the /data volume) or create the file first and chown it to 1000:1000." >&2
    exit 1
fi

# Bootstrap default config if not present (first run or fresh volume)
if [ ! -f "$CONFIG_PATH" ]; then
    echo "No config found at $CONFIG_PATH — copying default..."
    if ! mkdir -p /data/config || ! cp "$SHARE_DIR/ferrous-dns.toml" "$CONFIG_PATH"; then
        echo "ERROR: could not write $CONFIG_PATH as $RUN_AS." >&2
        echo "       /data and any mounted config path must be writable by that user;" >&2
        echo "       chown 1000:1000 them on the host." >&2
        exit 1
    fi
elif [ ! -w "$CONFIG_PATH" ]; then
    echo "WARNING: $CONFIG_PATH is not writable as $RUN_AS — the setup wizard," >&2
    echo "         POST /config and backup restore will fail to persist changes." >&2
fi

# Bootstrap migrations if not present (first run or fresh volume)
# The app resolves ./migrations relative to WORKDIR (/data)
if [ ! -d "/data/migrations" ]; then
    echo "No migrations found at /data/migrations — copying bundled migrations..."
    if ! cp -r "$SHARE_DIR/migrations" /data/migrations; then
        echo "ERROR: could not create /data/migrations as $RUN_AS." >&2
        echo "       The /data volume must be writable by that user." >&2
        exit 1
    fi
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
