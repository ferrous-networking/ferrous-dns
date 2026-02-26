# ============================================================================
# Ferrous DNS - Alpine Multi-stage Docker Build
# ============================================================================
FROM rust:1.93-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    musl-dev \
    openssl-dev \
    openssl-libs-static \
    pkgconfig


# Create app directory
WORKDIR /app

# Copy only workspace and crate manifests (cache invalidated only by dep changes)
COPY Cargo.toml Cargo.lock ./
COPY crates/cli/Cargo.toml ./crates/cli/
COPY crates/domain/Cargo.toml ./crates/domain/
COPY crates/application/Cargo.toml ./crates/application/
COPY crates/infrastructure/Cargo.toml ./crates/infrastructure/
COPY crates/jobs/Cargo.toml ./crates/jobs/
COPY crates/api/Cargo.toml ./crates/api/

# Create stub sources for all crates to compile dependencies only
RUN mkdir -p crates/cli/src crates/domain/src crates/application/src \
             crates/infrastructure/src crates/jobs/src crates/api/src && \
    echo 'fn main() {}' > crates/cli/src/main.rs && \
    touch crates/domain/src/lib.rs crates/application/src/lib.rs \
          crates/infrastructure/src/lib.rs crates/jobs/src/lib.rs \
          crates/api/src/lib.rs && \
    cargo build --release && \
    rm -rf crates/*/src

# Copy actual source code, web assets, and migrations
# (required for include_str! and sqlx::migrate! at compile time)
COPY crates/ ./crates/
COPY web/ ./web/
COPY migrations/ ./migrations/

# Build the application (static binary)
# Touch all source files to ensure cargo detects changes vs stub artifacts (timestamp fix)
RUN find crates -name "*.rs" -exec touch {} + && \
    cargo build --release --bin ferrous-dns && \
    strip target/release/ferrous-dns

# ============================================================================
# Runtime Stage - Alpine Minimal
# ============================================================================
FROM alpine:3.19

# Install runtime dependencies and create user
RUN apk add --no-cache \
    ca-certificates \
    tzdata && \
    addgroup -g 1000 ferrous && \
    adduser -D -u 1000 -G ferrous -s /bin/sh ferrous && \
    mkdir -p /data/config /data/db /data/logs && \
    chown -R ferrous:ferrous /data

# Copy binary from builder
COPY --from=builder /app/target/release/ferrous-dns /usr/local/bin/ferrous-dns

# Copy default config and migrations to a stable path outside the volume.
# The entrypoint will bootstrap these into /data/ on first run.
COPY --chown=ferrous:ferrous ferrous-dns.toml /usr/local/share/ferrous-dns/ferrous-dns.toml
COPY --chown=ferrous:ferrous migrations/ /usr/local/share/ferrous-dns/migrations/

# Copy entrypoint script
COPY docker/entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh && \
    chown root:root /usr/local/bin/ferrous-dns && \
    chmod 755 /usr/local/bin/ferrous-dns

# Set working directory
WORKDIR /data

# Switch to non-root user
USER ferrous

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD /usr/local/bin/ferrous-dns --version || exit 1

# Environment Variables
ENV FERROUS_CONFIG="/data/config/ferrous-dns.toml" \
    FERROUS_DNS_PORT="53" \
    FERROUS_WEB_PORT="8080" \
    FERROUS_BIND_ADDRESS="0.0.0.0" \
    FERROUS_DATABASE="/data/db/ferrous.db" \
    FERROUS_LOG_LEVEL="info" \
    RUST_LOG="info"

# Volumes
VOLUME ["/data"]

# Entrypoint
ENTRYPOINT ["/entrypoint.sh"]
