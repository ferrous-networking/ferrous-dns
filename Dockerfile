# ============================================================================
# Ferrous DNS - Alpine Multi-stage Docker Build
# ============================================================================
FROM rust:1.75-alpine AS builder

# Install build dependencies (musl-dev for static linking)
RUN apk add --no-cache \
    musl-dev \
    openssl-dev \
    openssl-libs-static \
    pkgconfig

# Set target for static compilation
ENV RUSTFLAGS="-C target-feature=+crt-static"

# Create app directory
WORKDIR /app

# Copy workspace manifests
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/

# Build dependencies first (cached layer)
RUN mkdir -p crates/cli/src && \
    echo "fn main() {}" > crates/cli/src/main.rs && \
    cargo build --release && \
    rm -rf crates/cli/src

# Copy actual source code
COPY crates/ ./crates/

# Build the application (static binary)
RUN cargo build --release --bin ferrous-dns && \
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
    # Create data directories
    mkdir -p /data/config /data/db /data/logs && \
    chown -R ferrous:ferrous /data

# Copy binary from builder
COPY --from=builder /app/target/release/ferrous-dns /usr/local/bin/ferrous-dns

# Copy entrypoint script
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && \
    chown root:root /usr/local/bin/ferrous-dns && \
    chmod 755 /usr/local/bin/ferrous-dns

# Expose ports
EXPOSE 53/udp 53/tcp 8080/tcp

# Set working directory
WORKDIR /data

# Switch to non-root user
USER ferrous

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD /usr/local/bin/ferrous-dns --version || exit 1

# ============================================================================
# Environment Variables (with default values)
# ============================================================================
ENV FERROUS_CONFIG="/data/config/ferrous-dns.toml"
ENV FERROUS_DNS_PORT="53"
ENV FERROUS_WEB_PORT="8080"
ENV FERROUS_BIND_ADDRESS="0.0.0.0"
ENV FERROUS_DATABASE="/data/db/ferrous.db"
ENV FERROUS_LOG_LEVEL="info"
ENV RUST_LOG="info"

# ============================================================================
# Volumes for data persistence
# ============================================================================
VOLUME ["/data"]

# ============================================================================
# Entrypoint (JSON format - corrigido)
# ============================================================================
ENTRYPOINT ["/entrypoint.sh"]
CMD ["serve"]
