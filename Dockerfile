FROM rust:1.97-alpine AS builder

RUN apk add --no-cache \
    musl-dev \
    openssl-dev \
    openssl-libs-static \
    pkgconfig

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY crates/cli/Cargo.toml ./crates/cli/
COPY crates/domain/Cargo.toml ./crates/domain/
COPY crates/application/Cargo.toml ./crates/application/
COPY crates/infrastructure/Cargo.toml ./crates/infrastructure/
COPY crates/jobs/Cargo.toml ./crates/jobs/
COPY crates/api/Cargo.toml ./crates/api/
COPY crates/api-pihole/Cargo.toml ./crates/api-pihole/
COPY tests/Cargo.toml ./tests/

RUN mkdir -p crates/cli/src crates/domain/src crates/application/src \
             crates/infrastructure/src crates/jobs/src crates/api/src \
             crates/api-pihole/src tests/performance && \
    echo 'fn main() {}' > crates/cli/src/main.rs && \
    touch crates/domain/src/lib.rs crates/application/src/lib.rs \
          crates/infrastructure/src/lib.rs crates/jobs/src/lib.rs \
          crates/api/src/lib.rs crates/api-pihole/src/lib.rs \
          tests/performance/competitor_comparison.rs && \
    cargo build --release && \
    rm -rf crates/*/src

COPY crates/ ./crates/
COPY web/ ./web/
COPY migrations/ ./migrations/

RUN find crates -name "*.rs" -exec touch {} + && \
    cargo build --release --bin ferrous-dns && \
    strip target/release/ferrous-dns

FROM alpine:3.24

RUN apk add --no-cache \
    ca-certificates \
    tzdata && \
    addgroup -g 1000 ferrous && \
    adduser -D -u 1000 -G ferrous -s /bin/sh ferrous && \
    mkdir -p /data/config /data/db /data/logs && \
    chown -R ferrous:ferrous /data

COPY --from=builder /app/target/release/ferrous-dns /usr/local/bin/ferrous-dns
COPY --chown=ferrous:ferrous ferrous-dns.toml /usr/local/share/ferrous-dns/ferrous-dns.toml
COPY --chown=ferrous:ferrous migrations/ /usr/local/share/ferrous-dns/migrations/
COPY docker/entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh && \
    chown root:root /usr/local/bin/ferrous-dns && \
    chmod 755 /usr/local/bin/ferrous-dns

WORKDIR /data
USER ferrous

HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=60 \
    CMD /usr/local/bin/ferrous-dns --version || exit 1

ENV FERROUS_CONFIG="/data/config/ferrous-dns.toml" \
    FERROUS_DNS_PORT="53" \
    FERROUS_WEB_PORT="8080" \
    FERROUS_BIND_ADDRESS="0.0.0.0" \
    FERROUS_DATABASE="/data/db/ferrous.db" \
    FERROUS_LOG_LEVEL="info" \
    RUST_LOG="info"

VOLUME ["/data"]

ENTRYPOINT ["/entrypoint.sh"]
