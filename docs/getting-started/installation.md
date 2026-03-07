# Installation

Ferrous DNS can be deployed via Docker (recommended), Docker Compose, or built from source.

---

## Docker

The fastest way to get started:

```bash
docker run -d \
  --name ferrous-dns \
  --restart always \
  --network host \
  --user root \
  -e FERROUS_CONFIG=/data/config/ferrous-dns.toml \
  -e FERROUS_DATABASE=/data/db/ferrous.db \
  -e FERROUS_DNS_PORT=53 \
  -e FERROUS_WEB_PORT=8080 \
  -e FERROUS_BIND_ADDRESS=0.0.0.0 \
  -e FERROUS_LOG_LEVEL=info \
  -e TZ=America/Sao_Paulo \
  --dns 10.0.0.1 \
  --cap-add NET_ADMIN \
  --cap-add SYS_TIME \
  --cap-add SYS_NICE \
  --cap-add NET_BIND_SERVICE \
  andersonviudes/ferrous-dns:latest
```

Access the dashboard at `http://localhost:8080`

!!! note "Network mode"
    `--network host` is required so Ferrous DNS can bind to port 53 and detect client IPs/MACs correctly. On macOS, host networking is not available in Docker Desktop — use a Linux VM or Docker Compose with explicit port mappings.

---

## Docker Compose

Create a `docker-compose.yml`:

```yaml
services:
  ferrous-dns:
    image: andersonviudes/ferrous-dns:latest
    container_name: ferrous-dns
    restart: always
    network_mode: host
    user: root
    environment:
      - FERROUS_CONFIG=/data/config/ferrous-dns.toml
      - FERROUS_DATABASE=/data/db/ferrous.db
      - FERROUS_DNS_PORT=53
      - FERROUS_WEB_PORT=8080
      - FERROUS_BIND_ADDRESS=0.0.0.0
      - FERROUS_LOG_LEVEL=info
      - TZ=America/Sao_Paulo
    dns:
      - 10.0.0.1
    cap_add:
      - NET_ADMIN
      - SYS_TIME
      - SYS_NICE
      - NET_BIND_SERVICE
    volumes:
      - ferrous-data:/data/

volumes:
  ferrous-data:
```

Then start it:

```bash
docker compose up -d
```

---

## Build from Source

### Prerequisites

- Rust 1.80+ (`rustup install stable`)
- SQLite development libraries

```bash
# Arch Linux
pacman -S sqlite

# Ubuntu / Debian
apt install libsqlite3-dev

# macOS
brew install sqlite
```

### Build

```bash
git clone https://github.com/ferrous-networking/Ferrous-DNS.git
cd Ferrous-DNS

# Standard build
cargo build --release

# Optimized for your CPU (recommended for production)
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

The binary is at `./target/release/ferrous-dns`.

### Run

```bash
./target/release/ferrous-dns --config ferrous-dns.toml
```

---

## Environment Variables

All configuration can be provided via environment variables. They take precedence over the TOML config file.

| Variable               | Default                               | Description                         |
|:-----------------------|:--------------------------------------|:------------------------------------|
| `FERROUS_CONFIG`       | —                                     | Path to TOML config file (optional) |
| `FERROUS_DNS_PORT`     | `53`                                  | DNS server port                     |
| `FERROUS_WEB_PORT`     | `8080`                                | Web dashboard port                  |
| `FERROUS_BIND_ADDRESS` | `0.0.0.0`                             | Bind address                        |
| `FERROUS_DATABASE`     | `/var/lib/ferrous-dns/ferrous.db`     | SQLite database path                |
| `FERROUS_LOG_LEVEL`    | `info`                                | Log level: `debug`, `info`, `warn`, `error` |

---

## Multi-Architecture Support

Docker images are published for both `amd64` and `arm64` (Raspberry Pi 4/5, Apple Silicon via Linux VM).

```bash
# Pull latest (auto-selects your arch)
docker pull andersonviudes/ferrous-dns:latest
```

!!! tip "Raspberry Pi"
    For low-RAM devices (1GB), tune the SQLite cache and shard count:
    ```toml
    sqlite_cache_size_kb = 8192
    sqlite_mmap_size_mb = 32
    # cache_shard_amount = 16
    ```
