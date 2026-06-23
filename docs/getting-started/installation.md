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
  -e TZ=America/Sao_Paulo \
  -v /path/to/ferrous-dns.toml:/data/config/ferrous-dns.toml \
  -v ferrous-data:/data/ \
  --dns 10.0.0.1 \
  --cap-add NET_ADMIN \
  --cap-add SYS_TIME \
  --cap-add SYS_NICE \
  --cap-add NET_BIND_SERVICE \
  ferrousnetworking/ferrous-dns:latest \
  --config /data/config/ferrous-dns.toml
```

Ports, bind address, database path, and log level are all set inside the mounted `ferrous-dns.toml`. The binary does not read `FERROUS_*` environment variables; pass overrides as CLI flags after the image name (e.g. `--dns-port 53`).

Access the dashboard at `http://localhost:8080`

!!! note "Network mode"
    `--network host` is required so Ferrous DNS can bind to port 53 and detect client IPs/MACs correctly. It is also required for **mDNS device discovery** (`mdns_enabled`): multicast on UDP 5353 does not traverse Docker bridge port mapping, so the listener only works in host mode. On macOS, host networking is not available in Docker Desktop — use a Linux VM or Docker Compose with explicit port mappings.

---

## Docker Compose

Create a `docker-compose.yml`:

```yaml
services:
  ferrous-dns:
    image: ferrousnetworking/ferrous-dns:latest
    container_name: ferrous-dns
    restart: always
    network_mode: host
    user: root
    command: ["--config", "/data/config/ferrous-dns.toml"]
    environment:
      - TZ=America/Sao_Paulo
    dns:
      - 10.0.0.1
    cap_add:
      - NET_ADMIN
      - SYS_TIME
      - SYS_NICE
      - NET_BIND_SERVICE
    volumes:
      - ./ferrous-dns.toml:/data/config/ferrous-dns.toml
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
git clone https://github.com/ferrous-networking/ferrous-dns.git
cd ferrous-dns

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

## Configuration

Ferrous DNS is configured through a TOML config file, with a few settings also exposed as command-line flags. **There are no environment variables** — the binary does not read `FERROUS_*` or `RUST_LOG`.

### Config file

Point the server at a config file with `--config`/`-c`:

```bash
./target/release/ferrous-dns --config ferrous-dns.toml
```

If `--config` is omitted, the server looks for a config file in this order:

1. `ferrous-dns.toml` in the current working directory
2. `/etc/ferrous-dns/config.toml`

If neither exists, built-in defaults are used.

### CLI flags

These flags override the matching values from the config file:

| Flag                  | Short | Description                                   |
|:----------------------|:------|:----------------------------------------------|
| `--config <FILE>`     | `-c`  | Path to the TOML config file                  |
| `--dns-port <PORT>`   | `-d`  | DNS server port (config: `server.dns_port`)   |
| `--web-port <PORT>`   | `-w`  | Web dashboard port (config: `server.web_port`) |
| `--bind <ADDR>`       | `-b`  | Bind address (config: `server.bind_address`)  |
| `--database <PATH>`   |       | SQLite database path (config: `database.path`) |
| `--log-level <LEVEL>` |       | Log level: `debug`, `info`, `warn`, `error` (config: `logging.level`) |

!!! note "Log level"
    The log level is set by `logging.level` in the config file (or the `--log-level` flag). `RUST_LOG` is **not** consulted.

---

## Multi-Architecture Support

Docker images are published for both `amd64` and `arm64` (Raspberry Pi 4/5, Apple Silicon via Linux VM).

```bash
# Pull latest (auto-selects your arch)
docker pull ferrousnetworking/ferrous-dns:latest
```

!!! tip "Raspberry Pi"
    For low-RAM devices (1GB), tune the SQLite cache and shard count:
    ```toml
    sqlite_cache_size_kb = 8192
    sqlite_mmap_size_mb = 32
    # cache_shard_amount = 16
    ```
