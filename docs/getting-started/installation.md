# Installation

Ferrous DNS can be deployed via Docker (recommended), Docker Compose, or built from source.

Linux (`amd64`/`arm64`) is the supported platform. There is **no native Windows or macOS binary** — see [Windows (WSL2)](#windows-wsl2) and [Platform support](#platform-support).

---

## Docker

The fastest way to get started:

```bash
docker run -d \
  --name ferrous-dns \
  --restart always \
  --network host \
  --user 1000:1000 \
  -e TZ=America/Sao_Paulo \
  -e FERROUS_CONFIG=/data/config/ferrous-dns.toml \
  -v ferrous-data:/data/ \
  --dns 10.0.0.1 \
  --cap-add NET_BIND_SERVICE \
  ferrousnetworking/ferrous-dns:latest
```

No host config file is needed to start: on first run the entrypoint copies the bundled default `ferrous-dns.toml` into `/data/config/` inside the `ferrous-data` volume. Ports, bind address, database path, and log level are all set inside that file, and can be overridden with the `FERROUS_*` environment variables below — the Docker image's entrypoint script translates them into the matching CLI flags at startup.

#### Environment Variables

| Variable              | Default                               | Description                         |
|:----------------------|:--------------------------------------|:------------------------------------|
| `FERROUS_CONFIG`      | —                                     | Path to TOML config file (optional) |
| `FERROUS_DNS_PORT`    | `53`                                  | DNS server port                     |
| `FERROUS_WEB_PORT`    | `8080`                                | Web dashboard port                  |
| `FERROUS_BIND_ADDRESS`| `0.0.0.0`                             | Bind address                        |
| `FERROUS_DATABASE`    | `/data/db/ferrous.db`                 | SQLite database path                |
| `FERROUS_LOG_LEVEL`   | `info`                                | Log level: debug, info, warn, error |

Access the dashboard at `http://localhost:8080`

!!! note "Network mode"
    `--network host` is required so Ferrous DNS can bind to port 53 and detect client IPs/MACs correctly. It is also required for **mDNS device discovery** (`mdns_enabled`): multicast on UDP 5353 does not traverse Docker bridge port mapping, so the listener only works in host mode. On macOS, host networking is not available in Docker Desktop — use a Linux VM or Docker Compose with explicit port mappings.

#### Keeping the config file on the host (optional)

Editing `ferrous-dns.toml` by hand is easier when the file lives on the host rather than inside the volume. Bind-mounting it takes two extra steps, both mandatory:

```bash
curl -fsSL -o ferrous-dns.toml \
  https://raw.githubusercontent.com/ferrous-networking/ferrous-dns/main/ferrous-dns.toml
chown 1000:1000 ferrous-dns.toml
```

Only then add the mount:

```bash
  -v "$PWD/ferrous-dns.toml:/data/config/ferrous-dns.toml" \
```

!!! warning "Create the file before mounting it"
    Docker creates the source of a bind mount as a **root-owned directory** when the host path does not exist. Mounting a path you have not created yet therefore puts a directory at `/data/config/ferrous-dns.toml`, and the container — which runs as uid 1000 — cannot write it, so it exits and `--restart always` turns that into a restart loop. Keep the mount writable too (no `:ro`): the first-run setup wizard, `POST /config` from the dashboard, and backup restore all persist changes back to this file.

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
    user: "1000:1000"
    environment:
      - FERROUS_CONFIG=/data/config/ferrous-dns.toml
      - TZ=America/Sao_Paulo
    dns:
      - 10.0.0.1
    cap_add:
      - NET_BIND_SERVICE
    volumes:
      - ferrous-data:/data/

volumes:
  ferrous-data:
```

To keep the config on the host, follow [Keeping the config file on the host](#keeping-the-config-file-on-the-host-optional) first, then add `- ./ferrous-dns.toml:/data/config/ferrous-dns.toml` to `volumes:`.

Then start it:

```bash
docker compose up -d
```

---

## Windows (WSL2)

There is no native Windows build. Ferrous DNS's UDP hot path relies on Linux-only socket APIs (`SO_REUSEPORT` for the per-core listeners, `IP_PKTINFO` for source-address selection, `recvmmsg` for batched receives), so on Windows it runs inside **WSL2** — either the Linux binary directly or the Docker image via Docker Desktop's WSL2 backend.

The catch is networking, not the build: by default WSL2 sits behind NAT with its own IP, so devices on your LAN cannot reach port 53 inside it. `netsh interface portproxy` does **not** solve this — it forwards TCP only, and DNS is primarily UDP. Network-wide blocking therefore requires WSL's *mirrored* networking mode.

### 1. Requirements

- **Windows 11 22H2** (build 22621) or newer — mirrored networking does not exist on Windows 10.
- WSL **2.0.9+** (check with `wsl --version`) and a distro: `wsl --install -d Ubuntu`.

### 2. Put WSL on the LAN

Create or edit `%UserProfile%\.wslconfig`:

```ini
[wsl2]
networkingMode=mirrored
```

Then apply it with `wsl --shutdown` and reopen your distro. WSL now shares the host's network interfaces, so a socket bound inside WSL is reachable on the Windows machine's LAN IP.

!!! warning "Do not set `hostAddressLoopback`"
    That option is experimental and does the opposite of what you want here (it lets WSL reach *the host* by its LAN IP). It is not needed for inbound access.

### 3. Allow inbound traffic through the Hyper-V firewall

Mirrored mode is still gated by the Hyper-V firewall, which blocks inbound connections by default. In an **elevated PowerShell**:

```powershell
$wsl = '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}'
New-NetFirewallHyperVRule -Name 'FerrousDNS-UDP53' -DisplayName 'Ferrous DNS (DNS/UDP)' `
  -VMCreatorId $wsl -Protocol UDP -LocalPorts 53 -Action Allow
New-NetFirewallHyperVRule -Name 'FerrousDNS-TCP53' -DisplayName 'Ferrous DNS (DNS/TCP)' `
  -VMCreatorId $wsl -Protocol TCP -LocalPorts 53 -Action Allow
New-NetFirewallHyperVRule -Name 'FerrousDNS-Web' -DisplayName 'Ferrous DNS (dashboard)' `
  -VMCreatorId $wsl -Protocol TCP -LocalPorts 8080 -Action Allow
```

Both UDP and TCP on 53 are needed — clients retry over TCP whenever a response is truncated.

### 4. Free port 53 inside the distro

Ubuntu's WSL image boots with systemd, and `systemd-resolved` holds a stub listener on `127.0.0.53:53`. Disable it and stop WSL from rewriting `/etc/resolv.conf`:

```bash
sudo mkdir -p /etc/systemd/resolved.conf.d
printf '[Resolve]\nDNSStubListener=no\n' | sudo tee /etc/systemd/resolved.conf.d/ferrous.conf
sudo systemctl restart systemd-resolved

printf '[network]\ngenerateResolvConf = false\n' | sudo tee -a /etc/wsl.conf
```

After `wsl --shutdown`, write your own `/etc/resolv.conf` (`nameserver 1.1.1.1`). Point it at a public resolver, not at Ferrous DNS itself — otherwise package installs inside the distro break whenever the server is stopped.

### 5. Run the server

Native binary — follow [Build from Source](#build-from-source) inside the distro, then grant the port-53 capability so you don't need root:

```bash
sudo setcap cap_net_bind_service=+ep ./target/release/ferrous-dns
./target/release/ferrous-dns --config ferrous-dns.toml
```

Docker Desktop — use explicit port mappings instead of `--network host`:

```bash
docker run -d --name ferrous-dns --restart always \
  -p 53:53/udp -p 53:53/tcp -p 8080:8080 \
  -e FERROUS_CONFIG=/data/config/ferrous-dns.toml \
  -v ferrous-data:/data/ \
  ferrousnetworking/ferrous-dns:latest
```

Docker Desktop 4.34+ does support host networking (opt-in under **Settings → Resources → Network**), but it is layer-4 only and containers cannot bind a specific host address, so explicit mappings are the predictable path here.

### Known limitations under WSL2

- **mDNS device discovery** (`mdns_enabled`) is untested and should be left off — multicast behaviour differs from a bare-metal Linux host.
- **WSL does not start at boot.** Register a Scheduled Task that runs `wsl -d Ubuntu -u root /path/to/ferrous-dns ...` at logon/startup, or the DNS server disappears after a reboot.
- **Mirrored mode has open port-binding bugs** upstream (wildcard binds and reserved localhost ranges). If a listener fails to bind, try a `wsl --shutdown` first.
- For anything you actually depend on, a Raspberry Pi, a spare Linux box, or a Hyper-V VM on an *external* (bridged) virtual switch is a less surprising host than WSL2.

!!! note "Windows 10, or NAT mode"
    Without mirrored networking, WSL2 can only serve the Windows machine itself (via `localhostForwarding`). It cannot act as a network-wide DNS server, and no `netsh` port-forwarding workaround exists for UDP.

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

Ferrous DNS is configured through a TOML config file, with a few settings also exposed as command-line flags. **The `ferrous-dns` binary itself has no environment variables** — it does not read `FERROUS_*` or `RUST_LOG` directly. The `FERROUS_*` variables only exist as a convenience layer in the Docker image's entrypoint script, which converts them into the CLI flags below before launching the binary. `RUST_LOG` is not one of them — the entrypoint only checks it to decide whether to echo its assembled command line for debugging; it never controls the server's own log level (`FERROUS_LOG_LEVEL`/`--log-level` does).

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

## Platform support

| Platform            | Status                                                                 |
|:--------------------|:-----------------------------------------------------------------------|
| Linux `amd64`       | Supported — prebuilt binary and Docker image                            |
| Linux `arm64`       | Supported — prebuilt binary and Docker image (Raspberry Pi 4/5)         |
| Windows             | Via [WSL2](#windows-wsl2) only — no native binary                       |
| macOS               | Docker with a Linux VM; no native binary and no host networking         |

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
