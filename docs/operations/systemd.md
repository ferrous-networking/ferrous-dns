# Bare Metal (systemd)

The release binary runs as a sandboxed systemd service: its own unprivileged user, only the capability to bind ports below 1024, a read-only view of the system except for its config and state directories, and a restart when it dies.

The unit ships in the repository as [`contrib/systemd/ferrous-dns.service`](https://github.com/ferrous-networking/ferrous-dns/blob/main/contrib/systemd/ferrous-dns.service). It needs systemd 247 or later and Linux on `amd64` or `arm64`, which are the two release builds.

---

## Install

### 1. The binary

Download the release, check it against its checksum, and put the binary on the path:

```bash
VERSION=X.Y.Z
ARCH=amd64   # or arm64
BASE=https://github.com/ferrous-networking/ferrous-dns/releases/download/v$VERSION
curl -fsSLO "$BASE/ferrous-dns-linux-$ARCH.tar.gz"
curl -fsSLO "$BASE/ferrous-dns-linux-$ARCH.tar.gz.sha256"
sha256sum -c "ferrous-dns-linux-$ARCH.tar.gz.sha256"
sudo tar -xzf "ferrous-dns-linux-$ARCH.tar.gz" -C /usr/local/bin ferrous-dns
ferrous-dns --version
```

The tarball holds that one file. The binary is statically linked, so no shared library or runtime has to be installed beside it.

### 2. A user and the config directory

```bash
sudo useradd --system --home-dir /var/lib/ferrous-dns --shell /usr/sbin/nologin ferrous-dns
sudo install -d -o ferrous-dns -g ferrous-dns -m 0750 /etc/ferrous-dns
```

The state directory, `/var/lib/ferrous-dns`, is created by systemd on the first start (`StateDirectory=`).

### 3. The config file

Start from the sample config of the same release, and move the database and the TLS files into the state directory:

```bash
sudo curl -fsSL -o /etc/ferrous-dns/config.toml \
  "https://raw.githubusercontent.com/ferrous-networking/ferrous-dns/v$VERSION/ferrous-dns.toml"
sudo sed -i \
  -e 's|^path = "ferrous-dns.db"|path = "/var/lib/ferrous-dns/ferrous.db"|' \
  -e 's|"/data/cert.pem"|"/var/lib/ferrous-dns/tls/cert.pem"|' \
  -e 's|"/data/key.pem"|"/var/lib/ferrous-dns/tls/key.pem"|' \
  /etc/ferrous-dns/config.toml
sudo chown ferrous-dns:ferrous-dns /etc/ferrous-dns/config.toml
sudo chmod 0600 /etc/ferrous-dns/config.toml
```

The file has to stay writable by the service. The setup wizard, every save from the dashboard and a backup import write it back, through a temporary file in the same directory, so the directory must be writable too. It ends up holding the admin password hash, so keep it `0600`. See the [configuration reference](../configuration/index.md) for every key.

### 4. The unit

```bash
sudo curl -fsSL -o /etc/systemd/system/ferrous-dns.service \
  "https://raw.githubusercontent.com/ferrous-networking/ferrous-dns/v$VERSION/contrib/systemd/ferrous-dns.service"
sudo systemctl daemon-reload
sudo systemctl enable --now ferrous-dns
```

If the start fails with `Address already in use`, something else holds port 53. On most distributions that is `systemd-resolved`. See [Port 53 Already in Use](../troubleshooting.md#port-53-already-in-use).

### 5. Check it

```bash
systemctl status ferrous-dns
journalctl -u ferrous-dns -n 50
dig @127.0.0.1 example.com
sudo -u ferrous-dns /usr/local/bin/ferrous-dns --config /etc/ferrous-dns/config.toml --healthcheck && echo healthy
```

Then open `http://<host>:8080` and set the admin password. To serve the dashboard over HTTPS behind a reverse proxy, continue with [TLS & reverse proxy](tls-reverse-proxy.md).

---

## The unit

```ini
--8<-- "contrib/systemd/ferrous-dns.service"
```

| Setting | Why |
|:--------|:----|
| `User=ferrous-dns`, `AmbientCapabilities=CAP_NET_BIND_SERVICE` | The server never runs as root. Binding 53 (and 853 for DoT/DoQ) is the one privileged thing it does, and the capability bounding set holds nothing else. |
| `ProtectSystem=strict`, `ReadWritePaths=/etc/ferrous-dns`, `StateDirectory=ferrous-dns` | The whole file system is read-only to the service except the config directory, which the dashboard rewrites, and `/var/lib/ferrous-dns`, which holds the database, the TLS files and anything you point it at there. |
| `UMask=0077` | The database, the TLS key and everything else it writes are readable by the service user only. |
| `Restart=on-failure` | A crash or a kill brings it back after 5 s. A clean `systemctl stop` does not. |
| `TimeoutStopSec=30s` | On SIGTERM the server closes the database within 5 s and folds the WAL back into it, so the next start has nothing to recover. |
| `RestrictAddressFamilies=… AF_NETLINK` | IPv4, IPv6 and Unix sockets, plus netlink, which the Pi-hole compatible network endpoints use to list interfaces. |
| `SystemCallFilter=@system-service`, `MemoryDenyWriteExecute=yes` and the `Protect*` lines | Standard sandboxing. `systemd-analyze security ferrous-dns` rates the unit 1.5 (OK). |

This unit was checked in three ways:

- `systemd-analyze verify` and `systemd-analyze security` pass.
- Run as a non-root user holding only `CAP_NET_BIND_SERVICE`, on a read-only root file system with only `/etc/ferrous-dns` and `/var/lib/ferrous-dns` writable, the server answered on port 53. It also took the first-run password, which rewrites the config, generated its HTTPS certificate under `/var/lib/ferrous-dns/tls/`, wrote a backup, and left no `-wal` file after SIGTERM.
- Under every sandboxing directive above except `ProtectHome`, which only hides `/home`, `/root` and `/run/user`, it loaded a blocklist over HTTPS, read the ARP table, started the mDNS listener and served the Pi-hole network endpoints.

### Changing the unit

Override settings with a drop-in instead of editing the file, so an upgrade of the file does not lose them:

```bash
sudo systemctl edit ferrous-dns
```

For example, a database outside `/var/lib/ferrous-dns` needs that directory added with another `ReadWritePaths=` line, as well as the new `[database] path` in the config.

---

## Upgrading the binary

Back up first, then replace the file and restart:

```bash
sudo -u ferrous-dns /usr/local/bin/ferrous-dns --config /etc/ferrous-dns/config.toml \
  --backup-database "/var/lib/ferrous-dns/pre-upgrade-$(date +%F).db"
sudo tar -xzf "ferrous-dns-linux-$ARCH.tar.gz" -C /usr/local/bin ferrous-dns
sudo systemctl restart ferrous-dns
```

Releases before 1.0.0 have no `--backup-database`; copy the stopped database instead. See [Upgrading](backups-upgrades.md#upgrading) for what to check before and after, and how to go back.
