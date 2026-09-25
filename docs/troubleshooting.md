# Troubleshooting

Common issues and solutions when running Ferrous DNS.

---

## Port 53 Already in Use

### Symptom

```text
Error: Address already in use (os error 98)
```

### Cause

On most Linux distributions, `systemd-resolved` occupies port 53.

### Solution

=== "Disable systemd-resolved"

    ```bash
    sudo systemctl stop systemd-resolved
    sudo systemctl disable systemd-resolved
    ```

    Then update `/etc/resolv.conf` to point to your router or a public resolver:

    ```bash
    sudo rm /etc/resolv.conf
    echo "nameserver 192.168.1.1" | sudo tee /etc/resolv.conf   # your router, or e.g. 1.1.1.1
    ```

    !!! warning "Don't point this machine at Ferrous DNS itself"
        With `nameserver 127.0.0.1`, this machine resolves through Ferrous DNS, which is not answering yet while it starts, so the hostnames in your upstream URLs cannot be looked up. If you do want that, set [`local_dns_server`](configuration/dns.md#local-dns-server) to your router so Ferrous DNS asks it for those names instead.

=== "Change systemd-resolved to stub mode"

    Edit `/etc/systemd/resolved.conf`:

    ```ini
    [Resolve]
    DNSStubListener=no
    ```

    Then restart:

    ```bash
    sudo systemctl restart systemd-resolved
    ```

=== "Use a different port"

    If you cannot disable systemd-resolved, run Ferrous DNS on a different port:

    ```toml
    [server]
    dns_port = 5353
    ```

    Then configure your router to forward DNS queries to `<server-ip>:5353`.

---

## DNS Queries Not Being Resolved

### Check 1: Is the server running?

```bash
# Docker
docker ps | grep ferrous

# Binary
ps aux | grep ferrous-dns
```

### Check 2: Can you reach the DNS port?

```bash
dig @<server-ip> example.com
```

If this times out, check firewall rules:

```bash
# Check if port 53 is open
sudo ss -tulnp | grep :53

# Open port 53 (if using ufw)
sudo ufw allow 53/udp
sudo ufw allow 53/tcp

# If mDNS device discovery is enabled (mdns_enabled), also allow UDP 5353
sudo ufw allow 5353/udp
```

### Check 3: Are upstream servers reachable?

Check the dashboard at **Settings > System Status > Upstream Health**. If all upstreams show "Unhealthy" (queries are still sent to them — the resolver fails open — but each may wait out the full timeout):

- Verify your upstream URLs are correct in `ferrous-dns.toml`
- Check network connectivity from the server: `dig @8.8.8.8 example.com`
- If using DoH/DoT/DoQ upstreams, ensure outbound ports 443/853 are open
- If only upstreams written as hostnames are unhealthy, see [An Upstream Hostname Never Comes Up](#hostname-upstream-never-comes-up)

---

## An Upstream Hostname Never Comes Up {#hostname-upstream-never-comes-up}

### Symptom

An upstream written with a hostname, such as `doq://dns.adguard-dns.com:853`, stays unhealthy and never answers, while the same server written as an IP address works. The startup log has `Failed to resolve upstream hostname, keeping unresolved … hostname=dns.adguard-dns.com`, and each query sent to it fails with `QUIC upstream dns.adguard-dns.com:853 has no IP address yet` (`QUIC transport requires resolved address` in 0.9.18 and earlier), which **Settings > System Status** also shows for that server.

### Cause

Ferrous DNS could not look the hostname up. It asks `local_dns_server` first when one is set, then the host's system resolver. The most common reason is a host whose `/etc/resolv.conf` points at Ferrous DNS itself, with no `local_dns_server` set: while Ferrous DNS starts, nothing answers that lookup, and afterwards Ferrous DNS has no resolved upstream to ask.

### Solution

- Set **Local DNS server** to your router in **Settings > DNS Settings** (`local_dns_server` in `[dns]`) and restart. Upstream hostnames are then asked to the router first
- Or point the host's own resolver at your router or a public resolver instead of Ferrous DNS
- Check the lookup works on the host: `getent hosts dns.adguard-dns.com`
- A lookup that failed is retried automatically, from the health-check interval up to every five minutes. The log shows `resolved to … upstream servers … on retry` when it succeeds. Saving the pools in **Settings > DNS Advanced > Upstream DNS Pools** retries at once

---

## An Upstream URL Is Rejected

Saving pools shows `Invalid server '…'`, or the server refuses to start with it. The message ends with how to fix the address; the common ones:

| Message | Fix |
|:--------|:----|
| `'quic://' is not a supported scheme` | Write DNS-over-QUIC as `doq://host:853` — AdGuard shows it as `quic://` |
| `missing port` | Add the port: `:853` for `tls://` and `doq://`, `:53` for `udp://` and `tcp://` |
| `add a scheme` | Only `IP:PORT` may omit the scheme; write a hostname as `udp://host:53` |
| `IPv6 addresses must be in brackets` | `https://[2606:4700:4700::1111]/dns-query` |

See [Upstream URL Formats](features/upstream-management.md#upstream-url-formats).

---

## A Domain Is Blocked and You Want It Allowed

### Symptom

A domain you need answers with `0.0.0.0` (or `NXDOMAIN`, depending on `block_mode`), and it is not on any blocklist you added.

### Cause

Find the real reason before changing anything. Open **Queries**, locate the domain, and read its **block source**:

| Block source | What matched |
|:-------------|:-------------|
| `blocklist` | A downloaded blocklist, or a domain you blocked by hand |
| `managed_domain` / `regex_filter` | A rule in **DNS Filter** |
| `schedule` | A time-based `BlockAll` window for the client's group |
| `dns_tunneling`, `dga_detection`, `dns_rebinding`, `nxdomain_hijack`, `response_ip_filter` | One of the five [malware detection](features/malware-detection.md) engines — a heuristic, so this is where false positives live |

### Solution

Click **Allow** next to the domain in the query log, or add it under **DNS Filter > Managed Domains** with the `allow` action.

That single step covers every row in the table above. An explicit allow is the highest-priority verdict in the pipeline: it overrules downloaded blocklists, schedule windows, blocked services, and all five detection engines. It applies from the next query — no restart.

```bash
curl -X POST http://localhost:8080/api/managed-domains \
  -H 'Content-Type: application/json' \
  -d '{"name":"needed by build agent","domain":"cdn.example.com","action":"allow","group_id":1}'
```

!!! warning "Pausing blocking will not do it"
    Disabling blocking releases downloaded blocklists only. A domain blocked by a rule you wrote by hand stays blocked — remove the rule instead. See [What a manual rule outranks](features/blocking-filtering.md#what-a-manual-rule-outranks).

---

## Blocklist Not Updating

### Symptom

**Last Sync** on the **Blocklists** page does not change after you click the refresh icon, or a list you added blocks nothing.

### Cause

A failed download does not fail the sync. The index is rebuilt without that download: the list keeps the copy it last downloaded, or stays empty if it never downloaded, and **Last Sync** keeps its old value. The reason is in the log:

```bash
docker logs ferrous-dns 2>&1 | grep "blocklist source"
```

| Log line | Meaning |
|:---------|:--------|
| `Fetched blocklist source url=…` | The download worked |
| `HTTP 404 for <url>` | The URL is wrong, or the list has moved |
| `timed out after Ns` | The server stopped sending for 30 seconds, or the download ran past 5 minutes |

### Solution

Correct the URL, or check that the server can reach the list's host. If the container restarts during a sync, the list is too large for the device's memory. See [Check blocklist size](#check-blocklist-size).

---

## Dashboard Not Loading

### Check the web port

```bash
curl -s http://<server-ip>:8080/ | head -20
```

If no response:

- Verify `web_port` in `ferrous-dns.toml` (default: `8080`)
- Check if the port is open: `sudo ss -tulnp | grep :8080`
- Check Docker port mappings if running in a container

### Blank page or JavaScript errors

- Clear browser cache and reload
- Check the browser console (F12) for errors
- Verify you are not using a very old browser — the dashboard requires ES2020 support

---

## DoT / DoH Not Working

### Check TLS certificates

```bash
# Verify cert file exists and is valid
openssl x509 -in /path/to/cert.pem -text -noout

# Check key matches cert
openssl x509 -in cert.pem -modulus -noout | md5sum
openssl rsa -in key.pem -modulus -noout | md5sum
# Both should output the same hash
```

### Check the server logs

```bash
# Docker
docker logs ferrous-dns 2>&1 | grep -i tls

# Binary
RUST_LOG=debug ./ferrous-dns --config ferrous-dns.toml 2>&1 | grep -i tls
```

If you see "TLS certificate not found, skipping DoT/DoH listeners", verify the file paths in:

```toml
[server.encrypted_dns]
tls_cert_path = "/data/cert.pem"
tls_key_path  = "/data/key.pem"
```

### Self-signed certificate rejected

Browsers reject DoH to servers with self-signed certificates. Options:

1. Use a [Let's Encrypt](https://letsencrypt.org/) certificate
2. Import the self-signed CA into your OS trust store
3. For DoT on Android/iOS, self-signed certificates are generally accepted

---

## High Memory Usage

### Check blocklist size

With large blocklists enabled, the block index can outgrow the DNS cache, and a sync briefly holds about twice as much. The measured sizes are in [large lists and memory](features/blocking-filtering.md#recommended-blocklists). On a device with 1 GB of RAM, use the mini or medium variant of HaGeZi's Threat Intelligence list rather than the full one.

### Check cache size

Apart from the block index, the DNS cache is the largest in-memory structure. Reduce it if memory is constrained:

```toml
[dns]
cache_max_entries = 50000    # default: 200000
```

### Check SQLite memory-mapped I/O

```toml
[database]
sqlite_mmap_size_mb = 32     # reduce from 64 for low-memory systems
sqlite_cache_size_kb = 8192  # reduce from 16384
```

### Raspberry Pi / low-memory devices

Use the RPi-optimized profile from the [cache configuration](configuration/cache.md):

```toml
[dns]
cache_max_entries = 50000
cache_compaction_interval = 300

[database]
sqlite_cache_size_kb = 8192
sqlite_mmap_size_mb = 32
```

---

## Database Locked / SQLITE_BUSY

### Symptom

```text
Error: database is locked
```

### Cause

SQLite WAL mode allows concurrent reads but serializes writes. Under very high query logging load, the write lock can be contended.

### Solution

Increase the busy timeout:

```toml
[database]
write_busy_timeout_secs = 60     # default: 30
```

Or reduce write pressure by sampling queries:

```toml
[database]
query_log_sample_rate = 10       # log 1 in 10 queries instead of all
query_log_max_batch_size = 5000  # larger batches = fewer transactions
```

---

## PROXY Protocol Rejecting Connections

### Symptom

All TCP DNS and DoT connections fail after enabling PROXY Protocol.

### Cause

When `proxy_protocol_enabled = true`, the server expects every TCP connection to start with a PROXY Protocol v2 header. Direct client connections (without a load balancer) do not include this header.

### Solution

Only enable PROXY Protocol when a compatible load balancer (HAProxy, AWS NLB, nginx stream module) is **always** in front:

```toml
[server]
# Only enable behind a load balancer
proxy_protocol_enabled = true
```

UDP DNS is not affected — PROXY Protocol only applies to TCP and DoT listeners.

---

## Docker Container Restart Loop on Startup

### Symptom

The container never finishes booting and `docker logs` repeats:

```text
No config found at /data/config/ferrous-dns.toml — copying default...
cp: can't create '/data/config/ferrous-dns.toml/ferrous-dns.toml': Permission denied
```

### Cause

The doubled path is the tell: `/data/config/ferrous-dns.toml` is a **directory**, so `cp` wrote *into* it. Docker creates the source of a bind mount as a root-owned directory whenever the host path does not exist yet, so a mount like `-v ./ferrous-dns.toml:/data/config/ferrous-dns.toml` pointing at a file you never created produces a directory the container cannot write — it runs as uid 1000. The entrypoint exits, and `restart: always` turns that into a loop.

### Solution

Stop the container, remove the directory Docker created, and drop the bind mount — the image bootstraps its own default config into the `/data` volume:

```bash
docker compose down          # or: docker rm -f ferrous-dns
rm -rf ./ferrous-dns.toml    # the directory Docker created, not a real config
```

To keep the config on the host instead, create the file and give it to uid 1000 **before** starting the container:

```bash
curl -fsSL -o ferrous-dns.toml \
  https://raw.githubusercontent.com/ferrous-networking/ferrous-dns/main/ferrous-dns.toml
chown 1000:1000 ferrous-dns.toml
```

The same applies to a config that is owned by another user: the mount must be writable by uid 1000 (and not `:ro`), or the setup wizard, `POST /config` and backup restore cannot persist changes.

---

## Docker Networking Issues

### Host network mode (recommended)

```yaml
services:
  ferrous-dns:
    network_mode: host
```

Host mode gives Ferrous DNS direct access to the network, enabling accurate client IP detection.

### Bridge mode

If you must use bridge mode, map the ports explicitly:

```yaml
services:
  ferrous-dns:
    ports:
      - "53:53/udp"
      - "53:53/tcp"
      - "8080:8080"
```

!!! warning "Client IP detection in bridge mode"
    In bridge mode, all queries appear to come from the Docker gateway IP (usually `172.17.0.1`). Client-specific features (groups, per-client policies) will not work correctly. Use host network mode for accurate client detection.

!!! warning "mDNS device discovery requires host mode"
    The mDNS listener (`mdns_enabled`) relies on multicast (`224.0.0.251:5353`), which does **not** traverse Docker bridge port mapping — adding `"5353:5353/udp"` to `ports:` will not deliver announcements. Use `network_mode: host` for mDNS to work.

---

## Increasing Log Verbosity

For debugging, increase the log level:

```toml
[logging]
level = "debug"    # options: error, warn, info, debug, trace
```

Or via environment variable:

```bash
RUST_LOG=debug ./ferrous-dns --config ferrous-dns.toml
```

!!! warning
    `debug` and `trace` levels produce significant log volume under load. Use only for troubleshooting, then revert to `info`.
