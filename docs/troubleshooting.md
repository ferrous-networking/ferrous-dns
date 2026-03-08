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

    Then update `/etc/resolv.conf` to point to Ferrous DNS or a public resolver:

    ```bash
    sudo rm /etc/resolv.conf
    echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf
    ```

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
```

### Check 3: Are upstream servers reachable?

Check the dashboard at **Settings > System Status > Upstream Health**. If all upstreams show "Unhealthy":

- Verify your upstream URLs are correct in `ferrous-dns.toml`
- Check network connectivity from the server: `dig @8.8.8.8 example.com`
- If using DoH/DoT/DoQ upstreams, ensure outbound ports 443/853 are open

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

### Check cache size

The DNS cache is the largest in-memory structure. Reduce it if memory is constrained:

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
