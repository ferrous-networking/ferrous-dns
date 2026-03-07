# Quick Start

This guide gets Ferrous DNS running on your network in minutes.

---

## Step 1: Start the Server

=== "Docker Compose (recommended)"

    ```bash
    docker compose up -d
    ```

=== "Docker"

    ```bash
    docker run -d --name ferrous-dns --network host \
      --restart always --user root \
      --cap-add NET_ADMIN --cap-add NET_BIND_SERVICE \
      andersonviudes/ferrous-dns:latest
    ```

=== "Binary"

    ```bash
    ./target/release/ferrous-dns --config ferrous-dns.toml
    ```

---

## Step 2: Open the Dashboard

Navigate to `http://<your-server-ip>:8080` in your browser.

The dashboard shows:

- Real-time query log
- Blocked vs. allowed query ratio
- Top queried domains
- Upstream latency graphs
- Connected clients

---

## Step 3: Point Your Devices to Ferrous DNS

### Option A — Router (network-wide)

Set the DNS server in your router's DHCP settings to your Ferrous DNS server IP. All devices on your network will automatically use it.

### Option B — Single device

**Linux** (`/etc/resolv.conf` or NetworkManager):
```
nameserver 192.168.1.100
```

**Windows** (Network Adapter settings → IPv4 → DNS Server):
```
192.168.1.100
```

**macOS** (System Settings → Network → DNS):
```
192.168.1.100
```

---

## Step 4: Add a Blocklist

1. Open the dashboard at `http://<server>:8080`
2. Go to **Blocklists** in the sidebar
3. Click **Add Blocklist**
4. Paste a blocklist URL (see suggestions below) and click **Save**
5. Click **Sync** to download and activate it

### Recommended Blocklists

| List | URL | Focus |
|:-----|:----|:------|
| Steven Black Unified | `https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts` | Ads + Malware |
| OISD (small) | `https://small.oisd.nl/domainswild` | Balanced |
| HaGeZi Pro | `https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt` | Comprehensive |
| Hagezi Threat Intelligence | `https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/tif.txt` | Security |

---

## Step 5: Test It

```bash
# Check DNS is working
dig @<server-ip> example.com

# Check blocking is working (should return NXDOMAIN or 0.0.0.0)
dig @<server-ip> ads.doubleclick.net

# Check encrypted DNS (DoH)
curl -s "http://<server-ip>:8080/dns-query?name=example.com&type=A"
```

---

## Basic Configuration

For a minimal setup, create `ferrous-dns.toml`:

```toml
[server]
dns_port = 53
web_port = 8080
bind_address = "0.0.0.0"

[dns]
dnssec_enabled = true
local_domain = "lan"
local_dns_server = "192.168.1.1:53"  # your router

[[dns.pools]]
name = "default"
strategy = "Parallel"
priority = 1
servers = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
]

[blocking]
enabled = true

[database]
path = "/data/ferrous.db"
log_queries = true

[logging]
level = "info"
```

See the [full configuration reference](../configuration/index.md) for all available options.

---

## Next Steps

- [Configure upstream DNS pools](../configuration/dns.md)
- [Set up encrypted DNS (DoT/DoH)](../features/encrypted-dns.md)
- [Create client groups with parental controls](../features/client-management.md)
- [Enable CNAME cloaking detection](../features/blocking-filtering.md)
