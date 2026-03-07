# Encrypted DNS

Ferrous DNS supports encrypted DNS both as a **client** (upstream protocols) and as a **server** (serving encrypted DNS to your devices).

---

## Upstream Protocols

When Ferrous DNS resolves a query, it can communicate with upstream servers using any of these protocols:

| Protocol | Standard | Description |
|:---------|:---------|:------------|
| Plain UDP | — | Traditional DNS, no encryption. Fastest, but exposes queries |
| Plain TCP | — | DNS over TCP. Used for large responses |
| DNS-over-HTTPS (DoH) | RFC 8484 | DNS inside HTTPS. Works through firewalls, hard to block |
| DNS-over-TLS (DoT) | RFC 7858 | DNS over TLS. Clean separation from HTTP traffic |
| DNS-over-QUIC (DoQ) | RFC 9250 | DNS over QUIC. Lowest latency of encrypted options |
| HTTP/3 | RFC 9114 | DoH over HTTP/3 (QUIC). Combines DoH benefits with QUIC performance |

### Configuring Upstreams

```toml
[[dns.pools]]
name = "secure"
strategy = "Parallel"
priority = 1
servers = [
    # DoQ — lowest latency encrypted
    "doq://dns.adguard-dns.com:853",
    "doq://dns.alidns.com:853",

    # DoH — universal compatibility
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
    "https://dns.quad9.net/dns-query",

    # HTTP/3 (DoH over QUIC)
    "h3://dns.google/dns-query",

    # DoT
    "tls://1.1.1.1:853",
    "tls://8.8.8.8:853",
]
```

### Public Resolver Reference

| Provider | DoH | DoT | DoQ |
|:---------|:----|:----|:----|
| Cloudflare | `https://cloudflare-dns.com/dns-query` | `tls://1.1.1.1:853` | — |
| Google | `https://dns.google/dns-query` | `tls://8.8.8.8:853` | — |
| Quad9 | `https://dns.quad9.net/dns-query` | `tls://dns.quad9.net:853` | — |
| AdGuard | `https://dns.adguard-dns.com/dns-query` | `tls://dns.adguard-dns.com:853` | `doq://dns.adguard-dns.com:853` |
| NextDNS | `https://dns.nextdns.io` | — | — |
| CleanBrowsing | `https://doh.cleanbrowsing.org/doh/security-filter/` | — | — |

---

## Server-Side Encrypted DNS

Ferrous DNS can serve DNS-over-TLS and DNS-over-HTTPS directly to clients on your network, so devices can connect to Ferrous DNS securely.

### Requirements

- A TLS certificate and private key in PEM format
- Open firewall ports (853 for DoT, 443 or custom for DoH)

### Configuration

```toml
[server.encrypted_dns]
dot_enabled   = true
dot_port      = 853
doh_enabled   = true
doh_port      = 443        # optional: omit to co-host on web_port
tls_cert_path = "/data/cert.pem"
tls_key_path  = "/data/key.pem"
```

### Self-Signed Certificate

```bash
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout key.pem -out cert.pem \
  -days 365 \
  -subj "/CN=dns.home.local" \
  -addext "subjectAltName=IP:192.168.1.100,DNS:dns.home.local"
```

Copy to your data directory and reference in config.

### Let's Encrypt Certificate

If your server has a public domain, use Certbot:

```bash
certbot certonly --standalone -d dns.yourdomain.com
# Certificate: /etc/letsencrypt/live/dns.yourdomain.com/fullchain.pem
# Key:         /etc/letsencrypt/live/dns.yourdomain.com/privkey.pem
```

```toml
[server.encrypted_dns]
tls_cert_path = "/etc/letsencrypt/live/dns.yourdomain.com/fullchain.pem"
tls_key_path  = "/etc/letsencrypt/live/dns.yourdomain.com/privkey.pem"
```

---

## Client Configuration

### DNS-over-TLS (DoT)

=== "Android"

    Settings > Network > Private DNS > Enter hostname:
    ```
    192.168.1.100
    ```
    Or with custom hostname:
    ```
    dns.home.local
    ```

=== "iOS / macOS"

    Use a `.mobileconfig` profile or a DNS app like DNSCloak. Set:
    - Server: `192.168.1.100`
    - Port: `853`
    - Protocol: TLS

=== "Router (Unifi / OPNsense)"

    Under DNS settings, set upstream to:
    ```
    tls://192.168.1.100:853
    ```

=== "Linux (systemd-resolved)"

    `/etc/systemd/resolved.conf`:
    ```ini
    [Resolve]
    DNS=192.168.1.100
    DNSOverTLS=yes
    ```

### DNS-over-HTTPS (DoH)

=== "Firefox"

    Settings > Privacy & Security > DNS over HTTPS > Custom:
    ```
    https://192.168.1.100/dns-query
    ```

=== "Chrome / Edge"

    Settings > Privacy > Security > Use secure DNS > Custom:
    ```
    https://192.168.1.100/dns-query
    ```

=== "curl (testing)"

    ```bash
    curl -s "https://192.168.1.100/dns-query?name=example.com&type=A" \
      --doh-url "https://192.168.1.100/dns-query"
    ```

=== "dig (testing)"

    ```bash
    # Test DoT
    kdig @192.168.1.100 +tls example.com

    # Test DoH
    curl -H "accept: application/dns-json" \
      "https://192.168.1.100/dns-query?name=example.com&type=A"
    ```

---

## IPv6 Upstreams

Ferrous DNS fully supports IPv6 upstreams:

```toml
[[dns.pools]]
name = "ipv6-pool"
strategy = "Parallel"
priority = 1
servers = [
    "https://[2606:4700:4700::1111]/dns-query",   # Cloudflare IPv6
    "https://[2001:4860:4860::8888]/dns-query",   # Google IPv6
]
```

---

## DNS Name Resolution for Upstreams

Upstream server hostnames are resolved at startup, so you can use domain names directly:

```toml
servers = [
    "doq://dns.adguard-dns.com:853",     # resolved at startup
    "https://dns.google/dns-query",       # resolved at startup
]
```

This avoids bootstrap DNS dependency issues — Ferrous DNS uses the system resolver once at startup to resolve upstream hostnames, then caches the IPs internally.
