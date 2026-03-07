# Server Configuration

The `[server]` section controls ports, bind address, API authentication, and encrypted DNS listeners.

---

## Basic Options

```toml
[server]
dns_port = 53
web_port = 8080
bind_address = "0.0.0.0"
```

| Option | Default | Description |
|:-------|:--------|:------------|
| `dns_port` | `53` | UDP and TCP port for DNS queries |
| `web_port` | `8080` | HTTP port for the dashboard and REST API |
| `bind_address` | `0.0.0.0` | Network interface to bind to. Use a specific IP to restrict access |

---

## API Security

### API Key

Protect the REST API with a static key:

```toml
[server]
api_key = "your-secret-api-key"
```

When set, all API requests must include the header:

```
Authorization: Bearer your-secret-api-key
```

!!! warning
    Full authentication (login, TOTP, HTTPS) is planned for v0.7.0. Until then, restrict dashboard access at the network or reverse proxy level.

### CORS

Allow cross-origin requests from specific origins:

```toml
[server]
cors_allowed_origins = ["https://dashboard.example.com"]
```

Use `["*"]` to allow all origins (not recommended for production).

---

## Pi-hole Compatibility

Ferrous DNS can expose the Pi-hole v6 API at `/api/*`, making it a drop-in replacement for existing integrations (Gravity Sync, third-party dashboards, scripts):

```toml
[server]
pihole_compat = true
```

When `pihole_compat = true`:

- Pi-hole API is served at `/api/*`
- Ferrous DNS native API moves to `/ferrous/api/*`
- The frontend auto-detects the correct prefix via `/ferrous-config.js`

---

## PROXY Protocol v2

Enable real client IP detection when running behind a load balancer (HAProxy, AWS NLB, nginx):

```toml
[server]
proxy_protocol_enabled = true
```

!!! danger
    Only enable this when a trusted load balancer **always** sits in front. Without a load balancer, all TCP DNS connections will be rejected (the server expects the PROXY Protocol header on every connection).

---

## Encrypted DNS {#encrypted-dns}

Ferrous DNS can serve **DNS-over-TLS (DoT)** and **DNS-over-HTTPS (DoH)** directly to clients. Both require a TLS certificate and private key in PEM format.

```toml
[server.encrypted_dns]
dot_enabled   = true
dot_port      = 853
doh_enabled   = true
doh_port      = 443        # omit to co-host DoH on web_port
tls_cert_path = "/data/cert.pem"
tls_key_path  = "/data/key.pem"
```

| Option | Default | Description |
|:-------|:--------|:------------|
| `dot_enabled` | `false` | Enable DoT listener |
| `dot_port` | `853` | TCP port for DoT (RFC 7858 standard: 853) |
| `doh_enabled` | `false` | Enable DoH endpoint (`/dns-query`) |
| `doh_port` | — | Dedicated HTTPS port for DoH; omit to co-host on `web_port` |
| `tls_cert_path` | `/data/cert.pem` | Path to TLS certificate (PEM) |
| `tls_key_path` | `/data/key.pem` | Path to TLS private key (PEM) |

!!! note "Missing certificate"
    If the certificate files are absent at startup, the affected listeners are skipped with a warning. The server continues serving plain DNS normally.

### Generating a Self-Signed Certificate

```bash
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout key.pem -out cert.pem \
  -days 365 -subj "/CN=ferrous-dns"
```

For production, use [Let's Encrypt](https://letsencrypt.org/) or your CA.

### Client Configuration (DoT)

Configure your devices or router to use DoT:

```
DNS server: 192.168.1.100
Port: 853
Protocol: DNS-over-TLS
```

### Client Configuration (DoH)

Use the DoH endpoint with any compatible client:

```
https://192.168.1.100/dns-query
```

See [Encrypted DNS features](../features/encrypted-dns.md) for more details and client setup examples.
