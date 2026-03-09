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
| `web_port` | `8080` | HTTP/HTTPS port for the dashboard and REST API |
| `bind_address` | `0.0.0.0` | Network interface to bind to. Use a specific IP to restrict access |

---

## Authentication {#authentication}

Ferrous DNS supports session-based authentication and API tokens to protect the dashboard and REST API.

### Enabling Authentication

```toml title="ferrous-dns.toml"
[auth]
enabled = true                          # Enable authentication globally
session_ttl_hours = 24                  # Session lifetime without "Remember Me"
remember_me_days = 30                   # Session lifetime with "Remember Me"
login_rate_limit_attempts = 5           # Max failed attempts before lockout
login_rate_limit_window_secs = 900      # Lockout window (15 min)

[auth.admin]
username = "admin"                      # Admin username
password_hash = ""                      # Argon2id hash (set via setup wizard or CLI)
```

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `enabled` | `bool` | `true` | Enable or disable authentication globally |
| `session_ttl_hours` | `int` | `24` | Default session lifetime in hours |
| `remember_me_days` | `int` | `30` | Extended session lifetime with "Remember Me" |
| `login_rate_limit_attempts` | `int` | `5` | Max failed login attempts before lockout |
| `login_rate_limit_window_secs` | `int` | `900` | Lockout window duration in seconds |
| `username` | `str` | `admin` | Admin username |
| `password_hash` | `str` | `""` | Argon2id password hash |

### First-Run Setup

When `password_hash` is empty, Ferrous DNS shows a setup wizard on the dashboard. Set the admin password via the web UI — the Argon2id hash is written to the config file automatically.

### Session Authentication

Users log in with username and password. A `ferrous_session` cookie is set on success. The "Remember Me" option extends the session from `session_ttl_hours` to `remember_me_days`.

### API Token Authentication

API tokens provide programmatic access via the `X-Api-Key` header. Tokens are managed through the REST API or the dashboard under **Settings > Security**. See [API Tokens](../api.md#api-tokens) for endpoint details.

### Auth Guard

All API endpoints are protected except public auth routes (`/api/auth/status`, `/api/auth/setup`, `/api/auth/login`, `/api/auth/logout`) and the health check (`/api/health`).

!!! info "Background cleanup"
    A background task runs periodically to prune expired sessions from the database.

### CORS

Allow cross-origin requests from specific origins:

```toml
[server]
cors_allowed_origins = ["https://dashboard.example.com"]
```

Use `["*"]` to allow all origins (not recommended for production).

---

## HTTPS (Web TLS) {#web-tls}

Serve the dashboard and REST API over HTTPS. When enabled, the same `web_port` handles both HTTPS and plain HTTP (with automatic redirect to HTTPS).

```toml title="ferrous-dns.toml"
[server.web_tls]
enabled       = false               # Enable HTTPS
tls_cert_path = "/data/cert.pem"    # PEM certificate path
tls_key_path  = "/data/key.pem"     # PEM private key path
```

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `enabled` | `bool` | `false` | Enable HTTPS for the web server |
| `tls_cert_path` | `str` | `/data/cert.pem` | Path to the PEM-encoded TLS certificate |
| `tls_key_path` | `str` | `/data/key.pem` | Path to the PEM-encoded TLS private key |

!!! tip "Quick setup"
    You can generate a self-signed certificate directly from the UI under **Settings > Security > HTTPS / TLS** — no command-line tools needed.

!!! note "Graceful fallback"
    If `enabled = true` but certificate files are missing, the server logs a warning and falls back to plain HTTP.

See [HTTPS for Web UI](../features/security.md#https) for full details, API endpoints, and UI management.

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

```text
DNS server: 192.168.1.100
Port: 853
Protocol: DNS-over-TLS
```

### Client Configuration (DoH)

Use the DoH endpoint with any compatible client:

```text
https://192.168.1.100/dns-query
```

See [Encrypted DNS features](../features/encrypted-dns.md) for more details and client setup examples.
