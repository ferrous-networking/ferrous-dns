# Security Features

Ferrous DNS includes several security mechanisms to protect your network from DNS-based attacks and data exposure.

---

## Authentication

Ferrous DNS provides session-based authentication to protect the dashboard and REST API.

### First-Run Setup

On first launch (when no password is configured), Ferrous DNS shows a setup wizard. Set the admin password via the web UI or CLI before the server accepts API requests.

### Session-Based Login

Users authenticate with username and password via the login page. On success, a session cookie (`ferrous_session`) is issued.

```http
POST /api/auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "your-password"
}
```

| Option | Description |
|:-------|:------------|
| **Remember Me** | Extends session lifetime from `session_ttl_hours` (default 24h) to `remember_me_days` (default 30 days) |
| **Rate Limiting** | After `login_rate_limit_attempts` failed attempts (default 5), login is locked for `login_rate_limit_window_secs` (default 900s / 15 min) |

### Auth Guard

All API endpoints are protected by the auth guard middleware, except:

- `GET /api/auth/status` — check if auth is enabled
- `POST /api/auth/setup` — first-run password setup
- `POST /api/auth/login` — login
- `POST /api/auth/logout` — logout
- `GET /api/health` — health check

### Session Management

View and revoke active sessions from **Settings > Security** or via the API:

```http
GET /api/auth/sessions
DELETE /api/auth/sessions/{id}
```

### Password Change

Change the admin password from **Settings > Security** or via:

```http
POST /api/auth/change-password
Content-Type: application/json

{
  "current_password": "old-password",
  "new_password": "new-password"
}
```

### Background Cleanup

A `SessionCleanupJob` runs periodically to prune expired sessions from the database.

---

## API Tokens

Named API tokens provide programmatic access to the Ferrous DNS API without requiring a session login. Tokens are ideal for automation scripts, monitoring integrations, and third-party tools.

### Token Authentication

Include the token in the `X-Api-Key` header:

```http
X-Api-Key: your-api-token
```

API tokens and session cookies are both valid authentication methods. The auth guard accepts either.

### Token Management

```http
GET    /api/api-tokens          # List all tokens (only prefix shown)
POST   /api/api-tokens          # Create a new token
PUT    /api/api-tokens/{id}     # Update token name or key
DELETE /api/api-tokens/{id}     # Delete a token
```

!!! note "Token storage"
    Tokens are stored as SHA-256 hashes. The full token is only returned once at creation time — save it immediately.

### Import Custom Keys

You can import existing API keys (e.g., from a Pi-hole migration) via `PUT /api/api-tokens/{id}` with a custom key value.

---

## Auth Configuration

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

| Field | Type | Default | Description |
|:------|:-----|:--------|:------------|
| `enabled` | `bool` | `true` | Enable or disable authentication globally |
| `session_ttl_hours` | `int` | `24` | Default session lifetime in hours |
| `remember_me_days` | `int` | `30` | Extended session lifetime when "Remember Me" is checked |
| `login_rate_limit_attempts` | `int` | `5` | Max failed login attempts before lockout |
| `login_rate_limit_window_secs` | `int` | `900` | Duration of lockout window in seconds |
| `username` | `str` | `admin` | Admin username |
| `password_hash` | `str` | `""` | Argon2id password hash (set via setup wizard or CLI) |

!!! tip "Setting the password hash"
    Use the setup wizard on first run to set the password interactively. The Argon2id hash is written to the config file automatically.

See [Auth Configuration](../configuration/server.md#authentication) for full details.

---

## DNSSEC Validation

DNSSEC (DNS Security Extensions) validates that DNS responses are authentic and have not been tampered with in transit.

```toml
[dns]
dnssec_enabled = true
```

When enabled, Ferrous DNS validates DNSSEC signatures on all upstream responses. Queries that fail validation return `SERVFAIL`, preventing forged responses from reaching clients.

**Standards**: RFC 4035

!!! note "Performance impact"
    DNSSEC validation adds a small overhead on cache misses (signature verification). Cache hits have zero DNSSEC overhead. Disable with `dnssec_enabled = false` only for maximum-throughput benchmarking.

---

## DNS Rebinding Protection

DNS rebinding attacks trick browsers into making requests to internal network resources by returning private IP addresses for public domain names.

Ferrous DNS detects and blocks responses that would return RFC-1918 private addresses for publicly-registered domains.

!!! info "No configuration required"
    DNS rebinding protection is built-in and always active when blocking is enabled. There is no TOML option to configure — it engages automatically.

**Protected ranges**:
- `10.0.0.0/8`
- `172.16.0.0/12`
- `192.168.0.0/16`
- `169.254.0.0/16` (link-local)
- `127.0.0.0/8` (loopback)

When a rebinding attempt is detected, the response is blocked and logged.

---

## PTR Block for Private Ranges

Prevent information leakage via reverse DNS lookups on private IP ranges:

```toml
[dns]
block_private_ptr = true
```

When enabled, PTR queries for RFC-1918 addresses that are not in the local records are blocked. This prevents external DNS leakage of your internal network topology.

---

## Non-FQDN Query Blocking

Block DNS queries for names that are not fully qualified domain names (FQDNs):

```toml
[dns]
block_non_fqdn = true
```

Non-FQDN queries (e.g. `myserver` without a domain suffix) can expose internal network information when forwarded to external resolvers. Blocking them keeps internal names local.

---

## PROXY Protocol v2 {#proxy-protocol}

When Ferrous DNS is deployed behind a load balancer, PROXY Protocol v2 restores accurate client IPs for logging, client detection, and per-group policies:

```toml
[server]
proxy_protocol_enabled = true
```

**Supported load balancers**: HAProxy, AWS NLB, nginx (stream module), Traefik

!!! danger
    Only enable when a trusted load balancer **always** injects the PROXY header. Without a load balancer in front, all TCP connections will fail.

---

## HTTPS for Web UI {#https}

Ferrous DNS can serve the dashboard and REST API over HTTPS, encrypting all traffic between your browser and the server.

### How It Works

When HTTPS is enabled, the web server uses a single port (default `8080`) that automatically detects the protocol:

- **TLS connections** (browsers accessing `https://`) are served normally over HTTPS
- **Plain HTTP connections** receive a `301 Moved Permanently` redirect to `https://`

This means you never need to configure separate HTTP and HTTPS ports.

### Configuration

```toml title="ferrous-dns.toml"
[server.web_tls]
enabled       = false               # Enable HTTPS for the dashboard and API
tls_cert_path = "/data/cert.pem"    # Path to PEM certificate
tls_key_path  = "/data/key.pem"     # Path to PEM private key
```

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `enabled` | `bool` | `false` | Enable HTTPS for the web server |
| `tls_cert_path` | `str` | `/data/cert.pem` | Path to the PEM-encoded TLS certificate |
| `tls_key_path` | `str` | `/data/key.pem` | Path to the PEM-encoded TLS private key |

!!! note "Graceful fallback"
    If `enabled = true` but the certificate files are missing at startup, the server logs a warning and falls back to plain HTTP.

### Managing Certificates via the UI

Navigate to **Settings > Security > HTTPS / TLS** to:

- **Enable/disable** HTTPS with a toggle
- **View certificate status** — subject, expiration date, and validity
- **Upload certificates** — drag and drop PEM certificate and key files
- **Generate a self-signed certificate** — instant HTTPS with one click (browsers will show a security warning, but the connection is encrypted)

!!! tip "Quick setup"
    Click **Generate Self-Signed Certificate** for immediate HTTPS without needing external certificates. For production, use [Let's Encrypt](https://letsencrypt.org/) or your CA.

### TLS API Endpoints

```http
GET  /api/tls/status              # Certificate status (exists, valid, subject, expiration)
POST /api/tls/upload              # Upload cert + key (multipart/form-data)
POST /api/tls/generate?force=true # Generate self-signed certificate
```

!!! warning "Restart required"
    Changing HTTPS settings requires a server restart to take effect. The UI shows a "Restart Required" banner after saving.

---

## Encrypted DNS Transports

Encrypting DNS traffic prevents:

- **ISP surveillance** — your DNS queries are not visible to your ISP
- **Man-in-the-middle** attacks — responses cannot be forged in transit
- **DNS poisoning** — combined with DNSSEC for end-to-end verification

See [Encrypted DNS](encrypted-dns.md) for setup.

---

## Upcoming Security Features

The following are planned for future releases:

| Feature | Description |
|:--------|:------------|
| **TOTP / 2FA** | Time-based one-time passwords for login |
| **Rate Limiting** | Per-client DNS query rate limits |
| **DoS Protection** | Protection against DNS flooding |
| **DNS Tunneling Detection** | Detect DNS used as a covert data channel |
| **Entropy Analysis** | Detect DGA (Domain Generation Algorithm) malware |
| **Read-Only Mode** | Disable config changes via a flag |

---

## Current Security Posture

| Mechanism | Status |
|:----------|:-------|
| DNSSEC validation | Active |
| DNS rebinding protection | Active |
| Encrypted upstream (DoH/DoT/DoQ) | Active |
| Server-side DoT/DoH | Active |
| PROXY Protocol v2 | Active |
| Dashboard authentication | Active |
| API token authentication | Active |
| HTTPS dashboard | Active |
| TOTP / 2FA | Planned |
