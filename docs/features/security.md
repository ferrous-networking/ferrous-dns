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

A background task runs periodically to prune expired sessions from the database.

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

## DNS Rate Limiting {#rate-limiting}

Ferrous DNS includes a token-bucket rate limiter that throttles abusive clients per subnet, protecting the server from query floods without affecting legitimate traffic.

### How It Works

Each client subnet (default `/24` for IPv4, `/48` for IPv6) gets an independent token bucket. Tokens refill at the configured `queries_per_second` rate, up to the `burst_size` capacity. When a subnet exhausts its tokens, queries are either **refused** (`REFUSED` response code) or **slipped** (`TC=1` truncated response forcing a TCP retry).

### Configuration

```toml title="ferrous-dns.toml"
[dns.rate_limit]
enabled                    = true
queries_per_second         = 1000     # sustained QPS per subnet
burst_size                 = 500      # token bucket capacity
ipv4_prefix_len            = 24       # /24 groups the home LAN
ipv6_prefix_len            = 48       # /48 standard home delegation
whitelist                  = ["127.0.0.0/8", "::1/128", "10.0.0.0/8"]
nxdomain_per_second        = 50       # separate stricter budget for NXDOMAIN
slip_ratio                 = 2        # every 2nd rate-limited response is TC=1
dry_run                    = false    # true = log only, don't refuse
stale_entry_ttl_secs       = 300      # evict idle subnet buckets after 5 min
```

| Option | Default | Description |
|:-------|:--------|:------------|
| `enabled` | `false` | Master switch for rate limiting |
| `queries_per_second` | `1000` | Sustained token refill rate per subnet |
| `burst_size` | `500` | Maximum tokens (allows short bursts above QPS) |
| `ipv4_prefix_len` | `24` | IPv4 subnet grouping prefix length |
| `ipv6_prefix_len` | `48` | IPv6 subnet grouping prefix length |
| `whitelist` | `[]` | CIDRs that bypass rate limiting entirely |
| `nxdomain_per_second` | `50` | Separate, stricter budget for NXDOMAIN responses |
| `slip_ratio` | `0` | Every Nth rate-limited response sends TC=1 instead of REFUSED. 0 = disabled |
| `dry_run` | `false` | Log rate-limit events without refusing queries |
| `stale_entry_ttl_secs` | `300` | Seconds before an idle subnet bucket is evicted |

### TC=1 Slip Mechanism

When `slip_ratio` is set (e.g. `2`), every Nth rate-limited UDP response is sent as a **truncated** response (`TC=1` flag set) instead of `REFUSED`. This forces the client to retry over TCP, which:

- Verifies the client is a legitimate resolver (not a spoofed-source flood)
- Allows real clients to still get answers via TCP even when rate-limited on UDP
- Follows the same approach used by NSD and BIND

### NXDOMAIN Budget

The `nxdomain_per_second` setting provides a separate, stricter budget for NXDOMAIN responses. This catches malware and IoT devices that probe many random subdomains while leaving the general query budget unaffected.

### Dry-Run Mode

Set `dry_run = true` to log rate-limit events without actually refusing queries. This is useful for calibrating thresholds before enforcing limits in production. Rate-limited queries appear in the query log with status `RATE_LIMITED` and in the dashboard stats.

!!! tip "Recommended first deployment"
    Enable rate limiting with `dry_run = true` for 24-48 hours. Check the dashboard for false positives, then switch to `dry_run = false` once thresholds are validated.

---

## TCP/DoT Connection Limiting {#connection-limiting}

Per-IP connection limits protect against TCP and DoT connection exhaustion:

```toml title="ferrous-dns.toml"
[dns.rate_limit]
tcp_max_connections_per_ip = 30    # max concurrent TCP DNS connections per IP
dot_max_connections_per_ip = 15    # max concurrent DoT connections per IP
```

| Option | Default | Description |
|:-------|:--------|:------------|
| `tcp_max_connections_per_ip` | `30` | Max concurrent TCP connections per IP. 0 = unlimited |
| `dot_max_connections_per_ip` | `15` | Max concurrent DoT connections per IP. 0 = unlimited |

Connections that exceed the limit are immediately closed. The connection counter is automatically decremented when a connection closes, preventing resource leaks.

---

## Upcoming Security Features

The following are planned for future releases:

| Feature | Description |
|:--------|:------------|
| **TOTP / 2FA** | Time-based one-time passwords for login |
| **DNS Tunneling Detection** | Detect DNS used as a covert data channel |
| **Entropy Analysis** | Detect DGA (Domain Generation Algorithm) malware |
| **Read-Only Mode** | Disable config changes via a flag |

---

## Current Security Posture

| Mechanism | Status |
|:----------|:-------|
| DNSSEC validation | :white_check_mark: Active |
| DNS rebinding protection | :white_check_mark: Active |
| Encrypted upstream (DoH/DoT/DoQ) | :white_check_mark: Active |
| Server-side DoT/DoH | :white_check_mark: Active |
| PROXY Protocol v2 | :white_check_mark: Active |
| Dashboard authentication | :white_check_mark: Active |
| API token authentication | :white_check_mark: Active |
| HTTPS dashboard | :white_check_mark: Active |
| DNS rate limiting | :white_check_mark: Active |
| TCP/DoT connection limiting | :white_check_mark: Active |
| TOTP / 2FA | :material-clock-outline: Planned |
