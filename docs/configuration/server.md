# Server Configuration

The `[server]` section controls ports, bind address, API authentication, and encrypted DNS listeners.

---

## Basic Options

```toml
[server]
dns_port = 53
web_port = 8080
bind_address = "auto"
metrics_enabled = false
trusted_proxies = ["127.0.0.0/8", "::1/128"]
```

| Option | Default | Description |
|:-------|:--------|:------------|
| `dns_port` | `53` | UDP and TCP port for DNS queries |
| `web_port` | `8080` | HTTP/HTTPS port for the dashboard and REST API |
| `bind_address` | `auto` | Default address every listener binds to. `auto` serves IPv4 and IPv6 on every interface (see [Dual-stack](#dual-stack)), `0.0.0.0` serves IPv4 only, and a specific IP restricts access to it. Must be `auto` or an IP literal; a hostname is rejected at startup |
| `web_bind_address` | _(unset)_ | Address the dashboard and REST API bind to instead of `bind_address`. See [Dashboard on its own address](#web-bind-address) |
| `metrics_enabled` | `false` | Serve an unauthenticated Prometheus text-exposition endpoint at `/metrics` on the web port (opt-in) |
| `trusted_proxies` | `["127.0.0.0/8", "::1/128"]` | CIDRs (or single addresses) of reverse proxies whose `X-Forwarded-For` / `X-Real-IP` headers are believed on DoH requests. See [DoH client identity](#doh-client-identity) |

### Dual-stack (IPv4 + IPv6) {#dual-stack}

`bind_address = "auto"`, the default, makes every listener — Do53 (UDP and TCP), DoT, DoH, DoQ, and the web dashboard — serve IPv4 and IPv6 clients on a single dual-stack socket, unless it has a [bind address of its own](#per-listener-bind). A config file without the key, or no config file at all, gets the same:

```toml
[server]
bind_address = "auto"
```

`"auto"` binds `[::]` (a bare `"::"` works too; all three spellings listen the same way). Every listener opens it with `IPV6_V6ONLY` off, so IPv4 is served whatever the host's `net.ipv6.bindv6only` says. The config file, backups and `GET /ferrous/api/v1/config` keep saying `auto`.

`bind_address = "0.0.0.0"` serves IPv4 only, as it always has. A config that names it, such as the `ferrous-dns.toml` that older releases shipped and that every existing Docker volume holds, keeps listening on IPv4 until that line is changed to `"auto"`.

IPv4 clients arrive on the dual-stack socket in v4-mapped form (`::ffff:192.168.1.10`). Do53, DoT, DoQ and the web server normalise them back to plain IPv4 before anything client-facing sees them, so client groups, per-client rules, the per-IP connection limit, the query log and the [Pi-hole compatible API](../features/pihole-compat.md)'s sessions and `/api/info/client` key a device the same way whichever protocol it used. The same normalisation is applied to the address a PROXY protocol v2 header carries.

DoH is keyed by the socket peer too (canonicalised the same way), except when that peer is one of `trusted_proxies` — see [DoH client identity](#doh-client-identity).

!!! note "Upgrading from a release that stored mapped addresses"
    Earlier releases stored the v4-mapped form for DoT and DoQ clients, so a device could end up with two client rows. A migration runs once on first start and rewrites them: `::ffff:10.0.0.1` becomes `10.0.0.1`, a mapped row is merged into its plain twin (query counts add up, and a group assigned to the mapped row is kept unless the plain row already had one), the query log follows, and a subnet written as `::ffff:10.0.0.0/104` becomes `10.0.0.0/8`. Nothing needs to be done by hand.

!!! note "IPv6 must exist in the kernel"
    The DNS listeners — Do53 (UDP and TCP), DoT, and DoQ — are created as `AF_INET6` sockets with `IPV6_V6ONLY` off, even for an IPv4-only `bind_address` (which is bound in v4-mapped form). A kernel booted with `ipv6.disable=1` or built without `CONFIG_IPV6` cannot create them, and those listeners will fail to start. IPv6 does not need to be configured on the network — it only needs to be available in the kernel. The dedicated DoH listener and the web dashboard bind an IPv4 address as `AF_INET`, so with `bind_address = "0.0.0.0"` they still start there; `"auto"` and `"[::]"` are IPv6 addresses, so on such a kernel the server stops at startup.

### Per-listener bind addresses {#per-listener-bind}

Each encrypted-DNS listener can override `bind_address`, which is useful when the protocols should not all be exposed on the same interface:

```toml
[server]
bind_address = "0.0.0.0"            # Do53 and the dashboard stay on IPv4

[server.encrypted_dns]
dot_enabled      = true
dot_bind_address = "[::]"           # DoT is dual-stack
doq_enabled      = true
doq_bind_address = "192.168.1.10"   # DoQ only on the LAN address
```

Like `bind_address`, each override must be an IP literal. A hostname on a listener that is running (for DoH: `doh_enabled` with a `doh_port`) stops startup; on one that is off it is ignored with a warning in the log.

See [Encrypted DNS](#encrypted-dns) for the full list of options.

### Dashboard on its own address {#web-bind-address}

`web_bind_address` moves the dashboard and the REST API, over HTTP or HTTPS, off `bind_address`, while every DNS listener stays where it is. The usual case is a reverse proxy on the same host, or in Docker with host networking: DNS serves the network, and the web server listens on loopback only. In a container on a bridge network, loopback is the container's own, so a proxy in another container cannot reach it there: leave the key unset.

```toml
[server]
bind_address     = "auto"        # DNS for the network
web_bind_address = "127.0.0.1"   # dashboard and API for the local reverse proxy only
```

Unset, the web server binds `bind_address`, as before. Unlike `bind_address`, it must be an IP literal: `auto` is not accepted here.

Everything served on `web_port` moves with it: the [Pi-hole compatible API](../features/pihole-compat.md), `/metrics`, and DoH when it has no `doh_port` of its own. A Prometheus on another host then has to scrape through the proxy. `--bind` (`FERROUS_BIND_ADDRESS` in Docker) changes `bind_address` only. `--healthcheck` probes the web server at `web_bind_address`.

### DoH client identity {#doh-client-identity}

A DoH query to `/dns-query` is attributed to the address of the TCP connection it arrived on, and that address picks the client's group and per-client rules (unless the client queries `/dns-query/<ClientID>`, described below). When the connection comes from a reverse proxy listed in `trusted_proxies`, the proxy may name the real client instead:

- `X-Forwarded-For` is read right to left — every proxy appends the address it received the request from — and the first hop that is not itself a trusted proxy is the client. Hops further left were written by the client and are ignored.
- Without `X-Forwarded-For`, the trusted proxy's `X-Real-IP` is used.
- On `/dns-query` (without a `<ClientID>`), a request from any other peer is attributed to that peer, whatever headers it carries, so a client cannot spoof another device's IP address through forwarding headers.

The default trusts only loopback, which fits a reverse proxy on the same host. List the proxy's address when it runs elsewhere — for a Docker bridge network that is the proxy container's address or the bridge subnet:

```toml
[server]
trusted_proxies = ["127.0.0.0/8", "::1/128", "172.18.0.0/16"]
```

Setting the list replaces the default, so keep the loopback entries if the proxy can also connect locally. Trust only addresses you control: any peer inside the list can claim to be any client.

To identify roaming or NATed DoH devices independently of their IP address, clients can also query `/dns-query/<ClientID>` using an identifier registered on the **DoH IDs** page (`/doh-ids.html`). Group resolution evaluates the DoH Client ID first, then falls back to `client_ip` → subnet → `Protected`. By default (`doh_allow_unregistered_ids = false`), unknown Client IDs are rejected with `400 Bad Request`; setting `doh_allow_unregistered_ids = true` in `[server.encrypted_dns]` (or toggling **Allow Unregistered Client IDs** on the **DoH IDs** page) accepts valid unregistered IDs for Query Log attribution while applying the client IP's group rules. Because a registered `/dns-query/<ClientID>` URL acts as a bearer credential that selects its group's policy regardless of source IP, anyone who knows the URL gets that group's rules — prefer the generated random UUID v4 for groups with lighter filtering. See [DoH IDs](../features/client-management.md#doh-ids).

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
password_hash = ""                      # Argon2id hash (set via setup wizard; empty triggers it)
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

All API endpoints are protected except public auth routes (`/ferrous/api/v1/auth/status`, `/ferrous/api/v1/auth/setup`, `/ferrous/api/v1/auth/login`, `/ferrous/api/v1/auth/logout`, and the [second-factor and passkey login steps](../api.md#two-factor-authentication-totp)) and the [health check](../api.md#health-check) (`/ferrous/api/v1/health`).

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
- Ferrous DNS native API stays at `/ferrous/api/v1/*`, as in every mode

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

Ferrous DNS can serve **DNS-over-TLS (DoT)**, **DNS-over-HTTPS (DoH)**, and **DNS-over-QUIC (DoQ)** directly to clients. DoT and DoQ require a TLS certificate and private key in PEM format. DoH is served over plain HTTP for a TLS-terminating reverse proxy (or over `[server.web_tls]` when co-hosted on `web_port`), so it needs no certificate here.

```toml
[server.encrypted_dns]
dot_enabled   = true
dot_port      = 853
doh_enabled   = true
doh_port      = 443        # omit to co-host DoH on web_port
doq_enabled   = true
doq_port      = 853        # UDP port; no collision with dot_port (TCP)
tls_cert_path = "/data/cert.pem"
tls_key_path  = "/data/key.pem"
```

| Option | Default | Description |
|:-------|:--------|:------------|
| `dot_enabled` | `false` | Enable DoT listener |
| `dot_port` | `853` | TCP port for DoT (RFC 7858 standard: 853) |
| `dot_bind_address` | — | Address for the DoT listener; inherits `[server].bind_address` when omitted |
| `doh_enabled` | `false` | Enable DoH endpoints (`/dns-query` and `/dns-query/<ClientID>`) |
| `doh_port` | — | Dedicated plain-HTTP port for DoH (behind a reverse proxy); omit to co-host on `web_port` |
| `doh_bind_address` | — | Address for the dedicated DoH listener; ignored when `doh_port` is omitted, since `/dns-query` then binds wherever the dashboard does (`web_bind_address`, else `bind_address`) |
| `doh_allow_unregistered_ids` | `false` | When `false`, requests to `/dns-query/<ClientID>` with an unregistered ID return `400 Bad Request`; when `true`, valid unregistered IDs are accepted for Query Log attribution and fall back to the client IP's group rules |
| `doq_enabled` | `false` | Enable DoQ listener |
| `doq_port` | `853` | UDP port for DoQ (RFC 9250 standard: 853) |
| `doq_bind_address` | — | Address for the DoQ listener; inherits `[server].bind_address` when omitted |
| `tls_cert_path` | `/data/cert.pem` | Path to the DoT/DoQ TLS certificate (PEM) |
| `tls_key_path` | `/data/key.pem` | Path to the DoT/DoQ TLS private key (PEM) |

!!! note "Missing certificate"
    If the certificate files are absent at startup, DoT and DoQ are skipped with a warning. DoH and plain DNS start normally.

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
