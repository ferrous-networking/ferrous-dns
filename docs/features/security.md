# Security Features

Ferrous DNS includes several security mechanisms to protect your network from DNS-based attacks and data exposure.

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

## Encrypted DNS Transports

Encrypting DNS traffic prevents:

- **ISP surveillance** — your DNS queries are not visible to your ISP
- **Man-in-the-middle** attacks — responses cannot be forged in transit
- **DNS poisoning** — combined with DNSSEC for end-to-end verification

See [Encrypted DNS](encrypted-dns.md) for setup.

---

## Upcoming Security Features (v0.7.0)

The following are planned for v0.7.0:

| Feature | Description |
|:--------|:------------|
| **Authentication** | Login with username/password for the dashboard |
| **HTTPS for Web UI** | TLS for the dashboard and REST API |
| **API Keys / Tokens** | Per-application API tokens |
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
| Dashboard authentication | Planned (v0.7.0) |
| API key authentication | Partial (static key) |
| TOTP / 2FA | Planned (v0.7.0) |
| HTTPS dashboard | Planned (v0.7.0) |

!!! warning "Dashboard access"
    Until v0.7.0 ships authentication, restrict dashboard access at the network level (firewall rule, VPN, or reverse proxy with HTTP basic auth).
