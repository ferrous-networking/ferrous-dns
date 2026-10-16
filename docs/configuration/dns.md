# DNS & Upstream Configuration

The `[dns]` section controls upstream resolution, DNSSEC, local records, and upstream pool management.

---

## Basic DNS Options

```toml
[dns]
upstream_servers = []
query_timeout = 3
default_strategy = "Parallel"
dnssec_mode = "Permissive"
block_private_ptr = true
block_non_fqdn = false
mdns_enabled = false              # passive mDNS/Bonjour listener on UDP 5353
# local_domain = "lan"            # optional — no default
local_dns_server = "10.0.0.1:53"
```

| Option | Default | Description |
|:-------|:--------|:------------|
| `upstream_servers` | `[]` | Fallback upstreams when no pool matches (same URL format as pools) |
| `query_timeout` | `3` | Seconds to wait for an upstream response |
| `default_strategy` | `"Parallel"` | Default strategy for `upstream_servers`: `"Parallel"`, `"Balanced"`, or `"Failover"` |
| `dnssec_mode` | `"Permissive"` | DNSSEC enforcement: `"Off"`, `"Permissive"`, or `"Strict"` (see [DNSSEC](#dnssec)) |
| `dnssec_trust_anchor_file` | — | Path to a trust anchor file replacing the embedded IANA root anchors (see [Trust anchors](#trust-anchors)) |
| `block_private_ptr` | `true` | Block PTR lookups for private/RFC-1918 IP ranges, except reverse zones a [conditional pool](#conditional-forwarding) answers |
| `block_non_fqdn` | `false` | Block queries for non-fully-qualified domain names |
| `local_domain` | — | Local domain: short hostnames are qualified with it, and names under it are answered by local records or `local_dns_server`, never the upstream pools; a [conditional pool](#conditional-forwarding) for the same names takes precedence |
| `local_dns_server` | — | Router/DHCP server used for PTR lookups, client hostname resolution, names under `local_domain`, and to look up the hostnames in upstream URLs: `IP:port`, or a bare IP for port 53. A hostname in the file is ignored with a warning, leaving local forwarding off; the API rejects it |
| `mdns_enabled` | `false` | Enable the passive mDNS/Bonjour listener (UDP 5353 multicast) for device discovery. In Docker this needs host networking — see [Installation](../getting-started/installation.md#docker) |
| `malware_detection_enabled` | `true` | Master switch for the five [malware detectors](../features/malware-detection.md): when `false`, none runs, whatever its own `enabled` says. Also in **Settings → Malware Detection** |
| `rebinding_protection_enabled` | `true` | Block public domains that resolve to private/RFC-1918 (or IPv6 ULA/link-local) addresses — see [DNS Rebinding Protection](../features/malware-detection.md#dns-rebinding-protection) |
| `rebinding_allowlist` | `[]` | Exact domain names exempt from rebinding protection regardless of resolved IP (split-horizon DNS); a wildcard or a trailing dot never matches and is rejected |
| `qname_case_randomization` | `false` | Randomize QNAME letter case on upstream queries of every record type (draft-vixie-dns-0x20) for extra anti-spoofing entropy; off by default because some upstreams/forwarders normalize case and would fail validation. DNS Cookies are always on regardless of this flag |

---

## Upstream URL Formats

Ferrous DNS supports all major DNS transport protocols:

| Protocol | URL Format | Example |
|:---------|:-----------|:--------|
| Plain UDP | `udp://host:port` | `udp://8.8.8.8:53` |
| Plain TCP | `tcp://host:port` | `tcp://8.8.8.8:53` |
| DNS-over-HTTPS | `https://host[:port]/path` | `https://cloudflare-dns.com/dns-query` |
| DNS-over-TLS | `tls://host:port` | `tls://1.1.1.1:853` |
| DNS-over-QUIC | `doq://host:port` | `doq://dns.adguard-dns.com:853` |
| HTTP/3 | `h3://host[:port]/path` | `h3://dns.google/dns-query` |

Every protocol takes a hostname or an IP address. `udp://`, `tcp://`, `tls://` and `doq://` need a port; DoH and HTTP/3 URLs default to 443. A bare `IP:PORT` is plain UDP, and an IPv6 address goes in brackets (`doq://[2a10:50c0::ad1:ff]:853`, `https://[2606:4700:4700::1111]/dns-query`).

```toml
servers = [
    "doq://dns.adguard-dns.com:853",   # looked up at startup and when pools are saved
    "https://dns.google/dns-query",
]
```

Upstream Management covers [hostname or IP](../features/upstream-management.md#hostname-or-ip), [AdGuard's `quic://` addresses](../features/upstream-management.md#from-adguard), and [how hostnames are resolved](../features/upstream-management.md#hostname-resolution).

---

## Upstream Pools {#upstream-pools}

Pools group upstream servers with a resolution strategy. Multiple pools can be defined with different priorities.

```toml
[[dns.pools]]
name = "primary"
strategy = "Parallel"
priority = 1
servers = [
    "doq://dns.adguard-dns.com:853",
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
]

[[dns.pools]]
name = "fallback"
strategy = "Failover"
priority = 2
servers = [
    "udp://8.8.8.8:53",
    "udp://1.1.1.1:53",
]
```

| Option | Description |
|:-------|:------------|
| `name` | Unique pool identifier |
| `strategy` | Resolution strategy (see below) |
| `priority` | Lower number = higher priority. The highest-priority healthy pool is used |
| `servers` | List of upstream servers (URL format) |
| `domains` | Domains this pool answers, with every name under them — a [conditional pool](#conditional-forwarding). Leave out for a default pool |
| `groups` | Client group ids the pool's `domains` are routed for. Leave out to route them for every client |
| `internal` | `true` for an unsigned internal zone: its answers skip DNSSEC validation and rebinding protection |

A pool with `domains` is skipped for every other name, so at least one pool must have no `domains`.

### Strategies

| Strategy | Behavior |
|:---------|:---------|
| `"Parallel"` | Queries all upstreams simultaneously, returns the fastest response. Best latency. |
| `"Balanced"` | Round-robin across healthy upstreams. Best load distribution. |
| `"Failover"` | Uses the first upstream; fails over to the next only on error. |

!!! tip "Recommended setup"
    Use `"Parallel"` with DoQ/DoH upstreams for lowest cache-miss latency. Add a `"Failover"` pool with plain UDP as a lower-priority fallback.

---

## Health Checks {#health-checks}

Ferrous DNS continuously monitors upstream health and routes around failed servers:

```toml
[dns.health_check]
interval = 30           # Seconds between health check probes
timeout = 2000          # Milliseconds to wait for a health response
failure_threshold = 3   # Consecutive failures before marking unhealthy
success_threshold = 2   # Consecutive successes to restore a server
```

A server is temporarily excluded from rotation when `failure_threshold` consecutive checks fail, and restored after `success_threshold` consecutive successes.

Each check asks a server for `google.com`. A [conditional pool](#conditional-forwarding)'s servers are asked for the SOA of the pool's first domain instead, so an internal server that answers only its own zone and refuses everything else is not marked down.

---

## Local DNS Records {#local-records}

Define static A/AAAA records served directly by Ferrous DNS, bypassing upstream resolution:

```toml
[[dns.local_records]]
hostname = "router"
domain = "local"
ip = "192.168.1.1"
record_type = "A"
ttl = 300

[[dns.local_records]]
hostname = "nas"
domain = "local"
ip = "192.168.1.50"
record_type = "A"
ttl = 300

# IPv6
[[dns.local_records]]
hostname = "server"
domain = "local"
ip = "fd00::1"
record_type = "AAAA"
ttl = 300
```

| Field | Description |
|:------|:------------|
| `hostname` | Short hostname (without domain) |
| `domain` | Domain suffix — full name is `hostname.domain` |
| `ip` | IPv4 or IPv6 address literal |
| `record_type` | `"A"` for IPv4, `"AAAA"` for IPv6 (case-insensitive) |
| `ttl` | Time-to-live in seconds (default `300`) |

Each record is checked when the file is loaded: a record whose `ip` is not an
address literal, whose `record_type` is not `A`/`AAAA`, or whose address is of
the wrong family (`A` with an IPv6 address, `AAAA` with an IPv4 one) is skipped
with a warning naming it, and the other records still load. The API rejects the
same mistakes with a `400`.

Several records may share a name and type, or an address. The last one in the
list answers, and deleting or editing one of them hands the name (or the PTR)
to the next remaining record rather than dropping it.

An exact local name stays local even when the requested record type is not
configured. For example, an `AAAA` query for the A-only `router.local` above
returns **NODATA** (`NOERROR` with an empty answer): the name exists, but has no
IPv6 address. It is not forwarded upstream or filled by a covering wildcard.
Adding or removing a record type takes effect immediately; removing the last
local address record restores normal resolution for the name.

### Wildcard Records

Set `hostname` to `*` to answer for every subdomain of `domain`, instead of
listing them one by one:

```toml
[[dns.local_records]]
hostname = "*"
domain = "home.lan"
ip = "192.168.1.10"
record_type = "A"
ttl = 300
```

`anything.home.lan` and `deeper.still.home.lan` both resolve to `192.168.1.10`.

The rules:

- **The domain itself is not covered.** `*.home.lan` does not answer for
  `home.lan` (RFC 4592). Add an exact record for the apex if you need one.
- **An exact record wins.** With both `*.home.lan → 192.168.1.10` and
  `nas.home.lan → 192.168.1.50`, a query for `nas.home.lan` gets `192.168.1.50`.
- **The most specific wildcard wins.** `*.dev.home.lan` beats `*.home.lan` for
  `api.dev.home.lan`.
- **A type the wildcard does not carry is answered as NODATA** — an empty
  `NOERROR`, not a query sent upstream. With only an A record defined, an `AAAA`
  for `anything.home.lan` returns no answer instead of leaking the internal name
  to your upstream resolver.
- **Wildcards are matched before the cache and never cached**, so adding or
  deleting one from the dashboard takes effect on the next query.
- **No PTR is generated.** A wildcard has no single name for an address to
  reverse to, so [Auto PTR Generation](#local-records) skips it.
- `*` is accepted only as the leftmost label: `*` or `*.dev` in `hostname`, never
  inside `domain`. Anything else is rejected with a `400`.

A wildcard needs something to anchor it: set `domain`, or a global
`dns.local_domain`. A bare `*` with neither is refused rather than stored as a
record that would cover every query.

### Auto PTR Generation

When you define a local A or AAAA record, Ferrous DNS automatically creates a PTR record. For example, `server.local → 192.168.1.100` also creates `100.1.168.192.in-addr.arpa → server.local`.

This means reverse DNS lookups work without any extra configuration, including for records added from the dashboard while the server runs — even when none were configured at startup.

---

## Conditional Forwarding

Queries for chosen domains can go to their own upstream pool (an office DNS server, an Active Directory domain controller, a national resolver) while every other query follows the default pools. List the domains in the pool:

```toml
[[dns.pools]]
name     = "gov"
strategy = "Failover"
servers  = ["udp://195.208.4.1:53", "udp://195.208.5.1:53"]
domains  = ["ru", "рф", "su"]

[[dns.pools]]
name     = "office-a"
strategy = "Failover"
servers  = ["udp://10.1.0.10:53"]
domains  = ["corp.example", "1.10.in-addr.arpa"]
groups   = [3]          # Clients > Groups: the group's id
internal = true
```

- **Which names.** A pool with `domains` answers those domains and every name under them, and is never asked anything else. The most specific domain wins: with pools for `example` and `corp.example`, `a.corp.example` goes to the second. Domains can be written in Unicode (`рф`) or punycode (`xn--p1ai`), and reverse zones such as `1.10.in-addr.arpa` work too. At least one pool must have no `domains`.
- **Which clients.** `groups` limits the pool to clients in those groups; leave it out to apply the pool to every client. For the same domain, a pool for the client's group wins over a pool for every client. Each group's answers are cached apart, so one group never receives another group's answer. A group a pool routes for cannot be deleted until it is removed from the pool.
- **No fallback.** When the pool cannot answer, the client gets `SERVFAIL`. The query is never retried on the default pools, so internal names do not leak to public resolvers and a national zone is never resolved anywhere else.
- **Health checks.** The pool's servers are checked with a query for its first domain, not `google.com`, so a server that answers only its own zone stays healthy. A pool whose servers are all marked down still asks them, as the default pools do.
- **DNSSEC and rebinding.** Both apply as usual, which is what a public zone such as a ccTLD needs; its DS and DNSKEY lookups go through the same pool. For an internal, unsigned zone, set `internal = true`. Its answers then skip DNSSEC validation, so they resolve under `dnssec_mode = "Strict"`, are exempt from [DNS rebinding protection](../features/malware-detection.md#dns-rebinding-protection), and show as Local DNS in the query log, like `local_dns_server` answers.
- **Precedence.** Local records answer first. A conditional pool beats `local_domain`, the private-range PTRs sent to `local_dns_server`, and `block_private_ptr`.

In the dashboard, the fields are **Domains**, **Client groups** and **Internal zone** on each pool under **Settings > DNS Advanced > Upstream DNS Pools**. Changes apply without a restart. When the routing changes, the DNS cache is cleared, so answers cached under the old routing are not served. A group id the pool names but that no longer exists, for example one written by hand in the TOML file, shows as **Group N (deleted)**; uncheck it before saving the pool.

!!! note "DNSSEC in group pools"
    DS and DNSKEY lookups follow only pools that apply to every client. A group pool that keeps validation on has its chain of trust fetched through those pools or the default ones. Internal zones set `internal = true`, so they are not affected.

### One domain through `local_domain`

`local_domain` plus `local_dns_server` still route a single LAN domain to your router, for every client:

```toml
[dns]
local_domain     = "corp.internal"
local_dns_server = "10.0.0.10:53"   # AD / internal DNS server
```

Besides forwarding `corp.internal` and every name under it, this qualifies single-label names (`fileserver` becomes `fileserver.corp.internal`, unless `block_non_fqdn` is on) and sends private-range PTRs to the same server. A conditional pool does neither. When that server answers NXDOMAIN, fails or does not answer, the client gets NXDOMAIN; the name is not retried upstream. Its answers skip DNSSEC validation and rebinding protection. In the dashboard both are under **Settings > DNS Settings** (**Block local domain from internet** and **Local DNS server**); a change applies after a restart.

!!! warning "Don't use `local_domain` for a public zone"
    Setting `local_domain` to a TLD such as `ru` turns off DNSSEC validation and rebinding protection for the whole TLD, and sends every single-label name to that server. Use a conditional pool instead.

---

## DNSSEC

Ferrous DNS validates DNSSEC signatures (chain of trust from the root KSK, RSA/ECDSA/Ed25519) on upstream responses. The `dnssec_mode` setting controls how the validation result is applied:

| Mode | DO bit / validation | Bogus / Indeterminate result | AD bit |
|------|---------------------|------------------------------|--------|
| `"Off"` | Not requested | — | never set |
| `"Permissive"` (default) | Requested + validated | served, tagged in the query log | set on `Secure` |
| `"Strict"` | Requested + validated | rejected with `SERVFAIL` + EDE 6 (Bogus) or EDE 5 (Indeterminate) | set on `Secure` |

- **AD bit** (Authenticated Data, RFC 6840): set only when a response validates as `Secure` and the client did not set the CD bit.
- **CD bit** (Checking Disabled, RFC 4035): when a client sets CD, enforcement is skipped for that query so the client can perform its own validation — Strict mode will not `SERVFAIL` it.
- **Fail-closed**: `Insecure` is served only when a signed proof shows the name sits below an unsigned delegation. An answer stripped of its signatures or its denial proof is `Bogus`, and a chain that could not be fetched (timeouts, unreachable upstream) is `Indeterminate`; Strict rejects both. Neither is cached, so the next query revalidates.
- **Upstreams must pass DNSSEC records through.** A forwarder that drops RRSIG/NSEC/NSEC3 (some home routers do) makes signed names `Bogus`. `ds_denials_unproven` at `GET /api/dnssec/stats` counts that case; watch it under `Permissive` before switching to `Strict`.
- **Conditional pools.** Answers from a [conditional pool](#conditional-forwarding) marked `internal = true` are not validated. DS and DNSKEY lookups follow conditional pools for every client, so a national zone routed to its own resolvers is validated through them.

```toml title="ferrous-dns.toml"
[dns]
dnssec_mode = "Strict"   # SERVFAIL on Bogus or Indeterminate; "Permissive" validates without rejecting; "Off" disables
```

!!! note
    DNSSEC validation adds a small latency overhead on cache misses (extra DNSKEY/DS lookups, cached per zone). For maximum throughput benchmarking, you can disable it: `dnssec_mode = "Off"`.

!!! tip "Backward compatibility"
    The legacy `dnssec_enabled = true/false` flag is still accepted (mapping to `Permissive`/`Off`) when `dnssec_mode` is absent, but `dnssec_mode` is the source of truth.

### Trust anchors {#trust-anchors}

Validation starts from the root key-signing key. Ferrous DNS embeds the IANA root trust anchors (`root-anchors.xml`) in the binary — **both** that are currently valid: KSK-2017 (key tag 20326), which signs the root today, and KSK-2024 (key tag 38696), scheduled to take over signing on **2026-10-11**. Shipping both means the rollover needs no action from you.

To pin your own set instead, point `dnssec_trust_anchor_file` at a file in DNS presentation format:

```toml title="ferrous-dns.toml"
[dns]
dnssec_trust_anchor_file = "/etc/ferrous-dns/root.key"
```

The file takes `DS` and `DNSKEY` records, one per line, with `;` comments — the format written by `unbound-anchor -a /etc/ferrous-dns/root.key` and shipped by the `dns-root-data` package as `root.key` / `root.ds`:

```
; the two current IANA root anchors, in DS form
. IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
. IN DS 38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16
```

Behaviour worth knowing:

- The file **replaces** the embedded anchors rather than adding to them, so you can retire an anchor and not only introduce one. List every anchor you want trusted.
- A configured file that cannot be read or parsed **aborts startup**. Falling back to the embedded set would leave you believing you had replaced the trust root when you had not. So does a file with no anchor for the root zone `.`: validation walks down from the root, so without one nothing could validate.
- The path is read once at startup. It is deliberately not exposed through the REST API or the web UI, and is not part of a configuration backup, since it names a host path.
- Startup logs the count and the source: `DNSSEC trust anchors loaded count=2 source=embedded`.

!!! warning "Rollover early warning"
    On every root DNSKEY refresh, Ferrous DNS compares the live root key-signing keys against your anchors and warns about any KSK no anchor covers:

    ```
    WARN Root zone publishes a KSK that no configured trust anchor covers;
         DNSSEC validation will break once the root signs with it —
         update the trust anchors key_tag=38696 algorithm=8
    ```

    Treat it as urgent: validation keeps working until the root starts signing with that key, and then fails for every signed zone. Automatic RFC 5011 anchor rollover is not implemented yet, so the update is manual — or arrives with a release that refreshes the embedded set.

---

## Rate Limiting {#rate-limiting}

Token-bucket rate limiting per client subnet protects against query floods and DoS attacks.

```toml
[dns.rate_limit]
enabled                    = true
queries_per_second         = 1000
burst_size                 = 500
ipv4_prefix_len            = 24
ipv6_prefix_len            = 48
whitelist                  = ["127.0.0.0/8", "::1/128", "10.0.0.0/8"]
nxdomain_per_second        = 50
slip_ratio                 = 2
dry_run                    = false
stale_entry_ttl_secs       = 300
tcp_max_connections_per_ip = 30
dot_max_connections_per_ip = 15
doq_max_connections_per_ip = 15
```

| Option | Default | Description |
|:-------|:--------|:------------|
| `enabled` | `false` | Master switch — `false` disables all rate limiting with zero overhead |
| `queries_per_second` | `1000` | Sustained token refill rate per subnet per second |
| `burst_size` | `500` | Token bucket capacity — allows short bursts above `queries_per_second` |
| `ipv4_prefix_len` | `24` | IPv4 prefix length for subnet grouping (e.g. 24 = /24) |
| `ipv6_prefix_len` | `48` | IPv6 prefix length for subnet grouping (e.g. 48 = /48) |
| `whitelist` | `[]` | CIDRs that bypass rate limiting entirely |
| `nxdomain_per_second` | `50` | Separate, stricter budget for NXDOMAIN answers per subnet; only an NXDOMAIN answer over it is limited, never the subnet's other queries. `local_dns_server` answers are not charged. 0 = no NXDOMAIN budget |
| `slip_ratio` | `0` | Every Nth rate-limited UDP response sends TC=1 (forcing TCP retry). 0 = disabled |
| `dry_run` | `false` | Log rate-limit events without refusing queries |
| `stale_entry_ttl_secs` | `300` | Seconds before an idle subnet bucket is evicted from memory |
| `tcp_max_connections_per_ip` | `30` | Max concurrent TCP DNS connections per IP. 0 = unlimited |
| `dot_max_connections_per_ip` | `15` | Max concurrent DoT connections per IP. 0 = unlimited |
| `doq_max_connections_per_ip` | `15` | Max concurrent DoQ connections per IP. 0 = unlimited |

!!! tip "Tuning for your network"
    For a typical household (~100 devices), the defaults work well. The `whitelist` should include your local networks to avoid rate-limiting internal traffic. Use `dry_run = true` to validate thresholds before enforcing.

See [Security > Rate Limiting](../features/security.md#rate-limiting) for detailed explanations of each feature.

---

## Supported Record Types

Ferrous DNS supports all common DNS record types per RFC 1035:

| Type | Description |
|:-----|:------------|
| `A` | IPv4 address |
| `AAAA` | IPv6 address |
| `CNAME` | Canonical name |
| `MX` | Mail exchanger |
| `TXT` | Text record |
| `PTR` | Reverse DNS |
| `NS` | Name server |
| `SRV` | Service locator |

---

## Local DNS Server {#local-dns-server}

```toml
[dns]
local_dns_server = "192.168.1.1:53"
```

`local_dns_server` points to your router or DHCP server. Ferrous DNS uses it for three distinct purposes. In the dashboard it is **Settings > DNS Settings > Local DNS server**; a change applies after a restart.

To send more than one domain, or a domain per client group, to an internal server, use a [conditional pool](#conditional-forwarding).

!!! note "Answers from the router are validated"
    Queries to `local_dns_server` get the same anti-spoofing as upstream pools: the answer must come from the router's address and match the transaction ID, the question and the DNS Cookie, and a truncated answer is retried over TCP. With `qname_case_randomization = true` the query name's case is randomized here too — if your router rewrites the case of names, every answer fails that check and the log shows `Local DNS server query failed`; turn 0x20 off in that case. See [Security Hardening](../features/security-hardening.md#upstream-response-validation).

---

### 1. PTR Lookups — Reverse DNS for Clients

When a client queries Ferrous DNS, the server knows the client's IP address. To display a human-readable hostname in the dashboard, logs, and per-client group matching, Ferrous DNS issues a PTR (reverse DNS) lookup for that IP.

```text
Client IP: 192.168.1.42
         │
         ▼
Ferrous DNS sends: PTR 42.1.168.192.in-addr.arpa → local_dns_server
         │
         ▼
Router responds:   "desktop-work.lan"
         │
         ▼
Dashboard shows:   desktop-work.lan (192.168.1.42)
```

Without `local_dns_server`, clients appear in the dashboard only as raw IP addresses. With it, they appear with their full hostname.

!!! note "block_private_ptr"
    The `block_private_ptr` option controls whether PTR queries from **external clients** for RFC-1918 addresses are blocked. It does not affect the internal PTR lookups Ferrous DNS makes to `local_dns_server` for its own client tracking.

---

### 2. DHCP Hostname Resolution

Many DHCP servers register client hostnames alongside their leases. `local_dns_server` allows Ferrous DNS to resolve these names, so devices show up with the same names your router assigns them — without requiring any manual configuration on the Ferrous DNS side.

This is especially useful for:

- Parental control rules tied to device names instead of IPs
- Client group assignment based on hostname patterns
- Dashboard readability when many devices are on the network

---

### 3. Upstream Server Name Resolution {#upstream-name-resolution}

Hostnames in upstream URLs, such as `doq://dns.adguard-dns.com:853`, are asked to `local_dns_server` first, then to the host's system resolver (`/etc/resolv.conf`). This matters when the machine running Ferrous DNS uses Ferrous DNS itself as its resolver. That setup can never look its own upstreams up through the system: nothing answers while Ferrous DNS starts, and afterwards it has no resolved upstream to ask.

```text
Startup: look up "dns.adguard-dns.com"
              │
              ▼ (local_dns_server is set)
    192.168.1.1:53  →  94.140.14.14, 2a10:50c0::ad1:ff
              │
              ▼
    doq://dns.adguard-dns.com:853 connects to those addresses
```

A lookup that fails is retried in the background. See [How hostnames are resolved](../features/upstream-management.md#hostname-resolution).

---

### Recommended Setup

For a typical home or office network:

```toml
[dns]
local_domain     = "lan"          # short hostnames resolve as name.lan
local_dns_server = "192.168.1.1:53"  # your router's IP
```

| Scenario | Effect |
|:---------|:-------|
| Client `192.168.1.42` connects | Dashboard shows `laptop.lan` instead of raw IP |
| Upstream URL `doq://dns.adguard-dns.com:853` | Hostname looked up through the router, even when this machine resolves through Ferrous DNS |
| New device joins the network | Hostname pulled from router's DHCP table |

---

## DNS Tunneling Detection

DNS tunneling detection is configured under `[dns.tunneling_detection]`. It is enabled by default and requires no additional setup.

Like DGA detection, rebinding protection, NXDomain hijack detection and response IP filtering, it can also be set in **Settings → Malware Detection**, which writes this file. For full documentation including real-world attack examples, configuration reference, confidence scoring, and whitelisting, see the [Malware Detection](../features/malware-detection.md) page. The valid range of each key is in the [configuration reference](ferrous-dns-toml.md#tunneling-detection).

```toml title="ferrous-dns.toml"
[dns.tunneling_detection]
enabled                    = true
action                     = "block"
max_fqdn_length            = 120
max_label_length           = 50
block_null_queries         = true
entropy_threshold          = 3.8
query_rate_per_apex        = 50
unique_subdomain_threshold = 30
txt_proportion_threshold   = 0.05
nxdomain_ratio_threshold   = 0.20
confidence_threshold       = 0.7
stale_entry_ttl_secs       = 300
domain_whitelist           = []
client_whitelist           = []
```

---

## DGA Detection

DGA (Domain Generation Algorithm) detection analyzes second-level domain names for statistical properties associated with algorithmically generated names. It is **enabled by default** and requires no external feeds.

For full documentation including signal descriptions, malware family examples, and whitelisting, see the [Malware Detection](../features/malware-detection.md#dga-detection) page.

```toml title="ferrous-dns.toml"
[dns.dga_detection]
enabled                       = true
action                        = "block"
hot_path_confidence_threshold = 0.40
sld_entropy_threshold         = 3.5
sld_max_length                = 24
consonant_ratio_threshold     = 0.75
digit_ratio_threshold         = 0.30
ngram_score_threshold         = 0.6
dga_rate_per_client           = 10
confidence_threshold          = 0.65
stale_entry_ttl_secs          = 300
domain_whitelist              = []
client_whitelist              = []
```

| Option | Default | Description |
|:-------|:--------|:------------|
| `enabled` | `true` | Master switch for DGA detection |
| `action` | `block` | Action when a DGA domain is detected: `block` (answer with the [`[blocking] block_mode`](blocking.md)) or `alert` (log only) |
| `hot_path_confidence_threshold` | `0.40` | Minimum weighted mini-score for Phase 1 hot-path detection (0.0–1.0). Typically requires 2+ signals to fire, preventing false positives on legitimate domains |
| `sld_entropy_threshold` | `3.5` | Shannon entropy of the SLD in bits/char — above this indicates a random-looking name |
| `sld_max_length` | `24` | Maximum SLD length — longer names trigger the length signal |
| `consonant_ratio_threshold` | `0.75` | Fraction of consonant characters — DGA names often lack vowels |
| `digit_ratio_threshold` | `0.30` | Fraction of digit characters — DGA algorithms frequently embed numbers |
| `ngram_score_threshold` | `0.6` | Bigram deviation score above this indicates non-human-readable character sequences |
| `dga_rate_per_client` | `10` | Maximum DGA-like domains per minute per client subnet |
| `confidence_threshold` | `0.65` | Minimum combined weighted score for Phase 2 background analysis to flag an SLD (0.0–1.0) |
| `stale_entry_ttl_secs` | `300` | Seconds before idle tracking entries are evicted from memory |
| `domain_whitelist` | `[]` | Domains that bypass DGA detection entirely |
| `client_whitelist` | `[]` | Client CIDRs (e.g. `10.0.0.0/8`) or bare IPs (a single host) that bypass DGA detection. Invalid entries are skipped with a warning |

---

## Response IP Filtering

Response IP filtering downloads C2 IP threat feeds and blocks DNS responses that resolve to known command-and-control server IPs. It is **disabled by default** because it requires configuring external feed URLs.

For full documentation including real-world examples, recommended feeds, and edge cases, see the [Malware Detection](../features/malware-detection.md#response-ip-filtering) page.

```toml title="ferrous-dns.toml"
[dns.response_ip_filter]
enabled                = false      # opt-in (requires feed URLs)
action                 = "block"    # "alert" | "block"
ip_list_urls = [
    # "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    # "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
]
refresh_interval_secs  = 86400      # 24 hours
ip_ttl_secs            = 604800     # 7 days
```

---

## DNS Cookies (RFC 7873)

DNS Cookies (RFC 7873) protect UDP-based DNS against two classes of attack: **source-IP spoofing** (an attacker forging queries from a victim's address) and **amplification** (an attacker using open resolvers to flood a target with large DNS responses). By exchanging a cryptographically verified token on every query/response pair, the server can distinguish legitimate clients from forged traffic before spending resources on resolution.

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `enabled` | `bool` | `true` | Master switch — enables DNS Cookie processing. When `false` the server never sends a COOKIE option |
| `server_secret` | `str` | `""` | Hex-encoded 32-byte HMAC secret (64 hex chars). Empty = auto-generate an ephemeral secret on startup (not suitable for production) |
| `secret_rotation_secs` | `int` | `3600` | Seconds between secret rotations. The previous secret is still accepted for one full rotation window to allow in-flight clients to re-negotiate without errors |
| `require_valid_cookie` | `bool` | `false` | Strict mode: a UDP query without a valid server cookie gets `BADCOOKIE` with a fresh cookie when it sent a client cookie, or `REFUSED` when it sent none (both with EDE 18). TCP, DoT, DoH and DoQ are not checked. Default `false` = permissive mode (always respond, and echo a fresh server cookie) |

!!! warning "The table is nested under `[dns]`"
    The section is `[dns.dns_cookies]`, not a top-level `[dns_cookies]`. A top-level table is silently ignored and leaves every value at its default.

### Permissive mode (default)

All queries are answered regardless of cookie status. The server always echoes a fresh HMAC-SHA256 server cookie in every response, so RFC-7873-capable clients learn and cache the cookie automatically. A malformed COOKIE option (not 8 or 16–40 bytes long) is answered with `FORMERR` in either mode (RFC 7873 §5.2.2).

```toml
[dns.dns_cookies]
enabled               = true
server_secret         = ""
secret_rotation_secs  = 3600
require_valid_cookie  = false
```

### Strict mode

UDP queries that arrive without a valid server cookie are rejected before any lookup, cache included. A query that carries a client cookie gets `BADCOOKIE` with a fresh server cookie, so an RFC 7873 client retries with it. One without any cookie gets `REFUSED`. TCP, DoT, DoH and DoQ are not checked: their handshake already proves the client's address (RFC 7873 §5.2.3). Strict mode also turns off the inline UDP cache path, so every UDP query takes the full path.

```toml
[dns.dns_cookies]
enabled               = true
server_secret         = "a1b2c3d4e5f6..."   # 64 hex chars (32 bytes)
secret_rotation_secs  = 3600
require_valid_cookie  = true
```

!!! warning "Strict mode may break legacy clients"
    Setting `require_valid_cookie = true` will reject UDP queries from DNS clients that do not implement RFC 7873 (older resolvers, some embedded devices, and certain monitoring tools). Enable strict mode only after verifying that all clients on your network support DNS Cookies, or use permissive mode (`require_valid_cookie = false`) as a safe default.

!!! tip "Persistent secret across restarts"
    When `server_secret` is empty, Ferrous DNS generates an ephemeral secret at startup. Clients that cached a server cookie during the previous run will need to re-negotiate on restart. For stable production deployments, set a fixed 64-character hex secret.

See [Security > DNS Cookies](../features/security.md#dns-cookies) for a full explanation of the handshake and threat model.
