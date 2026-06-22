# Blocking Configuration

The `[blocking]` section controls the base blocking settings. Blocklists, client groups, and per-group policies are managed via the dashboard or REST API.

---

## Basic Options

```toml
[blocking]
enabled = true
block_mode = "null_ip"
block_ttl = 60
# sinkhole_ipv4 = "192.168.1.2"
# sinkhole_ipv6 = "fd00::2"
```

| Option | Default | Description |
|:-------|:--------|:------------|
| `enabled` | `true` | Enable DNS-based blocking globally |
| `block_mode` | `"null_ip"` | How blocked domains are answered on the wire — see [Block Response Mode](#block-response-mode) |
| `block_ttl` | `60` | TTL (seconds) clients cache a blocked answer; also bounds the negative-cache lifetime for `nxdomain`/`nodata` |
| `sinkhole_ipv4` | _(unset)_ | Custom `A` target for `null_ip` blocks — see [Custom Sinkhole IP](#custom-sinkhole-ip). Unset → `0.0.0.0` |
| `sinkhole_ipv6` | _(unset)_ | Custom `AAAA` target for `null_ip` blocks. Unset → `::` |

!!! warning "Domains are not configured here"
    The `[blocking]` section also accepts `custom_blocked` and `whitelist` arrays, but **they are not consulted by the DNS query pipeline** — listing domains there has no effect on what is blocked or allowed. Blocked domains and allow-listed domains are managed via the dashboard or REST API and persisted in the SQLite database, not in this TOML file. See [Blocklist Management](#blocklist-management-dashboard) and [Allow/Block from Query Log](#allowblock-from-query-log) below.

---

## Block Response Mode

`block_mode` controls **how** a blocked domain is answered — this applies to every domain-verdict block (blocklist match, DGA detection, DNS tunneling, and the C2/threat filter). The choice affects how clients behave after a block: a cacheable answer makes them stop re-querying, while a non-cacheable rejection makes them retry aggressively.

| Mode | Response | Cacheable | Notes |
|:-----|:---------|:----------|:------|
| `null_ip` | `NOERROR` + `0.0.0.0` (A) / `::` (AAAA); `NODATA` for other types | Yes | **Default, recommended.** Clients connect to the null address and fail fast. |
| `nxdomain` | `NXDOMAIN` with a synthetic SOA | Yes | The domain appears not to exist. Some clients log noisy errors. |
| `nodata` | `NOERROR`, empty answer, with a synthetic SOA | Yes | The name exists but has no records of the requested type. |
| `refused` | `REFUSED` | No | Legacy behaviour. Clients retry aggressively — avoid unless required. |

For the negative modes (`nxdomain`, `nodata`, and `null_ip` answering a non-address query), Ferrous DNS attaches a synthetic `SOA` record to the authority section. Its `minimum` field is set to `block_ttl`, which lets downstream resolvers negatively cache the block per [RFC 2308](https://www.rfc-editor.org/rfc/rfc2308).

```toml
[blocking]
block_mode = "null_ip"   # null_ip | nxdomain | nodata | refused
block_ttl  = 60          # seconds clients/resolvers cache the blocked answer
```

!!! tip "Why `null_ip` is the default"
    A cacheable `0.0.0.0` answer is the gentlest on both the client and the resolver: the client gets an immediate connection failure and caches it for `block_ttl`, so it stops hammering the resolver. `refused` is non-cacheable (RFC 2308 §7), so clients re-query on every attempt.

!!! warning "Requires a restart"
    `block_mode`, `block_ttl`, `sinkhole_ipv4`, and `sinkhole_ipv6` are read once at startup. Changing them in the config file or via the dashboard takes effect only after the server is restarted. Blocklist contents (the domains themselves) still update live without a restart.

---

## Custom Sinkhole IP

By default, `null_ip` answers a blocked `A` query with `0.0.0.0` and a blocked `AAAA` query with `::` — addresses that clients can't connect to, so the request fails fast. If you instead run a local **block page** (a small web server that explains the domain was blocked), point blocked domains at it with `sinkhole_ipv4` / `sinkhole_ipv6`:

```toml
[blocking]
block_mode = "null_ip"          # sinkhole IPs only apply in null_ip mode
sinkhole_ipv4 = "192.168.1.2"   # A target for blocked domains
sinkhole_ipv6 = "fd00::2"       # AAAA target for blocked domains
```

The two families are independent: if you set only `sinkhole_ipv4`, blocked `AAAA` queries still return `::` (and vice-versa). The targets apply to **every** domain-verdict block (blocklist, DGA, tunneling, C2), just like `block_mode`. They are ignored in `nxdomain`, `nodata`, and `refused` modes, which carry no address.

!!! warning "Don't use loopback"
    Point the sinkhole at the **LAN IP** of the host serving the block page, not loopback (`127.0.0.1` / `::1`). A loopback target resolves to each *client's own* machine, not the Ferrous DNS server, so the block page won't load.

---

## Blocklist Management (Dashboard)

All blocklist management is done via the dashboard or REST API — not the TOML file.

### Adding a Blocklist

1. Go to **Blocklists** in the sidebar
2. Click **Add Blocklist**
3. Enter a name and URL
4. Select the format (hosts, domains, or regex)
5. Click **Save**, then **Sync**

### Supported Formats

| Format | Example |
|:-------|:--------|
| Hosts file | `0.0.0.0 ads.example.com` |
| Domain list | `ads.example.com` |
| Wildcard | `*.ads.example.com` |
| Regex | `/^ads\d+\.example\.com$/` |

### Blocklist URL Examples

```text title="Blocklist URLs"
# Hosts format
https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts

# Domain list
https://small.oisd.nl/domainswild

# Regex-capable
https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt
```

---

## Wildcard Blocking

Ferrous DNS supports wildcard patterns for blocking entire subdomains:

```text
*.ads.example.com    — blocks ads.example.com, video.ads.example.com, etc.
*.doubleclick.net    — blocks all subdomains of doubleclick.net
```

Wildcards can be added in the dashboard under **Blocklists > Custom Rules**.

---

## Regex Support

Regex patterns are supported in blocklists and custom rules:

```text
/^ads\d+\.example\.com$/     — matches ads1.example.com, ads42.example.com
/tracker/                    — matches any domain containing "tracker"
```

---

## CNAME Cloaking Detection

Ferrous DNS inspects CNAME chains in responses. If a CNAME points to a blocked domain, the entire response is blocked — even if the queried domain is not on the blocklist.

This catches trackers that hide behind first-party CNAMEs (e.g. `tracking.yoursite.com CNAME tracking.thirdparty.com`).

CNAME cloaking detection is enabled automatically when blocking is active.

---

## Safe Search Enforcement

Force safe search for major search engines and video platforms:

Managed in the dashboard under **Services > Safe Search**.

| Platform | What it does |
|:---------|:-------------|
| Google | Redirects to `forcesafesearch.google.com` |
| Bing | Redirects to `strict.bing.com` |
| YouTube | Restricts to the moderate or strict endpoint (selectable per group) |
| DuckDuckGo | Forces safe search mode |
| Yandex | Forces family search mode |
| Brave | Forces safe search mode |
| Ecosia | Forces safe search mode |

---

## Blockable Services (1-Click)

Pre-defined service categories can be blocked with a single click from the dashboard under **Services**:

- Social Media (Facebook, Instagram, TikTok, Twitter/X)
- Advertising networks
- Telemetry & tracking (Microsoft, Apple, Google)
- Adult content
- Gambling
- Gaming platforms

These use curated domain lists maintained by the Ferrous DNS project.

---

## Per-Client Group Policies

Different blocking rules can be applied to different client groups:

1. Create client groups in **Clients > Groups**
2. Assign blocklists to each group
3. Set schedules for time-based blocking (e.g. block social media on school devices during school hours)

See [Client Management](../features/client-management.md) for details.

---

## Allow/Block from Query Log

Any domain in the query log can be instantly added to the allowlist or blocklist by clicking the Allow or Block button next to it. Changes take effect immediately without a server restart.
