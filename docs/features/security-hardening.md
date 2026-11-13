# Security Hardening

Blocking is only half of what a resolver at the edge of a network does. The other half is making sure the answers it hands back are the ones the upstream side actually sent, and that one misbehaving client cannot degrade resolution for everyone else.

This page documents the hardening *underneath* the features: what protects the upstream path, what protects the listener and the dashboard, what is on by default — and, just as importantly, what is **not** covered yet.

How each dashboard mechanism is configured (authentication, tokens, HTTPS, 2FA) is in [Security Features](security.md).

---

## Threat model at a glance

### DNS side {#dns-side}

| Threat | Mechanism | Default |
|:-------|:----------|:--------|
| Off-path response forgery (cache poisoning) | Transaction ID + question matching, source address check, DNS Cookies, source-port rotation | On |
| On-path / normalizing upstreams | 0x20 QNAME case randomization | Off (opt-in) |
| Upstream tampering with signed zones | DNSSEC validation (`permissive` / `strict`) | Permissive |
| Downgrade of a signed delegation | DS denial proof against parent NSEC/NSEC3 | On (detection only) |
| Query floods / amplification | Per-subnet token bucket, NXDOMAIN budget, TC=1 slip, server-side DNS Cookies | Rate limiting off in code, on in the shipped example |
| Connection exhaustion (TCP/DoT/DoQ) | Per-IP connection caps | On |
| ISP NXDOMAIN hijacking | Periodic `.invalid` probes + answer rewrite | On |
| DNS rebinding | Public name → RFC 1918 answer filtering | On |
| Passive observation of your queries | DoT / DoH / DoQ upstreams | Off (plain UDP by default) |
| Disclosure of client subnets to upstreams | Upstream queries carry no option a client sent, EDNS Client Subnet included | Always |

### Dashboard and API side {#dashboard-and-api-side}

These rows cover the web listener (`web_port`, 8080 by default): the dashboard, the Ferrous API at `/ferrous/api/v1`, the [Pi-hole compatible API](pihole-compat.md) at `/api` when `pihole_compat` is on, and DoH and `/metrics` when they share the port. Every user and API token is a full admin (see the roles row), so these mechanisms keep out people who are not signed in; they do not limit what a signed-in user can do.

| Threat | Mechanism | Default | Not covered |
|:-------|:----------|:--------|:------------|
| Password guessing | Argon2id password hashes (19 MiB, 2 passes). A [lockout](security.md#login-lockout) after `login_rate_limit_attempts` wrong passwords or second-factor codes per client address (IPv6 per /64), shared by the dashboard and Pi-hole logins | On, 5 attempts per 15 min | Behind a reverse proxy every login shares the proxy's count. Checks that need a session (password change, turning 2FA off) are not counted |
| Finding which usernames exist | An unknown or disabled username costs the same password check as a wrong password and gets the same `401` | Always | — |
| First-run takeover | `POST /auth/setup` works only while the admin has no password, and one setup at a time | Until the first password is set | On a fresh install the first client to reach the port sets the password, and the web port listens on every interface by default (`bind_address = "auto"`, unless `web_bind_address` says otherwise): set it before the port is reachable |
| Credentials at rest | Passwords are Argon2id hashes: the admin's in `ferrous-dns.toml`, other users' in the database. Session tokens and API keys are kept only as SHA-256. A configuration export (`/config/export`) carries none of them | On | TOTP secrets are not encrypted, so a database copy (`--backup-database`, a volume snapshot) holds them beside the password hashes: keep copies as private as the server. A password needs only 8 to 256 bytes |
| Privilege inside the dashboard | Each user has a role, `admin` or `viewer`, recorded on the account and its sessions ([Users and Roles](security.md#users-and-roles)) | — | Roles are not enforced: every user and API token can change any setting, manage users and tokens, revoke any session, and turn authentication off with `POST /config` |
| Stolen or forged session cookies | 256-bit random tokens in an `HttpOnly; SameSite=Strict` cookie, `Secure` when the server serves HTTPS itself. Stored and listed only as their SHA-256. Fixed expiry (`session_ttl_hours`, `remember_me_days`), revocable under **Settings > Security**, and a password change signs out the user's other sessions | On | A session is not bound to an address or a browser. Behind a proxy that ends TLS the cookie has no `Secure` unless the server serves HTTPS too ([TLS & Reverse Proxy](../operations/tls-reverse-proxy.md)) |
| Stolen or guessed API tokens | Generated keys are 256-bit; custom keys need 32 characters and no surrounding whitespace. Keys are stored only as SHA-256, shown once and listed by a short prefix; tokens are revocable | On | A token has no scope or expiry and acts as a full admin. `X-Api-Key` guesses are not throttled, and the 32 characters are a length floor: a custom key is only as strong as whoever chose it made it. Used as a Pi-hole app password, a token skips the second factor |
| A leaked password | A second factor per account: TOTP (6 digits, ±30 s, each code accepted once, 10 single-use recovery codes) or passkeys with user verification | Off, enrolled per account under **Settings > Security** | Turning 2FA off needs a session and the password, not a code |
| Cross-site requests (CSRF) | The session cookie is `SameSite=Strict`, so a request another site triggers carries no session. API tokens travel in a header browsers never add | On | No CSRF token or `Origin` check. The login accepts any content type, so another site can sign a browser into an account whose password it knows |
| Framing (clickjacking) | `Content-Security-Policy: frame-ancestors 'self'` and `X-Frame-Options: SAMEORIGIN` on the dashboard, both APIs, `/docs`, `/metrics` and DoH on `web_port` ([Security headers](../configuration/server.md#security-headers)) | On | — |
| Script injection (XSS) | The dashboard renders server data as text; its few HTML bindings show only built-in markup (service icons, the TOTP QR code) or escaped values. `X-Content-Type-Options: nosniff` on the same responses as the frame policy | On | No script Content-Security-Policy: Alpine's standard build evaluates its expressions |
| Reading the API from another site | CORS without credentials: a browser on another site never sends the session cookie, so it can read only responses that need no login | `cors_allowed_origins = ["*"]` | The unauthenticated endpoints (`/auth/status`, `/health`, `/openapi.json`) are readable from any site unless `cors_allowed_origins` lists only the dashboard's own origin |
| DNS rebinding of the dashboard | None: the server does not check the `Host` header. A session cookie belongs to the dashboard's host name, so a page that points its own name at the server reaches it without a session | — | Through a rebound name, the unauthenticated endpoints, and every endpoint with `[auth] enabled = false`, can be called |
| Uploads | TLS certificate and key: PEM of at most 64 KB each, validated, written only to the paths in `ferrous-dns.toml` (the key with mode `0600`). Backup import: at most 2 MB, keeps this server's TLS paths, and turns login and its lockout on but never off. Blocklists are fetched by URL, never uploaded | On | — |
| Requests the server makes for an admin (SSRF) | Blocklist, allowlist and IP feed URLs must be `http://` or `https://`, DoH upstreams `https://`. The API tells only whether a list fetch failed; the reason goes to the server log | — | A signed-in user can make the server fetch any address it reaches, loopback, LAN and cloud metadata included, following up to 10 redirects and the `HTTP(S)_PROXY` environment; whether a fetch failed tells a reachable address from an unreachable one |
| Floods against the web listener | Only the login lockout, which counts failed logins per client. Request bodies are capped at 2 MB, and at 16 KiB on the Ferrous API's login and second-factor requests | — | No request rate limit, timeout or connection cap on the web listener: keep it behind a reverse proxy or on a trusted network. Every login, with a known username or not, takes one of the two password-hashing slots, so logins from many addresses at once slow real ones down |
| Endpoints without a login | On the Ferrous API only `/auth/status`, setup, login, logout, the second-factor and passkey login steps and `/health`; on the Pi-hole API only `/api/auth`, `/api/info/login` and `/api/info/client`. Also the dashboard's static files, `/ferrous-config.js` (the API base and the version) and each API's `/openapi.json` and `/docs` | Everything else needs a session or a token | `/metrics`, when `metrics_enabled = true`, has no authentication ([Metrics](metrics.md)). DoH (`/dns-query`) never asks for one |
| The Pi-hole compatible API | Off by default. When on, every other route needs a session `sid`, and it shares sessions, tokens and the lockout with the dashboard | `pihole_compat = false` | Pi-hole clients may send the `sid` in the query string, where proxies and browsers log URLs |
| A spoofed client address | The address a session records, and the DoH client, are the TCP peer; only a peer in [`trusted_proxies`](../configuration/server.md#doh-client-identity) may name the client | Loopback trusted | Any process on the server itself can name any client |

---

## Upstream response validation

Ferrous DNS validates every upstream response at two layers. A response that fails is not merely dropped — it is turned into a transport error, so the load balancer fails over to the next server in the pool instead of returning a possibly forged answer.

### Layer 1 — datagram level (plain UDP only)

Implemented in the UDP transport, before a single byte is parsed as a DNS message:

- **Source address** — the datagram must come from the IP *and port* of the upstream that was queried (an IPv4 peer reported as IPv4-mapped IPv6 still matches).
- **Message ID** — the first two bytes must match the transaction ID that was sent.
- **Size cap** — responses larger than 4096 bytes are not read.

A datagram failing either check is drained and the receive loop keeps waiting until the query deadline, rather than failing the in-flight query. This matters because upstream sockets are pooled and reused: a late answer to a *previous* query on the same socket says nothing about the query currently in flight.

### Layer 2 — message level (every transport)

Once parsed, the response passes through a single validation choke point before anything else — including before the "truncated, retry over TCP" path, so a forged `TC=1` cannot burn the retry:

| Check | Plain UDP/TCP (Do53) | DoT / DoH / DoQ |
|:------|:--------------------:|:---------------:|
| Transaction ID matches | Yes | Yes |
| Question section present | Yes | Yes |
| QTYPE matches the question asked | Yes | Yes |
| QNAME matches the question asked | Yes (case-sensitive when 0x20 is on) | Yes (case-insensitive) |
| DNS Cookie echo valid | Yes | Not applicable |

Encrypted transports skip the cookie and case checks because TLS/QUIC already authenticates the upstream, and some providers normalize QNAME case on the way back.

Both layers also cover queries to [`local_dns_server`](../configuration/dns.md#local-dns-server) — LAN names and private-range PTRs — whose answers are relayed to clients as-is. A failed answer there is logged as `Local DNS server query failed` and the client gets NXDOMAIN, since there is no second server to fail over to.

---

## DNS Cookies (RFC 7873)

Cookies are two independent halves. Be aware which one you are configuring.

### Client side — Ferrous → upstream

Always on, with no configuration key. Every plain-UDP upstream query carries a random 8-byte client cookie (EDNS option 10), and the echo is verified in constant time.

The check is deliberately **graceful**: an upstream that returns no cookie at all is accepted (many public resolvers do not implement RFC 7873). Only a malformed or mismatched echo is treated as a forgery.

### Server side — clients → Ferrous

Configured under `[dns.dns_cookies]`, documented in detail in [DNS Cookies](security.md#dns-cookies).

!!! warning "The section is nested under `[dns]`"
    The correct TOML section is **`[dns.dns_cookies]`**. A top-level `[dns_cookies]` table — which older example files and older versions of this documentation showed — is silently ignored, leaving you with the defaults while the file looks configured. If you set `server_secret` and cookies still regenerate on every restart, this is why.

```toml
[dns.dns_cookies]
enabled              = true    # on by default
server_secret        = ""      # empty = ephemeral secret, regenerated each restart
secret_rotation_secs = 3600
require_valid_cookie = false   # true = BADCOOKIE/REFUSED for UDP clients without a valid cookie
```

`server_secret` must be exactly 64 hex characters when set; with cookies enabled anything else aborts startup rather than silently falling back (with `enabled = false` it is ignored with a warning). Leaving it empty is fine for a single instance, but every restart invalidates outstanding client cookies — set it explicitly for production and for multi-instance deployments.

---

## 0x20 QNAME case randomization

`[dns] qname_case_randomization` (**default `false`**) randomizes the case of each letter in the outgoing QNAME, adding roughly one bit of entropy per letter for an off-path attacker to guess on top of the transaction ID and source port.

```toml
[dns]
qname_case_randomization = true
```

Details worth knowing before enabling it:

- It applies to **every record type**, not only A/AAAA.
- The echoed name is compared **case-sensitively on plain DNS only**. On DoT/DoH/DoQ the comparison is case-insensitive.
- The randomized name is canonicalized before the answer is cached, so neither the cache nor the query log keeps the randomized case. Every client gets the question back spelled as it sent it, so a downstream resolver doing its own 0x20 check accepts the answer.
- It also applies to queries sent to `local_dns_server`. A router that rewrites name case fails validation on every local answer, logged as `Local DNS server query failed`.
- It is off by default because a minority of upstreams normalize QNAME case, which would make every response from them fail validation. Enable it, then watch for a jump in upstream failures before leaving it on.

---

## Source-port rotation

Upstream UDP sockets are pooled, retaining up to 4 idle sockets per upstream server and admitting at most 64 simultaneous checked-out exchanges across the default pool. Both fresh and reused sockets consume admission capacity. Waiting for capacity spends the same query timeout as the exchange itself, and a wait that runs out is reported as a transport timeout, so the query fails over to the next pool like any other unreachable upstream. Each socket is retired and re-bound after roughly 1000 queries, with ±25% jitter so rotations do not synchronize. A source port an attacker has discovered goes stale on its own, and pooling avoids creating a socket per query.

---

## EDNS buffer size and truncation

Upstream queries advertise a 1232-byte EDNS UDP payload — small enough to avoid IP fragmentation on nearly every path, which is itself a spoofing vector. Oversized answers come back with `TC=1` and are retried over TCP, and client-advertised buffer sizes are honoured with correct truncation on the way back (RFC 6891 §6.2.5 / RFC 7766). Every answer carries an OPT record only when the query did (RFC 6891 §7) and copies the query's DO bit into it (RFC 3225 §3). That includes the upstream answers relayed for record types other than A/AAAA, cached or not: their upstream OPT is replaced by ours, with the upstream's extended RCODE kept and a client cookie echoed beside our server cookie (RFC 7873 §5.3). The upstream's own options, including its echo of the cookie Ferrous sent it, never reach the client, and neither does a TSIG or SIG(0): it signs the upstream's exchange with Ferrous, not the client's, and must stay the last record, where our OPT goes (RFC 8945 §5.1, §5.3; RFC 2931 §3). A client that did not set DO gets none of the RRSIG, NSEC and NSEC3 records the DO=1 upstream query returned, unless it asked for that type (RFC 4035 §3.2.1). Records behind a removed one keep their names: compression pointers into moved bytes are re-aimed, and pointers into removed bytes are replaced by the labels they pointed to.

In the other direction, upstream queries are built from the question alone and carry none of the options a client sent, so an EDNS Client Subnet (RFC 7871) never discloses a client's network to an upstream. Sending a chosen subnet upstream for CDN-accurate answers is not supported yet.

---

## DNSSEC

`[dns] dnssec_mode` accepts:

| Mode | Behaviour |
|:-----|:----------|
| `off` | No validation. |
| `permissive` | **Default.** Validate and tag the result (`dnssec_status` in the query log, AD bit on secure answers), but never SERVFAIL. |
| `strict` | Answers that do not validate — `Bogus`, or `Indeterminate` because the chain could not be fetched — become SERVFAIL, unless the client sets CD. |

NXDOMAIN and NODATA are validated too, via NSEC and NSEC3 denial-of-existence proofs (including opt-out and the RFC 9276 parameter limits). Validation results are exposed at `GET /ferrous/api/v1/dnssec/stats` and filterable in the query log.

**Insecure must be proven.** An answer is `Insecure` only when the zone above it proves, with signed NSEC/NSEC3, a delegation that has no DS (or an NSEC3 opt-out span), or when the DS names only algorithms this build cannot verify (RFC 6840 §5.2). An empty DS answer without that proof, an unsigned answer or denial from a zone the chain shows is signed, or a denial built from the parent's NSEC at a zone cut (RFC 6840 §4.1) is `Bogus`. A forwarder that strips the authority section therefore turns signed names `Bogus`; such answers are counted as `ds_denials_unproven` at `GET /ferrous/api/v1/dnssec/stats`, so check that counter before switching to `strict`.

Trust anchors are the IANA root KSKs, embedded in the binary. `[dns] dnssec_trust_anchor_file` **replaces** them (it does not merge), is read only at startup, and an unreadable file aborts boot rather than falling back to no validation. There is no RFC 5011 automated rollover: a future root key roll needs either an updated release or your own anchor file.

---

## Protecting the listener

### Per-subnet rate limiting

A token bucket keyed on the client subnet (`/24` for IPv4, `/48` for IPv6 by default) and kept apart for UDP and the stream transports, with a separate NXDOMAIN budget, a TC=1 slip mode that moves UDP clients onto TCP, where a spoofed-source flood cannot follow, and a dry-run mode for tuning without dropping traffic.

Note the **code default is `enabled = false`** while the shipped `ferrous-dns.toml` turns it on — check the value you actually run with. Full option reference: [Rate Limiting](../configuration/rate-limiting.md).

### Per-IP connection caps

TCP, DoT and DoQ each have a per-IP connection ceiling (30 / 15 / 15 by default), enforced with RAII guards so a slot is released even if a handler panics or a client disappears mid-connection.

### Answer-side filters

- **Rebinding protection** (`rebinding_protection_enabled`, on) — a public name resolving into RFC 1918 space is blocked, with an allowlist for the legitimate cases.
- **NXDOMAIN hijack detection** — random `.invalid` names (RFC 6761) are probed every 5 minutes; if an upstream answers them with an address, its NXDOMAIN rewrites are undone.
- **Response IP filtering** (opt-in) — drops answers pointing at known command-and-control addresses.
- **Private PTR / non-FQDN blocking** — keeps reverse lookups for internal ranges and single-label names from leaking upstream.

---

## What is *not* hardened yet

Published so you can plan around it rather than discover it. The dashboard and API side lists what it does not cover in the last column of [its table](#dashboard-and-api-side).

| Gap | What it means | Status |
|:----|:--------------|:-------|
| `Indeterminate` under `permissive` | When DS/DNSKEY lookups cannot be fetched, `permissive` still serves the answer without AD. Use `strict` to refuse it. | By design |
| RFC 5011 trust-anchor rollover | Root key updates need a new release or a manual anchor file. | Planned |

---

## Deployment checklist

- [ ] Set the admin password before the web port is reachable from other hosts: until then anyone who reaches it can set it.
- [ ] Set `[dns.dns_cookies] server_secret` to a fixed 64-hex-character value (and confirm the section is nested under `[dns]`).
- [ ] Confirm `[dns.rate_limit] enabled = true` in the config you actually deploy.
- [ ] Use DoT/DoH/DoQ upstreams if the path to your resolver provider is untrusted.
- [ ] Consider `dnssec_mode = "strict"` once you have watched `permissive` for a while without false Bogus.
- [ ] Try `qname_case_randomization = true` and watch upstream failure counts before keeping it.
- [ ] Keep `metrics_enabled = false` unless the port is reachable only from your monitoring host.
- [ ] Serving DoH through a reverse proxy on another host or container? List only that proxy in `[server] trusted_proxies`; every peer in the list can name any client (and so choose its group's filtering). See [DoH client identity](../configuration/server.md#doh-client-identity).
- [ ] Put the dashboard behind HTTPS ([TLS & Reverse Proxy](../operations/tls-reverse-proxy.md)) and enable TOTP or a passkey — the login lockout slows password guessing but does not replace a second factor.
- [ ] Keep the web port on a trusted network or behind a reverse proxy: it has no request rate limit, and every account and API token is a full admin.

The operational side of going live (backups, monitoring, sizing, a second resolver) is in [Running in Production](../operations/index.md).
