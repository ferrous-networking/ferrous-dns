# Security Hardening

Blocking is only half of what a resolver at the edge of a network does. The other half is making sure the answers it hands back are the ones the upstream side actually sent, and that one misbehaving client cannot degrade resolution for everyone else.

This page documents the hardening *underneath* the features: what protects the upstream path, what protects the listener, what is on by default — and, just as importantly, what is **not** covered yet.

For the dashboard/API side (authentication, tokens, HTTPS, 2FA) see [Security Features](security.md).

---

## Threat model at a glance

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

---

## Upstream response validation

Ferrous DNS validates every upstream response at two layers. A response that fails is not merely dropped — it is turned into a transport error, so the load balancer fails over to the next server in the pool instead of returning a possibly forged answer.

### Layer 1 — datagram level (plain UDP only)

Implemented in the UDP transport, before a single byte is parsed as a DNS message:

- **Source address** — the datagram must come from the IP of the upstream that was queried.
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
require_valid_cookie = false   # true = REFUSED + EDE 25 for cookieless clients
```

`server_secret` must be exactly 64 hex characters when set; anything else aborts startup rather than silently falling back. Leaving it empty is fine for a single instance, but every restart invalidates outstanding client cookies — set it explicitly for production and for multi-instance deployments.

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
- The randomized name is canonicalized before the answer is cached, so clients and the query log never see mixed-case names.
- It is off by default because a minority of upstreams normalize QNAME case, which would make every response from them fail validation. Enable it, then watch for a jump in upstream failures before leaving it on.

---

## Source-port rotation

Upstream UDP sockets are pooled — 4 sockets per upstream server, 64 in total — and each socket is retired and re-bound after roughly 1000 queries, with ±25% jitter so rotations do not synchronize. A source port an attacker has discovered goes stale on its own, and the pooling keeps this from costing a socket per query.

---

## EDNS buffer size and truncation

Upstream queries advertise a 1232-byte EDNS UDP payload — small enough to avoid IP fragmentation on nearly every path, which is itself a spoofing vector. Oversized answers come back with `TC=1` and are retried over TCP, and client-advertised buffer sizes are honoured with correct truncation on the way back (RFC 6891 §6.2.5 / RFC 7766).

---

## DNSSEC

`[dns] dnssec_mode` accepts:

| Mode | Behaviour |
|:-----|:----------|
| `off` | No validation. |
| `permissive` | **Default.** Validate and tag the result (`dnssec_status` in the query log, AD bit on secure answers), but never SERVFAIL. |
| `strict` | Bogus answers become SERVFAIL, unless the client sets CD. |

NXDOMAIN and NODATA are validated too, via NSEC and NSEC3 denial-of-existence proofs (including opt-out and the RFC 9276 parameter limits). Validation results are exposed at `GET /api/dnssec/stats` and filterable in the query log.

**Downgrade detection, not enforcement.** An empty DS answer is checked against the parent's authenticated NSEC/NSEC3 denial (RFC 4035 §5.2): a signed proof that contradicts the answer makes the response Bogus. But if the authority section is missing or unauthenticated, the resolver falls back to treating the delegation as insecure — so an attacker able to compose the entire response can still downgrade it by omitting the proof. These fail-opens are counted as `ds_denial_fail_opens` at `GET /api/dnssec/stats` so the gap is measurable rather than invisible.

Trust anchors are the IANA root KSKs, embedded in the binary. `[dns] dnssec_trust_anchor_file` **replaces** them (it does not merge), is read only at startup, and an unreadable file aborts boot rather than falling back to no validation. There is no RFC 5011 automated rollover: a future root key roll needs either an updated release or your own anchor file.

---

## Protecting the listener

### Per-subnet rate limiting

A token bucket keyed on the client subnet (`/24` for IPv4, `/48` for IPv6 by default), with a separate NXDOMAIN budget, a TC=1 slip mode that forces suspicious clients onto TCP, and a dry-run mode for tuning without dropping traffic.

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

Published so you can plan around it rather than discover it.

| Gap | What it means | Status |
|:----|:--------------|:-------|
| No API rate limiting | The REST API has no request throttling middleware of any kind. Put the dashboard behind a reverse proxy or a trusted network. | Not implemented |
| Login lockout is inert | `login_rate_limit_attempts` and `login_rate_limit_window_secs` are accepted, persisted and returned by the API, but nothing enforces them — password attempts are not throttled. Do not count on them. | Config accepted, not enforced |
| DS-denial fail-open | Downgrade *detection* only; a response with no authority section still degrades to insecure. Tracked by `ds_denial_fail_opens`. | Detection only |
| EDNS Client Subnet | Client ECS is not stripped from upstream queries yet. | Planned (RFC 7871) |
| RFC 5011 trust-anchor rollover | Root key updates need a new release or a manual anchor file. | Planned |
| `/metrics` is unauthenticated | When `metrics_enabled = true` the endpoint is served without auth. See [Metrics & Monitoring](metrics.md). | By design — bind it carefully |

---

## Deployment checklist

- [ ] Set `[dns.dns_cookies] server_secret` to a fixed 64-hex-character value (and confirm the section is nested under `[dns]`).
- [ ] Confirm `[dns.rate_limit] enabled = true` in the config you actually deploy.
- [ ] Use DoT/DoH/DoQ upstreams if the path to your resolver provider is untrusted.
- [ ] Consider `dnssec_mode = "strict"` once you have watched `permissive` for a while without false Bogus.
- [ ] Try `qname_case_randomization = true` and watch upstream failure counts before keeping it.
- [ ] Keep `metrics_enabled = false` unless the port is reachable only from your monitoring host.
- [ ] Put the dashboard behind HTTPS and enable TOTP or a passkey — there is no login throttling to fall back on.
