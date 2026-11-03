---
name: rate-limit-stream-budget
description: PR #355 (2026-11-01, closes #339) — TCP/DoT/DoH/DoQ get per-subnet rate-limit buckets of their own and are REFUSED, never slipped; BIND-style stream exemption and one shared budget were rejected, and why
type: project
scope: dns/rate-limit
impact: functional
paths:
  - crates/application/src/use_cases/dns/rate_limiter/mod.rs
  - crates/application/src/use_cases/dns/handle_dns_query.rs
---

**Decision:** on 2026-11-01 Viudes chose a second token-bucket map per subnet for the stream transports (`ClientProtocol::is_stream`: TCP, DoT, DoH, DoQ). It uses the same `[dns.rate_limit]` knobs, with no new config keys. A stream query over its budget gets REFUSED + EDE 18, never TC=1, so only UDP slips. Shipped in PR #355 (`e5dbd095`).

**Why:** before #355 the slip answered TC=1 on every transport, all from one bucket. The TCP retry of a slipped query was then limited again and got TC=1 back (`dig +tcp` → `flags: qr tc`), so the slip never let a real client through. A spoofed-source flood can only use UDP, so it cannot drain a stream budget, and the retry gets answered.

**Rejected:**
- **Exempting the streams, as BIND RRL does:** DoH has no per-IP connection cap (`rate_limit.rs` has TCP/DoT/DoQ caps only), so a DoH flood would have no bound at all. TCP/DoT/DoQ would be held only by their concurrent-connection caps.
- **One shared budget, with streams REFUSED instead of slipped:** the TCP retry is then refused while the subnet is over budget, so the slip still never gets a client through.

**What changes for a teammate:**
- A subnet that uses both kinds of transport can spend up to twice the configured numbers. That is by design (`docs/configuration/rate-limiting.md`, "Why the stream transports have a bucket of their own"), not a bug to merge back into one bucket.
- Revisit the exemption only once DoH has a connection cap, and accept that the streams are then bounded only by connection caps.
- The `RATE_LIMITED` vs `RATE_LIMITED_TC` status is decided in the use case (`apply_rate_limit`), so a per-transport rule belongs there. Remapping in `server.rs` would make the query log and the wire disagree.
- `SubnetKey` uses all 64 bits of an IPv6 /64, so there is no room for a transport bit in the key. That is why the streams have a separate map.

**Evidence:** issue #339; the body of PR #355 ("Why not exempt streams?"); the plan in session 397de3b6.
