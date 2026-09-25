---
name: upstream-hostname-startup-only-resolution
description: udp/tcp/tls/doq upstream hostnames are looked up only at startup and on pool save, via the system resolver; a failed lookup leaves the server dead until the next reload (documented in PR #255, not fixed)
type: project
paths: crates/infrastructure/src/dns/load_balancer/pool.rs, crates/infrastructure/src/dns/transport/resolver.rs, crates/infrastructure/src/dns/transport/quic.rs
---

**Symptom:** a `doq://`/`tls://`/`udp://`/`tcp://` upstream given by hostname fails every
query ("QUIC transport requires resolved address, got: host:853") if its lookup failed at
startup, and stays that way until a restart or pool reload. Looks to users like "hostnames
aren't supported" (issue #250 is probably this, or the UI's IP-only examples).

**Where:** `PoolManager::expand_hostnames` (`pool.rs`) keeps the protocol `Unresolved` on
lookup failure; `QuicTransport::resolved_addr` → `require_resolved` has no fallback. Only
`https://`/`h3://` resolve again at runtime (`h3.rs` `resolve_addr`). The lookup is
`tokio::net::lookup_host` (`transport/resolver.rs`) — system resolver only. Likely trigger:
the host's `/etc/resolv.conf` points at ferrous-dns itself, which is not listening yet.

**Docs mismatch (fixed by PR #255):** `docs/configuration/dns.md` used to say startup lookups
go to `local_dns_server` first; nothing in the code ever did that.

**Status:** found 2026-09-25 while triaging #250; hostname DoQ itself verified working live
(`doq://dns.adguard-dns.com:853` and `doq://94.140.14.14:853` both answered). PR #255 fixed the
docs mismatch and documented the failure mode (upstream-management "How hostnames are
resolved", troubleshooting "An Upstream Hostname Never Comes Up"). The runtime re-resolution
itself is still unfixed and unfiled. Related: [[upstream-url-parser-js-mirror]].
