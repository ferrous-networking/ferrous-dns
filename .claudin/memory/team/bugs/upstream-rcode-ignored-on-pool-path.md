---
name: upstream-rcode-ignored-on-pool-path
description: Upstream rcodes on the pool path — SERVFAIL caching and negative TTL fixed by #282 (2026-10-12); the query log still records upstream NXDOMAIN as NOERROR
type: project
paths:
  - crates/application/src/use_cases/dns/handle_dns_query.rs
  - crates/infrastructure/src/dns/cache_maintenance.rs
---

**Symptom:** the client gets the right rcode, but the query log records an upstream NXDOMAIN or NODATA as `response_status = 'NOERROR'`. This happens both live and from the cache. #282's follow-up also names SERVFAIL relayed from the cache. Anything reading the log is wrong for these rows: the dashboard, the Pi-hole `/queries` `status` and `reply`, and the `reply=NXDOMAIN` filter.

**Where:**
- `handle_dns_query.rs`: `base_query_log`, `cache_hit_log`, and the upstream `Ok` branch.
- The refresh log in `infrastructure/src/dns/cache_maintenance.rs`.
- `WireData` stores no rcode, so a fix has to carry it in `DnsResolution` or read it from the cached wire header ([[dns-resolution-wire-data-invariant]]).
- **Tunneling detector.** Its `nxdomain_ratio` signal only counts `Err(DomainError::NxDomain)`, which only negative entries of the local path produce, so it never fires for upstream NXDOMAINs.
- **RRL coupling.** Since PR #251 (2026-09-25), `rate_limit.nxdomain_per_second` is enforced BIND-RRL style per subnet. Upstream NXDOMAINs escape it today, so a fix that surfaces the rcode will start charging them. Before merging one, test the shipped config (/24, 50/s) against a client that legitimately produces many upstream NXDOMAINs. Local-server NXDOMAINs are exempt through the cache's `FLAG_LOCAL_DNS` bit.

**Repro:**
1. Run the binary with 1.1.1.1 upstream ([[runtime-verification-recipe]]).
2. Run `dig no-such-name-241.iana.org A` twice. Both return NXDOMAIN, the second from cache.
3. Both `query_log` rows show `response_status = 'NOERROR'`, and the second has `cache_hit = 1`.

**Status:**
- **2026-09-23:** filed as issue #244, which was closed on 2026-09-27 without a fix.
- **2026-10-12, PR #282** (`057b7e6`) fixed the other halves:
  - `query_server` returns `DomainError::UpstreamServerFailure` for every rcode except NOERROR and NXDOMAIN, so strategies and pools fail over, and nothing caches it.
  - A wire answer with no answer records is cached for the SOA negative TTL, held to 300–3600 s, on insert and on refresh. It used to be `cache_ttl`.
- **Query-log half:** still open and unfiled. #282 left RRL and the tunneling signal as they were.

**Why not fixed:** it needs the RRL decision above, and #282 kept its scope to caching and failover.

Origin: the PR #241 author spotted the NXDOMAIN case, and the review extended it to SERVFAIL and NODATA.
