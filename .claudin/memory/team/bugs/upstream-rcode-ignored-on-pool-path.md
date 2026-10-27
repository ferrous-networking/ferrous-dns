---
name: upstream-rcode-ignored-on-pool-path
description: Upstream rcodes on the pool path — SERVFAIL caching/negative TTL fixed by #282 (10-12); query log fixed by #305 (10-23); RRL + tunneling (issue #322) fixed on fix/upstream-nxdomain-budget (10-26), which makes the tunneling nx signal fire
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
- **2026-10-23, query-log half:** fixed by PR #305 (branch red tests `53ab8a57`, `b98f5dcd`; fix `9c78697a`). `DnsResolution::upstream_nxdomain` is set in `CoreResolver::resolve` from the parsed rcode, only when the reply has no addresses (the server answers addresses as NOERROR, `server.rs` `handle_raw_udp_fallback`). The cache reads it from the wire header (`wire_response::is_nxdomain`), and `InflightResult` copies it to followers. `rcode_name()` feeds the fresh, cache-hit, fast-path and refresh logs. Regression tests: `crates/infrastructure/tests/query_log_upstream_rcode_test.rs`. Old rows keep NOERROR.
- **2026-10-26, RRL + tunneling half:** filed as issue #322 and fixed on branch `fix/upstream-nxdomain-budget` (red tests `89a42108`, fix `c3c8727f`).
  - `HandleDnsQueryUseCase` charges `upstream_nxdomain && !local_dns` on the fresh and cache-hit `Ok` paths. `try_cache_wire_direct` declines such a hit while `DnsRateLimiter::limits_nxdomain()`, because the fast path cannot charge. Internal pools are exempt through `local_dns`, like `local_dns_server`.
  - `emit_tunneling_event` gets the same `upstream_nxdomain && !local_dns` flag (the review round on 10-27 caught internal pools feeding the ratio; red `e9d06beb`, fix `013a839e`).
  - Pre-existing gap the fix widened: every query through `execute` spends a general token in `rate_limiter.check`, and only UDP fast-path cache hits skip it. Cached non-IP upstream NXDOMAINs now leave the fast path while the NXDOMAIN budget is on, so they spend one too. `rate-limiting.md` says so now.
  - Pre-existing, now reachable: the slip answers TC=1 on every transport (`server.rs` `DnsRateLimitedSlip => query.truncated()`), so a TCP retry of an over-budget NXDOMAIN is limited again.
  - Regression tests: `crates/application/tests/rate_limit_nxdomain_test.rs`, `tunneling_test.rs`, and `crates/infrastructure/tests/rate_limit_upstream_nxdomain_test.rs`, the real stack.
- **Live A/B, shipped `[dns.rate_limit]` (/24, 50/s, slip 2), fake NXDOMAIN upstream, debug builds, 2026-10-26:**
  - 300 unique names as fast as possible: main 300 NXDOMAIN; branch 105 NXDOMAIN, then 98 TC + 97 REFUSED.
  - One cached TXT NXDOMAIN ×300: main 300 NXDOMAIN; branch 104, then limited.
  - 20 NXDOMAIN/s for 30 s: 600 NXDOMAIN on both arms. A resolving name answers while the budget is spent.
- **Behavior change to know about:** the tunneling `nxdomain_ratio` signal (weight 0.10) now fires.
  - Random TXT names under one apex at 10/s scored query_rate 0.25 + unique 0.25 + TXT 0.10 + NX 0.10 = 0.70, so the branch flagged and blocked the apex after 51 queries. Main scored 0.60 and never flagged.
  - A-only random-name floods stay at 0.60. DNSBL-style lookups that mix many unique NXDOMAINs with TXT under one apex can now reach the threshold.

**Why RRL/tunneling stayed out of #305:** the query-log fix changes reporting only. Charging the budget or the tunneling ratio changes what gets refused, which needed its own load test (above).

Origin: the PR #241 author spotted the NXDOMAIN case, and the review extended it to SERVFAIL and NODATA.
