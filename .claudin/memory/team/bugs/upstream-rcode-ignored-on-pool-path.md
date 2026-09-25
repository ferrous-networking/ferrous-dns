---
name: upstream-rcode-ignored-on-pool-path
description: Upstream NXDOMAIN, NODATA and SERVFAIL on the pool path are cached as WireData for cache_ttl and logged NOERROR; open as issue #244 (2026-09-23)
type: project
paths:
  - crates/infrastructure/src/dns/resolver/core.rs
  - crates/infrastructure/src/dns/resolver/cache_layer.rs
  - crates/infrastructure/src/dns/forwarding/response_parser.rs
---

**Symptom:** an upstream SERVFAIL, NXDOMAIN or NODATA answer is cached for the full `cache_ttl` (7200 s in the repo's `ferrous-dns.toml`), not the SOA negative TTL. SERVFAIL gets the same treatment, although RFC 2308 §7.1 caps SERVFAIL caching at 5 minutes. The query log records the answer as `NOERROR`. The client still gets the right rcode, because the cached upstream wire is relayed as-is.

**Where it lives:**
- The pool path of `CoreResolver::resolve` (`core.rs`, around line 139) returns `Ok` whatever the upstream rcode is. Only the local-server path checks `is_nxdomain()` and `is_server_error()`.
- `ResponseParser` computes `min_ttl` from the answer section only.
- `store_in_cache` in `cache_layer.rs` stores `WireData` with `min_ttl.unwrap_or(cache_ttl)`.
- `handle_dns_query.rs` logs `NOERROR` for every non-local resolution (around line 808). Cache hits log `NOERROR` too, at two more sites the issue does not name: the UDP wire fast path `try_cache_wire` added by #241 (around line 463) and `base_query_log` (around line 354), which the `execute` cache-hit branch uses. `WireData` stores no rcode, so a fix has to read it from the cached wire header.
- Side effect missing from the issue: the tunneling detector's `nxdomain_ratio` signal only counts `Err(DomainError::NxDomain)`. Only the cache layer produces that error, from negative entries of the local path, so the signal never fires for upstream NXDOMAINs.
- Coupling added by PR #251 (merged 2026-09-25): `rate_limit.nxdomain_per_second` is now enforced BIND-RRL style. Only an NXDOMAIN answer over the per-subnet budget is REFUSED or TC; the subnet's other queries are not. Upstream NXDOMAINs escape it today because of this bug. **A fix for #244 starts charging them**, so test the shipped config (/24, 50/s) against a client that legitimately produces many upstream NXDOMAINs before merging it. Local-server NXDOMAINs are exempt through the cache's `FLAG_LOCAL_DNS` bit.

**Reproduce:**
1. Run the binary with 1.1.1.1 as upstream (see [[runtime-verification-recipe]]).
2. Query `dig dnssec-failed.org A` twice. Both queries return SERVFAIL, the second one from cache.
3. In `query_log`, both rows show `response_status = 'NOERROR'` and the second has `cache_hit = 1`.
4. `no-such-name-241.iana.org` shows the same thing with NXDOMAIN.
5. For the TTL, read `GET /api/cache/entries` with auth disabled: all three entries show `"ttl": <cache_ttl>`. Don't rely on waiting past the SOA negative TTL instead. The negative cache clamps to 300–3600 s, so the fixed code would also still answer from cache 70 s after a `*.google.com` NXDOMAIN, whose SOA negative TTL is 60 s.

**Status:** pre-existing, filed as issue #244 on 2026-09-23 and still open. It was re-verified at runtime on `2175a35`, after #241 merged, and nothing had changed. The PR #241 author spotted the NXDOMAIN half. The review confirmed it at runtime and extended it to SERVFAIL and NODATA. The #241 review follow-ups are issues #245–#247. Related: [[dns-resolution-wire-data-invariant]].
