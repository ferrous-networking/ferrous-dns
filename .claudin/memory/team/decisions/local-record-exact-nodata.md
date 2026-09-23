---
name: local-record-exact-nodata
description: PR #227 made an exact local A/AAAA record authoritative for its whole name, so every other record type answers NODATA — including on public names used for split-horizon
type: project
scope: dns/local-records
impact: functional
---

PR #227 (approved 2026-09-19, fbernier) closed the gap where a configured local
record only shadowed its own record type. Before it, an `AAAA` query for an
A-only `nas.home.lan` was forwarded upstream and came back NXDOMAIN. Now
`CachedResolver::check_cache_str` asks the cache for ownership *before* the
ordinary lookup and answers NODATA (`NOERROR`, zero answers) when the name is
owned but the type is not configured.

Mechanics: `DnsCache` replaced `permanent_keys: DashSet<CacheKey>` with
`permanent_records: DashMap<CompactString, SmallVec<[RecordType; 2]>>`, and
`local_record_status()` returns `Present` / `MissingType` / `NotLocal`. Only
A/AAAA can ever enter that map — the config preload
(`cli/src/wiring/dns/cache.rs`) and the local-records admin use cases both
reject anything else — so the `NotLocal` arm for a name holding only
non-address permanent types is dead in production.

**This is the same semantic wildcards already had** (`LocalWildcardResolver`
answers NODATA for a type the wildcard does not carry) and it matches dnsmasq's
`--address=` behaviour. The PR makes exact records consistent with wildcards;
it is not an accident. See [[wildcard-local-records]].

**The consequence to remember: it applies to public names too.** Verified at
runtime by overriding `www.iana.org` with a local A — `AAAA`, `MX` and `TXT`
then return NODATA where upstream would have returned the Cloudflare CNAME and
its AAAA records. Anyone pinning only an IPv4 address for a split-horizon name
silently breaks IPv6 for it; the fix is to configure the AAAA as well. With
`dns64_prefix` set the same shadowing applies, because `Dns64Resolver` is wired
*below* the cache, so a locally overridden name can no longer get a synthesized
AAAA.

**Still open after the PR:** the NODATA response carries no SOA in AUTHORITY and
no AA bit (`dns/server.rs`, `handle_raw_udp_fallback`). RFC 2308 §2.2 wants the
SOA so a downstream forwarding resolver can negatively cache. Pre-existing —
the wildcard NODATA path has the same shape — and stub resolvers do not care,
so it was left as a follow-up. The fix would reuse `synthetic_block_soa`, which
already synthesizes an SOA for blocked answers, on both NODATA paths at once.

`has_response_data()` now returns `true` whenever `local_dns` is set, so the
name no longer matches what it does: a local NODATA has no response data by
definition. Do not "simplify" it back.
