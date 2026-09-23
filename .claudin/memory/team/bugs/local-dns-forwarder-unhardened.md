---
name: local-dns-forwarder-unhardened
description: DnsForwarder — the local_dns_server / conditional-forwarding path — skipped every anti-spoofing check the pool path applies; fixed by PR #240 (2026-09-23), which shares the pool path's validation
type: project
paths: crates/infrastructure/src/dns/forwarding/forwarder.rs, crates/infrastructure/src/dns/resolver/core.rs
---

**Status: fixed 2026-09-23 by PR #240** (`fix(dns): validate local_dns_server answers like upstream answers`).

Before #240, `DnsForwarder::query` built its query with `MessageBuilder::build_query`,
sent it on a bare connected `UdpSocket` and parsed the first datagram back — no 0x20,
no DNS cookie, no transaction-ID or question check, no canonicalization. It is the
path for every private-range PTR and every name under `local_domain`, and since
PR #218 its raw answer is relayed to clients verbatim — pre-existing exposure that
#218 widened, raised in that review as a follow-up that was never filed as an issue.

Now `DnsForwarder` (`crates/infrastructure/src/dns/forwarding/forwarder.rs`) uses
`build_query_hardened`, the shared UDP transport (source + TXID filtering, IPv6-aware
bind), `ResponseValidator::validate` + `canonicalize`, and a TCP retry on TC=1. Both
callers take `PoolManager::hardening()`, so `qname_case_randomization` applies to the
local server too.

**How to apply:** a router that rewrites query-name case fails every local answer
when 0x20 is on; `CoreResolver` logs it as `Local DNS server query failed` and the
client gets NXDOMAIN — point users there before suspecting the resolver. Regression
tests: `crates/infrastructure/tests/local_forwarder_spoofing_test.rs`.
Related: [[dns-resolution-wire-data-invariant]].
