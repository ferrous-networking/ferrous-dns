---
name: dns-resolution-wire-data-invariant
description: A resolver path that returns a DnsResolution without upstream_wire_data silently drops every non-A/AAAA answer — the defect behind issue #217 / PR #218
type: project
---

`DnsResolution.addresses` only ever holds A/AAAA rdata — `ResponseParser` lifts
those two record types and nothing else. Every other type a client asks for
(PTR, SRV, TXT, MX) reaches the client **only** through `upstream_wire_data`,
the verbatim upstream message the server relays with its answer, authority and
additional sections.

That is what issue #217 was. `CoreResolver::resolve_local_tld` built its
resolution with `upstream_wire_data: None`, so a LAN reverse lookup forwarded to
`local_dns_server` was answered correctly by the router and then handed to the
client as an empty NXDOMAIN. PR #218 (author `pwnflakes`, reviewed and approved
2026-09-06) sets `upstream_wire_data: Some(response.raw_bytes)` at
`crates/infrastructure/src/dns/resolver/core.rs:93`, keeps the reasoning as a
comment at lines 89-92, and adds
`crates/infrastructure/tests/local_dns_server_ptr_test.rs`
(`local_dns_server_ptr_relayed_on_wire`, `local_dns_server_a_record_populates_addresses`).

**Why:** the symptom is an empty answer, which points at blocking or NXDOMAIN
synthesis rather than at a missing struct field — it costs an hour to find the
first time and the same hour the second time.

**How to apply:** when adding or changing any path that constructs a
`DnsResolution`, carry the upstream wire bytes unless the answer is genuinely
synthesized locally, and cover it with a **non-address** record type; an
A-record test passes either way and proves nothing. The hostname-display path is
not a counter-example: `PtrHostnameResolver`
(`crates/infrastructure/src/system/hostname_resolver.rs:76`) queries
`local_dns_server` itself and reads `RData::PTR` out of `raw_answers`, never
touching `upstream_wire_data`. Related: [[local-dns-forwarder-unhardened]].
