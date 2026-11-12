---
name: rcode-response-counters
description: PR #363 (2026-11-04) — client rcodes are one since-boot counter family, ferrousdns_responses_total{rcode}, counted where replies leave DnsServerHandler; counters at the rcode sites and a SERVFAIL table/backfill/stats field were rejected
type: project
scope: metrics
impact: functional
paths:
  - crates/application/src/response_counter.rs
  - crates/infrastructure/src/dns/server.rs
  - crates/api/src/handlers/metrics.rs
---

**Decision:** on 2026-11-04 Viudes picked one Prometheus counter family, `ferrousdns_responses_total{rcode}`. It is monotonic since boot and follows the CoreDNS shape. The labels are NOERROR, FORMERR, SERVFAIL, NXDOMAIN, NOTIMP, REFUSED and OTHER.

It is counted at `DnsServerHandler`'s three exits in `server.rs`:
- `try_fast_path` calls `record_noerror`;
- `try_fast_path_wire` and `handle_raw_udp_fallback` call `record(reply)`.

So the metric is what went on the wire. A shed query (`None`) counts nothing. It shipped in PR #363 (`82b2a778`, closes #318) and drives the SERVFAIL and REFUSED ratio alerts in `contrib/prometheus/`.

**Why:**
- The first draft bumped two ad-hoc counters at five rcode sites. A future SERVFAIL path could be missed, and the REFUSED alert leaned on a 24 h gauge.
- The name follows CoreDNS before the 1.0 freeze.
- The bench A/B was accepted: no loss under dnsperf, and about +4.8% in criterion on the hit path. NOERROR has a cache line of its own because every hit bumps it.

**What changes for a teammate:**
- A new reply path or transport must leave through those exits or call `ResponseCounters` itself. Don't count where an rcode is chosen.
- BADCOOKIE and other extended rcodes land in `OTHER`, since only the header nibble is read. The docs say so.
- The metric name and labels are now part of the 1.0 surface and of the shipped alert rules (`ferrous-dns-alerts.yml`, tested by `ferrous-dns-alerts.test.yml`).

**Rejected:**
- **Counters at the rcode sites:** a new path slips past them.
- **A SERVFAIL table with a backfill and a `/stats` field:** the need was an alertable rate, which a counter gives with no migration.

**Evidence:** plan `.claudin/plans/steady-singing-lark.md`, section "Metric" and review point 1; PR #363.
