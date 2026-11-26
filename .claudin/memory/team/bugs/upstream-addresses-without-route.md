---
name: upstream-addresses-without-route
description: Issue #402 — on a host/container without IPv6, hostname upstreams showed Partial forever (AAAA addresses failing connect every 30 s); fixed by PR #406 (13e76d27, merged 2026-11-23) with a route probe in the health checker, ServerStatus::NoRoute and a no_route API field
type: project
paths:
  - crates/infrastructure/src/dns/transport/route.rs
  - crates/infrastructure/src/dns/load_balancer/health.rs
  - crates/infrastructure/src/dns/load_balancer/upstream_health_adapter.rs
  - web/static/shared.js
---

**Symptom (v1.0.0, #402):** in Docker on the default bridge (no IPv6), `tls://security.cloudflare-dns.com:853` resolved to 2 A + 2 AAAA. The IPv6 rows went Unhealthy with `Connection refused by TLS server …: Address not available (os error 99)` (`os error 101` on another host), the server read **Partial**, and `Health check: FAILED` repeated every 30 s per address. Queries were fine: Unhealthy endpoints leave rotation.

**Cause:** `UpstreamHostResolver` asks A and AAAA and every address becomes a pool member; nothing checked whether the host could reach a family. `kernel_has_ipv6()` (bind_address "auto") cannot tell: Docker creates AF_INET6 sockets fine, only `connect()` fails.

**Fix (PR #406, `13e76d27`, merged 2026-11-23):**
- `transport::route::has_route` connects a UDP socket (nothing is sent). Only `EAFNOSUPPORT` (socket), `EADDRNOTAVAIL`, `ENETUNREACH` and `EHOSTUNREACH` mean no route; other errors count as a route.
- `HealthChecker::check_server` probes each address of `DnsProtocol::addresses()` first. If none has a route, the result is `ServerStatus::NoRoute`: out of rotation at once, with no threshold, nothing sent, one `info!`. When the route is back, the server resets to `Unknown`. For https/h3 (one protocol, many addresses) the unroutable ones go in `ServerHealth.unroutable` for display. `with_route_probe` is the test seam.
- API: `no_route: bool` per `resolved` entry. It is a new field, not a new status value, because `docs/api.md` only promises new fields for v1. The row keeps `status: "Unhealthy"`. The aggregate ignores no-route rows; with none left, it is Unhealthy.
- UI: grey "No route" badge, a line under the server, and a `.notice-info` at the top of the card, on Dashboard and Settings.

**Rejected:** filtering at resolution time (a `skipped` list through the resolver, `ServerGroup`, the refresh compare and the API, and IPv6 coming back only at the next hostname refresh, up to 1 h); a `NoRoute` status value in the API.

**Repro without root:** `crates/cli/tests/upstream_no_route_live_test.rs` runs the binary under the seccomp no-IPv6 filter (`start_without_ipv6`) with a FakeUpstream as both router and upstream. Live: a host binary mounted into `archlinux:latest` on Docker's default bridge (glibc matches the host).

**Open, unfiled:** the per-IP rows of https/h3 still copy one per-URL probe, and h3 dials only `first()` with a pool keyed by `host:port`. Viudes chose not to file an issue for it. Related: [[upstream-hostname-startup-only-resolution]], [[bind-address-auto-dual-stack]].
