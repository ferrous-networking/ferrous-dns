# Changelog

Ferrous DNS uses [Conventional Commits](https://www.conventionalcommits.org/) and [git-cliff](https://git-cliff.org/) to write its changelog. Every release pull request adds a section to [`CHANGELOG.md`](https://github.com/ferrous-networking/ferrous-dns/blob/main/CHANGELOG.md) in the repository root; the per-release notes below are included from that file, and each one is also published on [GitHub Releases](https://github.com/ferrous-networking/ferrous-dns/releases) together with the binaries.

---

## Version History

| Version | Highlights | Status |
|:--------|:-----------|:------:|
| v0.10.x | API v1 freeze (`/ferrous/api/v1`, public JSON `/health`, one pagination envelope, error statuses for failed config saves, a reference for every route), Docker healthcheck on the running server, mDNS client names, query-log disk reclaim + hourly rollups, upstream NXDOMAIN budget | Released |
| v0.9.x | Upstream anti-spoofing (0x20, DNS Cookies, response validation), DNSSEC validation enforcement + DS denial proofs, DoQ server listener, DNS64, TOTP/2FA + passkeys, custom sinkhole IP, conditional forwarding per client group, DNS Filter what-if backtest, Cache Control page + per-entry cache refresh, overload shedding, Pi-hole v6 conformance, offline web UI | Released |
| v0.8.x | Config export/import, Prometheus metrics, OpenAPI docs, Extended DNS Errors (RFC 8914), DNS Cookies (RFC 7873), optimistic prefetch, configurable block response, hot-reload of upstream pools | Released |
| v0.7.x | HTTPS, auth, API tokens, rate limiting, DNS tunneling detection, DGA detection, NXDomain hijack detection, response IP filtering (C2 blocking) | Released |
| v0.6.x | In-flight coalescing, TSC timer, Pi-hole API compat, benchmark suite | Released |
| v0.5.0 | DoH/DoT server-side, PROXY Protocol v2, auto PTR, DNS rebinding protection | Released |
| v0.4.0 | Parental controls, per-group time-based scheduling | Released |
| v0.3.0 | DoQ + HTTP/3 upstreams, CNAME cloaking, Safe Search, blockable services | Released |
| v0.2.0 | Blocklists, allowlists, client groups, wildcard/regex blocking | Released |
| v0.1.0 | Foundation — DNS resolver, cache L1/L2, REST API, Web UI | Released |

See the [Roadmap](roadmap.md) for upcoming features. Releases up to v0.9.3 are listed only on [GitHub Releases](https://github.com/ferrous-networking/ferrous-dns/releases).

---

--8<-- "CHANGELOG.md:releases"
