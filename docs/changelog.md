# Changelog

Ferrous DNS uses [Conventional Commits](https://www.conventionalcommits.org/) and [git-cliff](https://git-cliff.org/) for automated changelog generation.

The full changelog is published with each release on GitHub:

**[View Changelog on GitHub Releases](https://github.com/ferrous-networking/ferrous-dns/releases)**

---

## Version History

| Version | Highlights | Status |
|:--------|:-----------|:------:|
| v0.8.0 | Config export/import, query log export, Prometheus metrics, OpenAPI docs | In Progress |

### v0.8.2 — DNS Cookies

#### Added

- RFC 7873 DNS Cookies (EDNS option 10) — server-side anti-spoofing and amplification protection with HMAC-SHA256 server cookies, secret rotation, and permissive/strict enforcement modes.
| v0.7.x | HTTPS, auth, API tokens, rate limiting, DNS tunneling detection, DGA detection, NXDomain hijack detection, response IP filtering (C2 blocking) | Released |
| v0.6.x | In-flight coalescing, TSC timer, Pi-hole API compat, benchmark suite | Released |
| v0.5.0 | DoH/DoT server-side, PROXY Protocol v2, auto PTR, DNS rebinding protection | Released |
| v0.4.0 | Parental controls, per-group time-based scheduling | Released |
| v0.3.0 | DoQ + HTTP/3 upstreams, CNAME cloaking, Safe Search, blockable services | Released |
| v0.2.0 | Blocklists, allowlists, client groups, wildcard/regex blocking | Released |
| v0.1.0 | Foundation — DNS resolver, cache L1/L2, REST API, Web UI | Released |

See the [Roadmap](roadmap.md) for upcoming features.
