# Roadmap

Current release: **v0.9.24**

What comes next is tracked on GitHub: one issue per item, grouped into milestones. Each milestone page lists its open and closed issues and shows how far along it is. When a release ships, its milestone is closed and lists every pull request in it and the issues they fixed, whichever milestone they were planned in; what it did not get to moves to the next milestone. What already shipped is in the [Changelog](changelog.md).

| Milestone | Goal |
|:----------|:-----|
| [v0.10.0 — API v1](https://github.com/ferrous-networking/ferrous-dns/milestone/1) | Freeze the Ferrous API at `/ferrous/api/v1`: a public health endpoint, error statuses that mean what they say, one pagination style, and a reference that covers every route |
| [v1.0.0 — Production Ready](https://github.com/ferrous-networking/ferrous-dns/milestone/2) | A production deployment guide, a security review, no config keys that do nothing, and the known correctness bugs fixed |
| [v1.1.0 — Next Features](https://github.com/ferrous-networking/ferrous-dns/milestone/3) | Features planned after 1.0 |

Missing something? Search the [open issues](https://github.com/ferrous-networking/ferrous-dns/issues) first, then open a [feature request](https://github.com/ferrous-networking/ferrous-dns/issues/new?template=feature_request.yml). A comment on an existing issue saying how you would use the feature helps decide what comes first.

---

## RFC Compliance

| RFC | Topic | Status |
|:----|:------|:------:|
| RFC 1035 | DNS basics — A, AAAA, CNAME, MX, TXT, PTR | Done |
| RFC 2308 | Negative caching — NXDOMAIN/NODATA cached for the SOA negative TTL (held to 300–3600 s) | Done |
| RFC 6891 | EDNS0 OPT records, 1232-byte upstream payload | Done |
| RFC 7766 | DNS over TCP, TC=1 truncation semantics | Done |
| RFC 7858 | DNS-over-TLS (DoT) — server + upstream | Done |
| RFC 8484 | DNS-over-HTTPS (DoH) — server + upstream | Done |
| RFC 9250 | DNS-over-QUIC (DoQ) — server + upstream | Done |
| RFC 9114 | HTTP/3 upstream | Done |
| RFC 4035 / RFC 6840 | DNSSEC validation — AD/CD handling, SERVFAIL on Bogus in strict mode | Done |
| RFC 5155 / RFC 9276 | NSEC3 denial of existence, incl. opt-out and parameter limits | Done |
| RFC 6605 / RFC 8080 | DNSSEC ECDSA P-256/P-384 and Ed25519 signatures | Done |
| RFC 7873 | DNS Cookies — client side always on, server side configurable (strict mode answers BADCOOKIE) | Done |
| RFC 8914 | Extended DNS Errors (EDE) | Done |
| RFC 8767 | Serve-stale — an expired answer is served while its refresh runs | Done |
| RFC 6147 | DNS64 AAAA synthesis (`64:ff9b::/96`) | Done |
| RFC 6761 | Special-use names (`.invalid` probes for NXDOMAIN hijack detection) | Done |
| [PROXY Protocol v2](https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt) | Real client IP behind load balancers (HAProxy spec) | Done |
| draft-vixie-dns-0x20 | QNAME case randomization | Done (opt-in) |
| RFC 7871 | EDNS Client Subnet — a client's ECS is never sent upstream; optional subnet injection planned ([#333](https://github.com/ferrous-networking/ferrous-dns/issues/333)) | Partial |
| RFC 5011 | Automated trust anchor rollover ([#338](https://github.com/ferrous-networking/ferrous-dns/issues/338)) | Planned |

See [Security Hardening](features/security-hardening.md) for what each of the security-related entries actually does and where it stops.

---

## Release history

Per-version highlights and the full notes of every release since v0.9.4 live in the [Changelog](changelog.md); each release's notes are also published on [GitHub Releases](https://github.com/ferrous-networking/ferrous-dns/releases).
