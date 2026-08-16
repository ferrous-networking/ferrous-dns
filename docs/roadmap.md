# Roadmap

Current release: **v0.9.11**

The milestone list below is included verbatim from [`ROADMAP.md`](https://github.com/ferrous-networking/ferrous-dns/blob/main/ROADMAP.md) in the repository root, which is the single source of truth for what is shipped. Edit that file — this page cannot drift from it, and the docs build fails if the include is removed or the version above stops matching `Cargo.toml`.

---

--8<-- "ROADMAP.md"

---

## RFC Compliance

| RFC | Topic | Status |
|:----|:------|:------:|
| RFC 1035 | DNS basics — A, AAAA, CNAME, MX, TXT, PTR | Done |
| RFC 6891 | EDNS0 OPT records, 1232-byte upstream payload | Done |
| RFC 7766 | DNS over TCP, TC=1 truncation semantics | Done |
| RFC 7858 | DNS-over-TLS (DoT) — server + upstream | Done |
| RFC 8484 | DNS-over-HTTPS (DoH) — server + upstream | Done |
| RFC 9250 | DNS-over-QUIC (DoQ) — server + upstream | Done |
| RFC 9114 | HTTP/3 upstream | Done |
| RFC 4035 / RFC 6840 | DNSSEC validation — AD/CD handling, SERVFAIL on Bogus in strict mode | Done |
| RFC 5155 / RFC 9276 | NSEC3 denial of existence, incl. opt-out and parameter limits | Done |
| RFC 7873 | DNS Cookies — client side always on, server side configurable | Done |
| RFC 8914 | Extended DNS Errors (EDE) | Done |
| RFC 6147 | DNS64 AAAA synthesis (`64:ff9b::/96`) | Done |
| RFC 6761 | Special-use names (`.invalid` probes for NXDOMAIN hijack detection) | Done |
| [PROXY Protocol v2](https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt) | Real client IP behind load balancers (HAProxy spec) | Done |
| draft-vixie-dns-0x20 | QNAME case randomization | Done (opt-in) |
| RFC 7871 | EDNS Client Subnet — strip by default, optional injection | Planned |
| RFC 5011 | Automated trust anchor rollover | Planned |
| RFC 7828 | edns-tcp-keepalive | Planned |

See [Security Hardening](features/security-hardening.md) for what each of the security-related entries actually does and where it stops.

---

## Release history

Per-version highlights live in the [Changelog](changelog.md); full release notes are published on [GitHub Releases](https://github.com/ferrous-networking/ferrous-dns/releases).
