---
name: upstream-hostname-startup-only-resolution
description: Upstream hostnames used to be looked up once, via the system resolver only, so a host resolving through ferrous-dns itself never got its upstreams (#250); PR #255 asks local_dns_server first and retries in the background
type: project
paths: crates/infrastructure/src/dns/load_balancer/pool.rs, crates/infrastructure/src/dns/transport/resolver.rs, crates/cli/src/wiring/dns/pool.rs
---

**Symptom (0.9.18 and earlier):** a `doq://`/`tls://`/`udp://`/`tcp://` upstream given by hostname
failed every query with "QUIC transport requires resolved address, got: host:853" if its lookup
failed at startup, and stayed that way until a restart or pool save. To users this looked like
"hostnames aren't supported". That was issue #250: the reporter's
`doq://dns.adguard-dns.com:853` and private `…d.adguard-dns.com:853` both failed, even after a
restart.

**Why a retry alone could not fix it:** when the host's resolver is ferrous-dns itself and every
upstream is a hostname, a later lookup goes to ferrous-dns, which has no resolved upstream to
answer with. The loop needs a resolver outside it. `docs/troubleshooting.md` "Port 53 Already
in Use" told users to write `nameserver 127.0.0.1`, which sets up exactly that loop; #255
changed the advice.

**Fix (PR #255, `235cc81`):** `UpstreamHostResolver` (`transport/resolver.rs`) asks
`local_dns_server` for A+AAAA first (hardened `DnsForwarder`, 2s) and then falls back to
`lookup_host`. `PoolManager::with_host_resolver` keeps it for build, reload and retry.
`start_hostname_retry_task` (`cli/src/wiring/dns/pool.rs`) retries unresolved servers from the
health-check interval, doubling up to 300s, and `compare_and_swap`s so a UI reload is never
overwritten. The unresolved error now reads "… has no IP address yet … set Local DNS server".
The UI shows Local DNS server as its own always-visible field, which used to be hidden unless
a local domain was set. Accepted tradeoff: when the router answers, an `/etc/hosts` pin for an
upstream hostname is not consulted.

**Still open:** hostnames that did resolve are never refreshed, so an upstream that changes IPs
keeps the old ones until a restart or save. Without `local_dns_server`, the circular setup still
fails; it is only explained, by design.

**Repro without root (2026-09-25):** `unshare -rm`, then bind-mount a `resolv.conf` with
`nameserver 127.0.0.1` (nothing listening there) over `/etc/resolv.conf`. Also bind-mount an
`nsswitch.conf` with `hosts: files dns`, because this machine's nss-resolve otherwise goes
straight to systemd-resolved. Then exec the binary. In that namespace a hostname DoQ upstream
fails and an IP one works. Related: [[upstream-url-parser-js-mirror]], [[runtime-verification-recipe]].
