---
name: upstream-hostname-startup-only-resolution
description: Upstream hostnames used to be looked up once, via the system resolver only (#250); PR #255 asks local_dns_server first and retries; resolved hostnames are re-looked-up at their TTL on branch fix/upstream-hostname-refresh
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

**IP refresh (branch `fix/upstream-hostname-refresh`, 2026-10-23):** resolved hostnames used to
keep their IPs until a restart or save. A retry run for another server also dropped a resolved
hostname's IPs when its own lookup failed. Now:
- `run_hostname_refresh` (`load_balancer/hostname_refresh.rs`) keeps one pending lookup per
  hostname server, due at its answer's TTL. The TTL comes from `ResolvedHost.ttl`, the router's
  min TTL (`lookup_host` gives none, so 5 min), clamped to [60 s, 1 h]. Failures back off from the
  health interval to 300 s.
- It replaced `start_hostname_retry_task` and `retry_unresolved`.
- `PoolManager::refresh_hostname` patches only that server's groups via `assemble`, swaps only
  when the address *set* changed (`compare_and_swap`), and forgets the replaced transports.
- A failed lookup keeps the previous group (`kept_group`), on reloads too.
- `apply` notifies `reloaded`, so a reload's new servers are armed at once.

Without `local_dns_server`, the circular setup still fails; it is only explained, by design.

**Repro without root (2026-09-25):** `unshare -rm`, then bind-mount a `resolv.conf` with
`nameserver 127.0.0.1` (nothing listening there) over `/etc/resolv.conf`. Also bind-mount an
`nsswitch.conf` with `hosts: files dns`, because this machine's nss-resolve otherwise goes
straight to systemd-resolved. Then exec the binary. In that namespace a hostname DoQ upstream
fails and an IP one works. Related: [[upstream-url-parser-js-mirror]], [[runtime-verification-recipe]].
