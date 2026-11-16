---
name: runtime-fake-upstream-and-network
description: Runtime tricks beyond the base recipe — a fake UDP upstream for cache load (malware off, non-reserved names, RssAnon), watching renewals at TTL 60, faking the resolver without root, IPv6 bindv6only via unshare, Secure cookies on loopback
type: project
---

Part of [[runtime-verification-recipe]], which has the base config, ports and how to stop instances.

**Driving cache load with a fake upstream** (used 2026-10-16 for the cache-removal A/B):
- **The responder:** a ~20-line Python UDP script that copies the question and answers `A 192.0.2.1` for every name works as the only upstream. Answer other types with an empty NOERROR. Copying the question bytes as received keeps the 0x20 case check happy.
- **Turn malware detection off.** Set `malware_detection_enabled = false` in `[dns]`. Otherwise the NXDomain hijack detector sees the catch-all answer its `.invalid` probes, and turns every answer into NXDOMAIN. DGA may also flag the random names.
- **Pick a non-reserved domain.** Names under `.test` come back NXDOMAIN locally, so use something like `n123.live-ab.ferrous-bench.net`.
- **Watch the cache:** `GET /ferrous/api/v1/cache/metrics` has `total_entries`, `evictions` and `compactions`.
- **Compare memory with `RssAnon`, not `VmRSS`.** With the DB on tmpfs (the scratchpad), the mmapped database counts as `RssShmem` and swamps the difference.

**Watching renewals live:**
- Set `cache_min_ttl = 60` and `cache_max_ttl = 60` in `[dns]`. Every entry then renews about every 45 s, for as long as it is inside `cache_access_window_secs`.
- Don't go below 60. A TTL under `REFRESH_LEAD_SECS` (60) only renews if a client asked for the entry since the last renewal (`is_worth_renewing` in `refresh.rs`). A 20 s clamp with no traffic left an empty cache within 40 s (seen 2026-10-17).
- Each renewal writes a `cache_refresh = 1` row to `query_log`. Those rows match the per-entry `refreshes` in `GET /ferrous/api/v1/cache/entries` one to one.

**Faking this machine's resolver without root:**
- Run the binary under `unshare -rm`, with a `resolv.conf` and an `nsswitch.conf` (`hosts: files dns`) bind-mounted over `/etc`.
- Mounting only `resolv.conf` does nothing here, because nss-resolve goes straight to systemd-resolved.
- The full recipe is in [[upstream-hostname-startup-only-resolution]].

**IPv6 socket behaviour without root:**
- Under `unshare -rn`, run `ip link set lo up` and `echo 1 > /proc/sys/net/ipv6/bindv6only`. A `[::]` listener that leaves `IPV6_V6ONLY` to the sysctl then refuses IPv4 clients.
- #385's red proof for the web listeners ran this way on 2026-11-09 ([[bind-address-auto-dual-stack]]).
- CI cannot run it, because Ubuntu 24.04 runners restrict unprivileged user namespaces.

**Secure-cookie behaviour cannot be reproduced on loopback:** curl and browsers both treat `127.0.0.1` as a secure context, and accept a `Secure` cookie over plain HTTP. Bind to the host's LAN address (`--bind <lan-ip>`) to observe the real rejection. This is why [[web-tls-secure-cookie-invariant]] went unnoticed in local development.
