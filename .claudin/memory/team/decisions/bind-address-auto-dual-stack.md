---
name: bind-address-auto-dual-stack
description: PR #385 (2026-11-10) made bind_address "auto" the default, meaning [::]; PR #387 (23320c21, 2026-11-12, closes #386) added AF_INET listeners and the IPv4 fallback for "auto" on kernels without IPv6; explicit addresses, "0.0.0.0" and "[::]" included, never change
type: project
scope: config/server, cli/server listeners, docker
impact: functional
paths:
  - crates/domain/src/config/server.rs
  - crates/cli/src/bootstrap/listen.rs
  - crates/cli/src/server/listener_socket.rs
  - crates/cli/src/server/dns/pktinfo.rs
  - crates/cli/src/server/web.rs
  - docker/entrypoint.sh
---

**Decision:** `[server] bind_address = "auto"` is the default. It applies when there is no config file, when the key is missing, and in the shipped `ferrous-dns.toml`. It means `[::]`, or `0.0.0.0` on a kernel without IPv6. Every explicit address, `"0.0.0.0"` and `"[::]"` included, binds exactly what it says. #385 (`c2839ba6`, merged 2026-11-10) shipped `"auto"` for issue #375; #387 (`23320c21`, merged 2026-11-12, closes #386) added the IPv4 fallback.

**Why:**
- In #375, IPv6-only clients got no answers, because every shipped config bound `0.0.0.0`. Viudes promised publicly on 2026-11-07 that `"auto"` becomes the default, `[::]` with IPv6 and `0.0.0.0` without, and that `"0.0.0.0"` stays IPv4-only ([[upgrades-keep-existing-behaviour]]).
- #385 shipped without the fallback: every DNS listener was AF_INET6, so on a kernel booted with `ipv6.disable=1` DNS could not start even on `0.0.0.0`, and a probe would only have kept the dashboard up. #386 made the listeners follow the address family, which is what makes the fallback serve DNS.

**What changes for a teammate:**
- Every listener opens its socket through `open_listener_socket` (`crates/cli/src/server/listener_socket.rs`): AF_INET for an IPv4 address, AF_INET6 with `only_v6(false)` for an IPv6 one. A `socket()` failing with `EAFNOSUPPORT` on an IPv6 address becomes an error that names the address and says the kernel has no IPv6. The callers keep their own options: DNS sets `SO_REUSEPORT`, the web and DoH listeners (`bind_web_listener`) must not, or a second instance would silently share the port.
- The error's advice is "listen on an IPv4 address instead", never `bind_address = "auto"`. The address may come from `web_bind_address` or a per-listener override, which take an IP and win over `bind_address`.
- Linux is the supported platform. The non-Linux UDP loop builds on macOS, but not on FreeBSD or OpenBSD, whose libc has no `IP_PKTINFO`. That is a documented limit, not a `cfg` gate on the hot path.
- The UDP hot path (`pktinfo.rs`) handles both families. AF_INET reads `IP_PKTINFO`'s `ipi_addr`, the header destination, as the mapped `IPV6_PKTINFO` does, and sends with `ipi_spec_dst` and `ipi_ifindex = 0`. The kernel's `ip_cmsg_send` treats a mapped IPV6_PKTINFO the same way, so IPv4 replies behave identically on both socket families. Received addresses are decoded by their family. The send side needs the socket's family, which `create_udp_socket` returns with the socket.
- `"auto"` is resolved only in a listen-only copy, `bootstrap::resolve_listen_config` in `main.rs`. It probes `socket(AF_INET6)` once, and only `EAFNOSUPPORT` counts as no IPv6. A sandbox's `EACCES` is left to the bind. The stored config (`config_arc`), `GET /config`, saves and backups keep the string `"auto"`. The fallback is logged at `info!`. A sysctl-disabled IPv6 (`net.ipv6.conf.all.disable_ipv6 = 1`) still creates IPv6 sockets, so `"auto"` stays dual-stack there.
- Only `[server] bind_address` accepts `"auto"`; `web_bind_address` and the per-listener overrides stay IP-only, and an IPv6 one fails on such a kernel.
- A dual-stack socket reports IPv4 peers as `::ffff:a.b.c.d`. The `canonical_peer` layer in `web.rs` rewrites `ConnectInfo` to the plain address, and the DNS transports unmap at their edge. AF_INET sockets report plain IPv4, so the unmapping is a no-op there.
- Docker: the images and `docker-compose.yml` no longer set `FERROUS_BIND_ADDRESS`. The entrypoint still skips the value `0.0.0.0` and prints a NOTICE, so `-e FERROUS_BIND_ADDRESS=0.0.0.0` cannot force IPv4 over a file that says `"auto"` ([[docker-database-path-ignores-image-default]]).
- The upgrade exception: an install with no config file, or with no `bind_address` key, starts serving IPv6 too. The docs' Upgrading section names it. An older release rejects `"auto"` in the config file and in backups, so a rollback needs an address in the file first.
- Tests: `crates/cli/tests/server_process` can take IPv6 away from the real binary with a seccomp filter (`start_without_ipv6`, `command_without_ipv6(errno)`), unprivileged and CI-safe; under `CI` a missing filter fails the test instead of skipping it. The `only_v6(false)` guards only bite with `net.ipv6.bindv6only = 1`, which needs `unshare -rn` ([[runtime-verification-recipe]]) and cannot run in CI.

**Rejected:**
- An AF_INET socket only when AF_INET6 fails (#386): every bind would grow a fallback, and the AF_INET path would only ever run under the no-IPv6 simulation. Following the address is behaviour-identical for IPv4 clients and puts every `0.0.0.0` install on it.
- Resolving `"auto"` inside the five `*_listen_address` helpers with an `ipv6_supported: bool`, or applying the fallback to `config` before `config_arc` is built: the first threads I/O knowledge through the domain, the second persists `0.0.0.0` on the next save.
- A fallback for an explicit `"[::]"`: an explicit address binds exactly what it says.
- `Option<IpAddr>` with `None` meaning auto: `--bind auto` would become `Option<Option<_>>`, and persistence would need a sentinel anyway.
- Canonicalising the peer in each handler that reads it: every future handler would have to remember it.
- Passing `FERROUS_BIND_ADDRESS=0.0.0.0` through as `--bind`: it would undo every Docker volume whose file was edited to `[::]`, after Viudes told Docker users that editing the file is enough.
- Moving `"0.0.0.0"` configs to dual-stack: it breaks the public promise and the upgrade rule. Existing volumes say `"0.0.0.0"` and stay IPv4-only until their owner edits the file.

**Evidence:** plans `.claudin/plans/tidy-knitting-pony.md` (#385) and `.claudin/plans/misty-giggling-moore.md` (#386); PR #385 (`c2839ba6`). #386's live check ran main × branch under `systemd-run --user -p RestrictAddressFamilies="AF_INET AF_UNIX AF_NETLINK"`. Main's `"auto"` exited with os error 97, and main's `"0.0.0.0"` served no DNS (`/health` 503). The branch answered on both, and its `"[::]"` failed with the new message.
