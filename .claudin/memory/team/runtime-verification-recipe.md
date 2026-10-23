---
name: runtime-verification-recipe
description: Minimal standalone config and steps to run ferrous-dns locally for runtime verification, including the required TOML sections, TOML enum casing, the admin-username gotcha, killing instances safely, and driving cache load with a fake upstream
type: project
---

Running the ferrous-dns binary against a throwaway config for runtime verification (not tests) needs more than a stub TOML. `Config` has no `#[serde(default)]` on `server`, `dns`, `blocking`, `logging` or `database`, so all five tables must be present. Validation also rejects a config that has neither `dns.upstream_servers` nor a `[[dns.pools]]` (`root.rs:79`). With a pool, `upstream_servers = []` is fine.

A pool's `strategy` in the TOML is case-sensitive: write `"Parallel"`, `"Failover"` or `"Balanced"`. Lowercase `"parallel"` stops startup with `unknown variant`, even though the `/api/config` JSON and the Settings form use lowercase. The same goes for `dnssec_mode`: write `"Off"`, `"Permissive"` or `"Strict"`; `"off"` fails to load (seen 2026-10-16).

Working minimal config:

```toml
[server]
dns_port = 15353
web_port = 18080
bind_address = "127.0.0.1"

[dns]
upstream_servers = ["1.1.1.1:53"]

[blocking]
enabled = true

[logging]
level = "info"

[database]
path = "/tmp/<workdir>/ferrous.db"

[auth]
enabled = true
```

Run it from a directory containing a `migrations` symlink to the repo's `migrations/` — the app resolves `./migrations` relative to the working directory, not the config path.

**Stop that instance before running `make ci`, or pick another DNS port** (25353 worked on 2026-10-16). `crates/infrastructure/tests/helpers/dns_server_mock.rs:104` binds port **15353**, the same port as the config above. A verification instance still running there makes `test_mock_server_starts` fail with a bare `assertion failed: result.is_ok()`, which looks nothing like a port conflict.

**Main × branch side by side:** before the first edit, build `main` and copy `target/debug/ferrous-dns` to the scratchpad. Then run it and the branch build on different web/DNS ports, each in its own directory with its own `migrations` symlink, and diff the same curl script's output.

**Stopping instances:** a plain `pkill -f` pattern also matches the shell running it. So does `kill $(pgrep -f ...)`, which on 2026-10-16 killed the calling shell with exit 144. Bracket one character instead: `pkill -f "[f]errous-dns-fix --config"`. The bracket does not help when the same Bash call also starts the binary: the unbracketed `…/ferrous-dns-main --config` text further down that command line still matches, and the shell dies with exit 144. Start instances from a script file, and stop them in a separate call.

**Driving cache load with a fake upstream** (used 2026-10-16 for the cache-removal A/B):
- **The responder:** a ~20-line Python UDP script that copies the question and answers `A 192.0.2.1` for every name works as the only upstream.
- **Turn malware detection off.** Set `malware_detection_enabled = false` in `[dns]`. Otherwise the NXDomain hijack detector sees the catch-all answer its `.invalid` probes and turns every answer into NXDOMAIN, and DGA may flag the random names.
- **Pick a non-reserved domain.** Names under `.test` come back NXDOMAIN locally, so use something like `n123.live-ab.ferrous-bench.net`.
- **Watch the cache:** `GET /api/cache/metrics` has `total_entries`, `evictions` and `compactions`.
- **Compare memory with `RssAnon`, not `VmRSS`.** With the DB on tmpfs (the scratchpad), the mmapped database counts as `RssShmem` and swamps the difference.

**Watching renewals live:** set `cache_min_ttl = 60` and `cache_max_ttl = 60` in `[dns]`, and every entry renews about every 45 s for as long as it is inside `cache_access_window_secs`. Don't go below 60. A TTL under `REFRESH_LEAD_SECS` (60) only renews if a client asked for the entry since the last renewal (`is_worth_renewing` in `refresh.rs`), so a 20 s clamp with no traffic leaves an empty cache within 40 s (seen 2026-10-17). Each renewal writes a `cache_refresh = 1` row to `query_log`, and those rows match the per-entry `refreshes` in `GET /api/cache/entries` one to one.

To reach an authenticated session: `POST /api/auth/setup {"password": "..."}` returns 204 and writes the Argon2 hash into the config file, but the running process keeps its startup snapshot of `[auth]`, so **restart before logging in**.

**Admin username:** since PR #251 (merged 2026-09-25 as `e75ba8c`), `AdminConfig` has a hand-written `Default` with `username = "admin"` (`domain/src/config/auth.rs:121-124`). A config with no `[auth.admin]` table now logs in as `admin`. Before #251 the username came out empty and every login returned 401, so only builds older than `e75ba8c` still need `username = "admin"` set by hand.

**Verifying blocklist behaviour:** query with `dig @127.0.0.1 -p 15353 <domain>`; under the default `block_mode = "null_ip"` a blocked name answers `0.0.0.0` with `EDE 15 (Blocked)`. The trustworthy "my list actually loaded" signal is the `Fetched blocklist source url=…` log line, **not** the `exact=` count in `Block index compiled` — a 224k-entry HaGeZi list logs `exact=0` because its entries parse as wildcards. A source whose URL 404s is only `warn!`-logged and the reload still reports success, so always check for the fetch line per URL. See [[issue-216-blocklist-sync]].

**Scripting the API without a session:** with `[auth] enabled = false` every `/api/*` route answers plain curl, which is the quickest way to run a request matrix. Expected noise in the browser console then: a 401 on `/api/auth/2fa/status` and the known 404 on `/api/health/upstreams`. The Tailwind CDN warning went away with #271, which vendored every asset.

**Saving pools from the Settings UI on this minimal config** (the pool editor is on the **DNS Advanced** tab) returns "Restart the server for the changes to take effect" on the first save. The form sends every `dns` field, and they differ from the stub file. Once the file has been written, later pool-only saves report "applied immediately" (seen 2026-10-16). To confirm the pool went live, check `GET /api/upstream/health/detail` or the `/api/config` pools.

**Docs check:** `mkdocs build --strict` (`site/` is gitignored; pull requests that touch the docs run the same build in `docs.yml`).

**Faking this machine's resolver without root:** run the binary under `unshare -rm` with a `resolv.conf` and an `nsswitch.conf` (`hosts: files dns`) bind-mounted over `/etc`. Mounting only `resolv.conf` does nothing here, because nss-resolve goes straight to systemd-resolved. The full recipe is in [[upstream-hostname-startup-only-resolution]]. Watch out for `pkill -f <pattern>`: the pattern also matches the shell running it, which kills your own command.

**Secure-cookie behaviour cannot be reproduced on loopback:** curl and browsers both treat `127.0.0.1` as a secure context and accept a `Secure` cookie over plain HTTP. Bind to the host's LAN address (`--bind <lan-ip>`) to observe the real rejection. This is why [[web-tls-secure-cookie-invariant]] went unnoticed in local development.
