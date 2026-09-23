---
name: runtime-verification-recipe
description: Minimal standalone config and steps to run ferrous-dns locally for runtime verification, including the required TOML sections and the admin-username gotcha
type: project
---

Running the ferrous-dns binary against a throwaway config for runtime verification (not tests) needs more than a stub TOML — `Config` has no `#[serde(default)]` on `server`, `dns`, `blocking`, `logging` or `database`, so all five tables must be present, and validation additionally rejects an empty `dns.upstream_servers`.

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

**Stop that instance before running `make ci`.** `crates/infrastructure/tests/helpers/dns_server_mock.rs:104` binds port **15353** — the same port this recipe suggests — so a still-running verification instance fails `test_mock_server_starts` with a bare `assertion failed: result.is_ok()` that looks nothing like a port conflict.

To reach an authenticated session: `POST /api/auth/setup {"password": "..."}` returns 204 and writes the Argon2 hash into the config file, but the running process keeps its startup snapshot of `[auth]`, so **restart before logging in**.

**Gotcha:** `AdminConfig` derives `Default`, so a config file with no `[auth.admin]` table gets `username = ""` rather than the `"admin"` that `default_admin_username()` supplies when the table exists without the key. After setup, set `username = "admin"` in the generated `[auth.admin]` table and restart, or every login returns 401 with "Invalid credentials".

**Verifying blocklist behaviour:** query with `dig @127.0.0.1 -p 15353 <domain>`; under the default `block_mode = "null_ip"` a blocked name answers `0.0.0.0` with `EDE 15 (Blocked)`. The trustworthy "my list actually loaded" signal is the `Fetched blocklist source url=…` log line, **not** the `exact=` count in `Block index compiled` — a 224k-entry HaGeZi list logs `exact=0` because its entries parse as wildcards. A source whose URL 404s is only `warn!`-logged and the reload still reports success, so always check for the fetch line per URL. See [[issue-216-blocklist-sync]].

**Secure-cookie behaviour cannot be reproduced on loopback:** curl and browsers both treat `127.0.0.1` as a secure context and accept a `Secure` cookie over plain HTTP. Bind to the host's LAN address (`--bind <lan-ip>`) to observe the real rejection. This is why [[web-tls-secure-cookie-invariant]] went unnoticed in local development.
