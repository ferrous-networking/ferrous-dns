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

**Admin username:** since PR #251 (merged 2026-09-25 as `e75ba8c`), `AdminConfig` has a hand-written `Default` with `username = "admin"` (`domain/src/config/auth.rs:121-124`). A config with no `[auth.admin]` table now logs in as `admin`. Before #251 the username came out empty and every login returned 401, so only builds older than `e75ba8c` still need `username = "admin"` set by hand.

**Verifying blocklist behaviour:** query with `dig @127.0.0.1 -p 15353 <domain>`; under the default `block_mode = "null_ip"` a blocked name answers `0.0.0.0` with `EDE 15 (Blocked)`. The trustworthy "my list actually loaded" signal is the `Fetched blocklist source url=…` log line, **not** the `exact=` count in `Block index compiled` — a 224k-entry HaGeZi list logs `exact=0` because its entries parse as wildcards. A source whose URL 404s is only `warn!`-logged and the reload still reports success, so always check for the fetch line per URL. See [[issue-216-blocklist-sync]].

**Scripting the API without a session:** with `[auth] enabled = false` every `/api/*` route answers plain curl, which is the quickest way to run a request matrix. Expected noise in the browser console then: a 401 on `/api/auth/2fa/status`, the known 404 on `/api/health/upstreams`, and the Tailwind CDN warning.

**Saving pools from the Settings UI on this minimal config** (the pool editor is on the **DNS Advanced** tab) always returns "Restart the server for the changes to take effect", because that form sends every `dns` field and they differ from the stub file — so the "applied immediately" message never appears. Confirm the pool went live with `GET /api/upstream/health/detail` instead.

**Docs check:** `mkdocs build --strict -d <scratch dir>` — a plain `mkdocs build` rewrites the tracked `site/`.

**Secure-cookie behaviour cannot be reproduced on loopback:** curl and browsers both treat `127.0.0.1` as a secure context and accept a `Secure` cookie over plain HTTP. Bind to the host's LAN address (`--bind <lan-ip>`) to observe the real rejection. This is why [[web-tls-secure-cookie-invariant]] went unnoticed in local development.
