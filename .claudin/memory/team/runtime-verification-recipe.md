---
name: runtime-verification-recipe
description: Minimal standalone config and steps to run ferrous-dns locally for runtime verification — required TOML tables, enum casing, migrations symlink, main×branch, stopping instances safely, auth-off curl, a local list source; links to the UI-session and fake-upstream recipes
type: project
---

Running the ferrous-dns binary against a throwaway config for runtime verification (not tests) needs more than a stub TOML. `Config` has no `#[serde(default)]` on `server`, `dns`, `blocking`, `logging` or `database`, so all five tables must be present. Validation also rejects a config that has neither `dns.upstream_servers` nor a `[[dns.pools]]` (`root.rs:79`). With a pool, `upstream_servers = []` is fine.

A pool's `strategy` in the TOML is case-sensitive: write `"Parallel"`, `"Failover"` or `"Balanced"`. Lowercase `"parallel"` stops startup with `unknown variant`, even though the `/ferrous/api/v1/config` JSON and the Settings form use lowercase. The same goes for `dnssec_mode`: write `"Off"`, `"Permissive"` or `"Strict"`; `"off"` fails to load (seen 2026-10-16).

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

Run it from a directory containing a `migrations` symlink to the repo's `migrations/`. The app resolves `./migrations` relative to the working directory, not the config path.

**Stop that instance before running `make ci`, or pick another DNS port** (25353 worked on 2026-10-16). `crates/infrastructure/tests/helpers/dns_server_mock.rs:104` binds port **15353**, the same port as the config above. A verification instance still running there makes `test_mock_server_starts` fail with a bare `assertion failed: result.is_ok()`, which looks nothing like a port conflict.

**Main × branch side by side:** before the first edit, build `main` and copy `target/debug/ferrous-dns` to the scratchpad. Later on, build it from a detached `git worktree` with its own target dir ([[shared-target-dir-across-checkouts]]); a debug build of the binary alone took 3 m 39 s at half the cores on 2026-11-15. Run main and the branch on different web and DNS ports, each in its own directory with its own `migrations` symlink, and diff the same curl script's output.

**Stopping instances:** a plain `pkill -f` pattern also matches the shell running it. So does `kill $(pgrep -f ...)`, which on 2026-10-16 killed the calling shell with exit 144. Bracket one character instead: `pkill -f "[f]errous-dns-fix --config"`. The bracket does not help when the same Bash call also starts the binary: the unbracketed `…/ferrous-dns-main --config` text further down that command line still matches, and the shell dies with exit 144. Start instances from a script file, and stop them in a separate call.

**Scripting the API without a session:** with `[auth] enabled = false` every `/ferrous/api/v1/*` route answers plain curl. With `pihole_compat = true`, the Pi-hole `/api/*` routes answer without a SID too (2026-11-15). That is the quickest way to run a request matrix. Expected noise in the browser console then: a 401 on `/ferrous/api/v1/auth/2fa/status`.

**To reach an authenticated session:** `POST /ferrous/api/v1/auth/setup {"password": "..."}` returns 204 and writes the Argon2 hash into the config file. The running process keeps its startup snapshot of `[auth]`, so **restart before logging in**. Since PR #251 (`e75ba8c`), a config with no `[auth.admin]` table logs in as `admin`. Older builds need `username = "admin"` set by hand, or every login returns 401.

**API base by build:** since v0.10.0 the Ferrous API is at `/ferrous/api/v1` in every mode, and the old bases answer a 307 (use `curl -L`). Builds before it serve `/api`, or `/ferrous/api` with `pihole_compat = true`. Mind this in a main × branch diff across that release.

**Verifying blocklist behaviour:**
- Query with `dig @127.0.0.1 -p 15353 <domain>`. Under the default `block_mode = "null_ip"`, a blocked name answers `0.0.0.0` with `EDE 15 (Blocked)`.
- The trustworthy "my list actually loaded" signal is the `Fetched blocklist source url=…` log line, **not** the `exact=` count in `Block index compiled`. A 224k-entry HaGeZi list logs `exact=0`, because its entries parse as wildcards.
- A source whose URL 404s is only `warn!`-logged, and the reload still reports success. Always check for the fetch line per URL. See [[issue-216-blocklist-sync]].
- **A list with no internet:** serve a generated hosts file with `python3 -m http.server <port> --bind 127.0.0.1` and add it with `POST /ferrous/api/v1/blocklist-sources {"name","url","group_ids":[1],"enabled":true}`. On 2026-11-15 a debug build compiled 200k entries in about 0.5 s.
- Each rebuild logs `Block filter reload completed`, so counting that line in each instance's log compares rebuilds main × branch.

**Docs check:** `mkdocs build --strict` (`site/` is gitignored; pull requests that touch the docs run the same build in `docs.yml`).

**More recipes:**
- A live dashboard session, UI-wide audits, animation checks and Settings saves: [[runtime-live-ui-session]].
- Cache load with a fake upstream, watching renewals, faking the resolver without root, IPv6 socket behaviour, and the Secure cookie on loopback: [[runtime-fake-upstream-and-network]].
